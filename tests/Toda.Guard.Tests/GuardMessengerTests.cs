using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Toda.Guard.Tests;

/// <summary>Guard's messages (ADR 0087): its own texts for each kind, and the default messenger that writes them to a folder.</summary>
public class GuardMessengerTests
{
    [Fact]
    public void Every_kind_has_its_texts_in_English_and_Arabic_with_the_values_it_names()
    {
        string[] kinds = [GuardMessageKinds.SignUpVerify, GuardMessageKinds.PasswordReset, GuardMessageKinds.AddressVerify,
            GuardMessageKinds.SecondFactorCode, GuardMessageKinds.SecondFactorCodeMessage];
        Assert.Equal(kinds.Order(), GuardMessageTemplates.All.Select(t => t.Key).Order());
        foreach (GuardMessageTemplate template in GuardMessageTemplates.All)
        {
            Assert.True(template.Texts.ContainsKey("en") && template.Texts.ContainsKey("ar"), template.Key);
            Assert.Equal(template.Email, template.Texts.Values.All(t => t.Subject is not null));
            foreach (GuardTemplateText text in template.Texts.Values)
            {
                string rendered = PickupGuardMessenger.Render(text.Body, template.Sample);
                Assert.DoesNotContain("{{", rendered);
            }
        }

        // A second step's code is in both of its texts: the code must reach the person.
        Assert.All(GuardMessageTemplates.All.Where(t => t.Key.StartsWith(GuardMessageKinds.SecondFactorCode, StringComparison.Ordinal)),
            t => Assert.All(t.Texts.Values, x => Assert.Contains("{{ code }}", x.Body)));
    }

    [Fact]
    public void Values_are_filled_by_their_path_and_missing_ones_left_empty()
    {
        Dictionary<string, object?> model = new() { ["code"] = "482913", ["recipient"] = new Dictionary<string, object?> { ["name"] = "Dana" } };

        Assert.Equal("Dana: 482913 ()", PickupGuardMessenger.Render("{{ recipient.name }}: {{code}} ({{ nothing.here }})", model));
    }

    [Fact]
    public async Task The_default_messenger_writes_mail_to_its_folder_and_reaches_no_one_without_one()
    {
        string folder = Path.Combine(Path.GetTempPath(), "guard-pickup-" + Guid.NewGuid().ToString("N"));
        try
        {
            PickupGuardMessenger messenger = new(Options.Create(new GuardOptions { Messenger = { PickupFolder = folder } }), new NoAccounts(),
                NullLogger<PickupGuardMessenger>.Instance);
            Assert.Single(await messenger.ReachAsync(Guid.NewGuid(), "dana@toda.example", CancellationToken.None));
            Assert.Equal([new GuardMethod("email", "Email", true)], await messenger.MethodsAsync(CancellationToken.None));

            GuardSendResult sent = await messenger.SendAsync(new GuardMessage(GuardMessageKinds.PasswordReset, null, "dana@toda.example", "Dana",
                new Dictionary<string, object?> { ["username"] = "dana", ["link"] = "https://toda.example/reset#t", ["minutes"] = 60 }, "ar", "password-reset"),
                CancellationToken.None);

            Assert.Equal(new GuardSendResult(1, 0), sent);
            string mail = await File.ReadAllTextAsync(Assert.Single(Directory.GetFiles(folder)));
            Assert.Contains("To: \"Dana\" <dana@toda.example>", mail);
            Assert.Contains("https://toda.example/reset#t", mail);
            Assert.Contains("تودا", mail);

            PickupGuardMessenger nowhere = new(Options.Create(new GuardOptions()), new NoAccounts(), NullLogger<PickupGuardMessenger>.Instance);
            Assert.Empty(await nowhere.ReachAsync(Guid.NewGuid(), "dana@toda.example", CancellationToken.None));
            Assert.False(Assert.Single(await nowhere.MethodsAsync(CancellationToken.None)).Ready);
            Assert.Equal(new GuardSendResult(0, 1), await nowhere.SendAsync(new GuardMessage(GuardMessageKinds.PasswordReset, null, "dana@toda.example", null,
                new Dictionary<string, object?>(), null, "password-reset"), CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(folder))
            {
                Directory.Delete(folder, recursive: true);
            }
        }
    }

    private sealed class NoAccounts : IAccountLookup
    {
        public Task<AccountInfo?> GetAsync(Guid accountId, CancellationToken cancellationToken = default) => Task.FromResult<AccountInfo?>(null);

        public Task<IReadOnlyDictionary<Guid, AccountInfo>> GetManyAsync(IEnumerable<Guid> accountIds, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyDictionary<Guid, AccountInfo>>(new Dictionary<Guid, AccountInfo>());

        public Task<AccountInfo?> FindByUsernameAsync(string username, CancellationToken cancellationToken = default) => Task.FromResult<AccountInfo?>(null);

        public Task<IReadOnlyList<AccountInfo>> FindByEmailAsync(string email, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AccountInfo>>([]);

        public Task<IReadOnlyList<AccountInfo>> SearchAsync(string text, int max = 20, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AccountInfo>>([]);
    }
}
