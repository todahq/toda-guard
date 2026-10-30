using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Npgsql;
using Toda.Guard.Services.TwoFactor;

namespace Toda.Guard.Host.Tests;

/// <summary>The sample host's tests set the process's environment, so they run one at a time.</summary>
[CollectionDefinition(Collection, DisableParallelization = true)]
public sealed class SampleHost
{
    public const string Collection = "Sample host";
}

/// <summary>
/// What a right short of an admin's, or a sign-in ticket, mustn't reach: setting up an app in place of an emailed code,
/// adding a verified address, and merging rights into oneself. Each also shows what stays allowed.
/// Needs Postgres: localhost:5432 (postgres/postgres), or the server GUARD_TEST_POSTGRES names.
/// </summary>
[Collection(SampleHost.Collection)]
public sealed class SecurityTests : IAsyncLifetime
{
    private static readonly string Server =
        Environment.GetEnvironmentVariable("GUARD_TEST_POSTGRES") is { Length: > 0 } server ? server : "Host=localhost;Port=5432;Username=postgres;Password=postgres";
    private const string AdminPassword = "Host-Admin-Pass-1";
    private const string Password = "Password-12345";
    private static readonly string CsrfHeader = new GuardNames().CsrfHeader;
    private static readonly Guid Internal = Guid.Parse("00000000-0000-0000-0000-00000000d001");
    private static readonly Guid Admins = Guid.Parse("00000000-0000-0000-0000-00000000a001");

    private readonly string _database = "guard_security_" + Guid.NewGuid().ToString("N")[..12];
    private readonly string _mail = Path.Combine(Path.GetTempPath(), "guard-security-mail-" + Guid.NewGuid().ToString("N"));
    private WebApplicationFactory<Program>? _factory;

    public Task InitializeAsync()
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ConnectionStrings__Guard", $"{Server};Database={_database}");
        Environment.SetEnvironmentVariable("Guard__Seed__AdminPassword", AdminPassword);
        Environment.SetEnvironmentVariable("Guard__Messenger__PickupFolder", _mail);
        Environment.SetEnvironmentVariable("Guard__Features__Merges", "true");
        _factory = new WebApplicationFactory<Program>();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }

        Environment.SetEnvironmentVariable("Guard__Features__Merges", null);
        NpgsqlConnection.ClearAllPools();
        await using NpgsqlConnection connection = new($"{Server};Database=postgres");
        await connection.OpenAsync();
        await using NpgsqlCommand drop = new($"DROP DATABASE IF EXISTS \"{_database}\" WITH (FORCE)", connection);
        await drop.ExecuteNonQueryAsync();
        if (Directory.Exists(_mail))
        {
            Directory.Delete(_mail, recursive: true);
        }
    }

    [Fact]
    public async Task A_ticket_sets_up_an_app_only_when_the_person_has_no_way_through_the_step()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        await AddToAdminsAsync(admin, await CreateAccountAsync(admin, "carol", "carol@example.test"));
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Put, $"/api/guard/groups/{Admins}/two-factor", new { mode = "required" })).Code);

        // No app and no codes the site sends: the ticket sets the app up.
        JsonElement enrol = await ChallengeAsync("carol");
        Assert.True(enrol.GetProperty("enrol").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await Client().PostAsJsonAsync("/api/guard/second-factor/enrol/app", new { ticket = enrol.GetProperty("ticket").GetString() })).StatusCode);

        // The site mails codes: the step asks for one, and the ticket can't set up an app in its place.
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Put, "/api/guard/security/second-factor", new { methods = new[] { "email" } })).Code);
        JsonElement asked = await ChallengeAsync("carol");
        Assert.False(asked.GetProperty("enrol").GetBoolean());
        string ticket = asked.GetProperty("ticket").GetString()!;
        HttpClient attacker = Client();
        Assert.Equal(HttpStatusCode.Unauthorized, (await attacker.PostAsJsonAsync("/api/guard/second-factor/enrol/app", new { ticket })).StatusCode);
        string code = Totp.Code(Totp.FromBase32(Totp.ToBase32(new byte[20])), Totp.StepAt(DateTimeOffset.UtcNow));
        Assert.Equal(HttpStatusCode.Unauthorized, (await attacker.PostAsJsonAsync("/api/guard/second-factor/enrol/app/confirm", new { ticket, code })).StatusCode);
        Assert.NotEqual(HttpStatusCode.OK, (await attacker.PostAsJsonAsync("/api/guard/session/second-factor", new { ticket })).StatusCode);
    }

    [Fact]
    public async Task Only_an_admin_adds_removes_or_redirects_an_accounts_addresses()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Guid adminId = await MyIdAsync(admin);
        Guid role = await CreateRoleAsync(admin, "rename-people",
            """{ "action": "update", "subject": "Account", "fields": ["displayName"], "conditions": { "directoryId": { "$in": "${grant.directoryIds}" } } }""",
            """{ "action": "update", "subject": "Account", "fields": ["displayName"], "conditions": { "id": "${user.id}" } }""");
        Guid helper = await CreateAccountAsync(admin, "helper", "helper@corp.example");
        await GrantAsync(admin, role, helper, new { directoryIds = new[] { Internal } });

        Session h = await SignInAsync("helper", Password);
        Assert.Equal(HttpStatusCode.Forbidden, (await h.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{adminId}/emails", new { email = "evil@attacker.example" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await h.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{helper}/emails", new { email = "ceo@bigcustomer.example" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await h.SendAsync(HttpMethod.Put, $"/api/guard/accounts/{adminId}/mail-to", new { email = "helper@corp.example" })).Code);

        (HttpStatusCode added, string body) = await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{helper}/emails", new { email = "helper@other.example" });
        Assert.Equal(HttpStatusCode.OK, added);
        Assert.Contains("\"verifiedAt\":\"", body);
    }

    [Fact]
    public async Task A_merge_right_short_of_an_admins_moves_no_rights()
    {
        Session admin = await SignInAsync("admin", AdminPassword);
        Guid adminId = await MyIdAsync(admin);
        Guid role = await CreateRoleAsync(admin, "dedup",
            """{ "action": "merge", "subject": "Account", "conditions": { "directoryId": { "$in": "${grant.directoryIds}" } } }""");
        Guid deduper = await CreateAccountAsync(admin, "deduper", "deduper@corp.example");
        await GrantAsync(admin, role, deduper, new { directoryIds = new[] { Internal } });
        Guid plain = await CreateAccountAsync(admin, "plain", "plain@corp.example");
        Guid plainToo = await CreateAccountAsync(admin, "plain2", "plain2@corp.example");
        Guid granted = await CreateAccountAsync(admin, "granted", "granted@corp.example");
        await GrantAsync(admin, role, granted, new { directoryIds = new[] { Internal } });

        Session d = await SignInAsync("deduper", Password);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{adminId}/merge", new { survivorId = deduper, confirm = "admin" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{plain}/merge", new { survivorId = deduper, confirm = "plain" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{adminId}/merge", new { survivorId = plain, confirm = "admin" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{granted}/merge", new { survivorId = plain, confirm = "granted" })).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await d.SendAsync(HttpMethod.Get, "/api/guard/roles")).Code);

        // Accounts with no rights of their own still merge, and an admin merges any.
        Assert.Equal(HttpStatusCode.OK, (await d.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{plain}/merge", new { survivorId = plainToo, confirm = "plain" })).Code);
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(HttpMethod.Post, $"/api/guard/accounts/{granted}/merge", new { survivorId = adminId, confirm = "granted" })).Code);
    }

    private sealed record Session(HttpClient Http, string Csrf)
    {
        public async Task<(HttpStatusCode Code, string Body)> SendAsync(HttpMethod method, string url, object? body = null)
        {
            using HttpRequestMessage request = new(method, url) { Content = body is null ? null : JsonContent.Create(body) };
            request.Headers.Add(CsrfHeader, Csrf);
            HttpResponseMessage response = await Http.SendAsync(request);
            return (response.StatusCode, await response.Content.ReadAsStringAsync());
        }
    }

    private HttpClient Client() => _factory!.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });

    private async Task<Session> SignInAsync(string username, string password)
    {
        HttpClient client = Client();
        HttpResponseMessage signedIn = await client.PostAsJsonAsync("/api/guard/session", new { username, password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        string prefix = new GuardCookieOptions().Csrf + "=";
        string cookie = signedIn.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(prefix, StringComparison.Ordinal));
        return new Session(client, Uri.UnescapeDataString(cookie[prefix.Length..].Split(';')[0]));
    }

    /// <summary>The second step a right password is asked for.</summary>
    private async Task<JsonElement> ChallengeAsync(string username)
    {
        HttpResponseMessage asked = await Client().PostAsJsonAsync("/api/guard/session", new { username, password = Password });
        Assert.Equal(HttpStatusCode.Unauthorized, asked.StatusCode);
        return JsonDocument.Parse(await asked.Content.ReadAsStringAsync()).RootElement.GetProperty("secondFactor").Clone();
    }

    private static async Task<Guid> MyIdAsync(Session session) =>
        JsonDocument.Parse((await session.SendAsync(HttpMethod.Get, "/api/guard/me")).Body).RootElement.GetProperty("account").GetProperty("id").GetGuid();

    private static async Task<Guid> CreateAccountAsync(Session admin, string username, string email)
    {
        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Post, "/api/guard/accounts", new { username, displayName = username, email, password = Password });
        Assert.Equal(HttpStatusCode.OK, code);
        return JsonDocument.Parse(body).RootElement.GetProperty("id").GetGuid();
    }

    private static async Task AddToAdminsAsync(Session admin, Guid accountId)
    {
        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Post, $"/api/guard/groups/{Admins}/members", new { accountId });
        Assert.True(code == HttpStatusCode.NoContent, body);
    }

    private static async Task<Guid> CreateRoleAsync(Session admin, string key, params string[] rules)
    {
        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Post, "/api/guard/roles",
            new { key, name = key, description = (string?)null, rules = rules.Select(r => JsonDocument.Parse(r).RootElement).ToArray() });
        Assert.True(code == HttpStatusCode.OK, body);
        return JsonDocument.Parse(body).RootElement.GetProperty("id").GetGuid();
    }

    private static async Task GrantAsync(Session admin, Guid role, Guid account, object scope)
    {
        (HttpStatusCode code, string body) = await admin.SendAsync(HttpMethod.Post, $"/api/guard/roles/{role}/grants", new { principalType = "Account", principalId = account, scope });
        Assert.True(code == HttpStatusCode.OK, body);
    }
}
