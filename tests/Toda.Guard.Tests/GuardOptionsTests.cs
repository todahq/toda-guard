using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace Toda.Guard.Tests;

/// <summary>Guard's settings (ADR 0087) from the "Guard" section, and the default site they give.</summary>
public class GuardOptionsTests
{
    private static GuardOptions Bound(params (string Key, string Value)[] values)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();
        GuardOptions options = new();
        configuration.GetSection(GuardOptions.Section).Bind(options);
        return options;
    }

    [Fact]
    public void Sign_up_starts_closed_and_the_seed_has_Todas_names_unless_the_host_says()
    {
        GuardOptions toda = Bound();
        Assert.False(toda.SignUp.Open);
        Assert.Equal(("Toda Administrator", "admin@toda.local", "Toda internal", "toda-users", "Everyone who may sign in to Toda."),
            (toda.Seed.AdminDisplayName, toda.Seed.AdminEmail, toda.Seed.InternalDirectoryName, toda.Seed.UsersGroupName, toda.Seed.UsersGroupDescription));
        Assert.Equal("Toda administrators. Members, direct or nested, can administer Toda.", toda.Seed.AdminsGroupDescription);
        Assert.False(Services.SelfService.Initial(toda.SignUp).Enabled);

        GuardOptions host = Bound(("Guard:SignUp:Open", "true"), ("Guard:Seed:UsersGroupName", "market-users"), ("Guard:Seed:AdminPassword", "x"));
        Assert.True(host.SignUp.Open);
        Assert.Equal("market-users", host.Seed.UsersGroupName);
        Domain.SignUpSettings open = Services.SelfService.Initial(host.SignUp);
        Assert.True(open.Enabled);
        Assert.Equal(GuardConstants.InternalDirectoryId, open.DirectoryId);
        Assert.Null(Services.SelfService.Initial(toda.SignUp).DirectoryId);
    }

    [Fact]
    public void The_authenticators_issuer_is_Todas_as_before_unless_the_host_names_it()
    {
        Assert.Equal("Toda (toda.example)", Services.TwoFactor.SecondFactors.IssuerFor(new GuardOptions { PublicUrl = "https://toda.example" }));
        Assert.Equal("Toda", Services.TwoFactor.SecondFactors.IssuerFor(new GuardOptions()));
        GuardOptions market = Bound(("Guard:PublicUrl", "https://market.example"), ("Guard:Texts:ProductName:en", "Market"));
        Assert.Equal("Market (market.example)", Services.TwoFactor.SecondFactors.IssuerFor(market));
        Assert.Equal("Acme", Services.TwoFactor.SecondFactors.IssuerFor(Bound(("Guard:TwoFactor:Issuer", "Acme"), ("Guard:PublicUrl", "https://x.example"))));
        Assert.False(new GuardOptions().TwoFactor.ListsRecovery);
        Assert.True(Bound(("Guard:TwoFactor:ListsRecovery", "true")).TwoFactor.ListsRecovery);
    }

    [Fact]
    public void A_mailed_links_page_takes_the_language_where_it_says_lang()
    {
        Assert.Equal("https://toda.example/reset-password", GuardPageOptions.Link("https://toda.example", "/reset-password", "ar"));
        Assert.Equal("https://market.example/ar/reset-password", GuardPageOptions.Link("https://market.example", "/{lang}/reset-password", "ar"));
        Assert.Equal("https://market.example/en/signup/verify", GuardPageOptions.Link("https://market.example", "/{lang}/signup/verify", null));
    }

    [Fact]
    public void Guards_names_bind_from_Guard_Names_and_name_its_protection_purposes()
    {
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(
            [new("Guard:Names:ProtectionPrefix", "Acme.Guard"), new("Guard:Names:TokenClaim", "acme_token")]).Build();
        GuardNames names = new();
        configuration.GetSection(GuardNames.Section).Bind(names);

        Assert.Equal("acme_token", names.TokenClaim);
        Assert.Equal("Acme.Guard.SecondFactor.v1", names.Purpose("SecondFactor.v1"));
        Assert.Equal(new GuardNames().CsrfHeader, names.CsrfHeader);
    }

    [Fact]
    public void Guard_needs_ABPs_clock_in_UTC_and_says_so_otherwise()
    {
        Assert.Null(TodaGuardModule.ClockProblem(new Volo.Abp.Timing.AbpClockOptions { Kind = DateTimeKind.Utc }));
        Assert.Contains("needs it in UTC", TodaGuardModule.ClockProblem(new Volo.Abp.Timing.AbpClockOptions { Kind = DateTimeKind.Local }));
        Assert.NotNull(TodaGuardModule.ClockProblem(new Volo.Abp.Timing.AbpClockOptions { Kind = DateTimeKind.Unspecified }));
    }

    [Fact]
    public void The_Guard_section_binds_and_its_other_keys_are_left_alone()
    {
        GuardOptions options = Bound(("Guard:PublicUrl", "https://toda.example"), ("Guard:Site:TimeZone", "Asia/Riyadh"),
            ("Guard:Site:FirstDayOfWeek", "Sunday"), ("Guard:Site:Languages:0", "en"), ("Guard:Site:Languages:1", "ar"),
            ("Guard:Oidc:AllowHttp", "true"), ("Guard:TwoFactor:Disabled", "false"));

        Assert.Equal("https://toda.example", options.PublicUrl);
        Assert.Equal(DayOfWeek.Sunday, options.Site.FirstDayOfWeek);
        Assert.Contains("ar", options.Site.Languages);
    }

    [Fact]
    public async Task The_default_site_reads_the_options()
    {
        OptionsGuardSiteDefaults site = new(Options.Create(Bound(("Guard:Site:TimeZone", "Asia/Riyadh"), ("Guard:Site:Languages:0", "en"), ("Guard:Site:Languages:1", "ar"))));

        Assert.Equal("Asia/Riyadh", site.TimeZone);
        Assert.Equal(DayOfWeek.Monday, site.FirstDayOfWeek);
        Assert.Equal("ar", await site.ChoosableLanguageAsync("AR", CancellationToken.None));
        Assert.Null(await site.ChoosableLanguageAsync("fr", CancellationToken.None));
        Assert.Equal("UTC", new OptionsGuardSiteDefaults(Options.Create(Bound(("Guard:Site:TimeZone", "Mars/Olympus")))).TimeZone);
    }
}
