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
