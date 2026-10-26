namespace Toda.Guard;

/// <summary>
/// Guard's settings (ADR 0087), from the configuration's "Guard" section; the keys Guard already read (Guard:Oidc:*,
/// Guard:TwoFactor:*, Guard:SignIn:*, Guard:Seed:*) keep working as they are. A host may fill what it knows in code.
/// </summary>
public sealed class GuardOptions
{
    public const string Section = "Guard";

    /// <summary>
    /// The site's address as people reach it (https://toda.example): the links in mail, the authenticator app's issuer, the
    /// origin a browser's sign-in must come from. Toda fills it from Toda:PublicUrl when Guard:PublicUrl isn't set.
    /// </summary>
    public string? PublicUrl { get; set; }

    /// <summary>The site's defaults when a host doesn't say (<see cref="IGuardSiteDefaults"/>).</summary>
    public GuardSiteOptions Site { get; set; } = new();

    /// <summary>The default messenger's pickup folder (<see cref="IGuardMessenger"/>).</summary>
    public GuardMessengerOptions Messenger { get; set; } = new();
}

/// <summary>A site's time zone (an IANA name), the day its weeks start on, and the languages people may choose.</summary>
public sealed class GuardSiteOptions
{
    public string TimeZone { get; set; } = "UTC";

    public DayOfWeek FirstDayOfWeek { get; set; } = DayOfWeek.Monday;

    public List<string> Languages { get; set; } = ["en"];
}

/// <summary>
/// Where the default messenger writes each message it sends, one file each, rendered from Guard's own texts. Null
/// writes nowhere: a message is then not sent, and says so.
/// </summary>
public sealed class GuardMessengerOptions
{
    public string? PickupFolder { get; set; }
}
