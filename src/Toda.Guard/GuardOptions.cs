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

    /// <summary>
    /// The name the site's admins group is made with, once, at the first start (its id is fixed, GuardConstants.AdminsGroupId,
    /// and admin rights follow the id, never the name). Toda's is toda-admins.
    /// </summary>
    public string AdminsGroupName { get; set; } = "toda-admins";

    /// <summary>
    /// The scope of the host's own API in the tokens Guard issues (Toda's toda.api by default): what the web's and the
    /// phone's tokens carry and apps are granted. A host's clients and its MCP metadata name the same.
    /// </summary>
    public string ApiScope { get; set; } = Controllers.GuardOidc.ApiScope;

    /// <summary>The browser's cookies Guard sets and reads; Toda's names by default.</summary>
    public GuardCookieOptions Cookies { get; set; } = new();

    /// <summary>The host's pages Guard links to or sends people to; Toda's by default.</summary>
    public GuardPageOptions Pages { get; set; } = new();

    /// <summary>The host's own OpenID Connect clients, as Guard treats them apart; Toda's by default.</summary>
    public GuardClientOptions Clients { get; set; } = new();

    /// <summary>What the host uses of Guard; each off removes that feature's endpoints (all on by default).</summary>
    public GuardFeatures Features { get; set; } = new();

    /// <summary>The site's defaults when a host doesn't say (<see cref="IGuardSiteDefaults"/>).</summary>
    public GuardSiteOptions Site { get; set; } = new();

    /// <summary>The default messenger's pickup folder (<see cref="IGuardMessenger"/>).</summary>
    public GuardMessengerOptions Messenger { get; set; } = new();

    /// <summary>The product's name in Guard's messages, and a host's own templates for them; Toda's texts by default.</summary>
    public GuardTextOptions Texts { get; set; } = new();
}

/// <summary>
/// The names of a browser session's cookies (ADR 0075): its secret (only the server reads it), the anti-forgery value the
/// page sends back as X-Toda-Csrf, the phone's embedded mode, and the page's language. A host beside Toda on the same
/// domain gives its own, so the two don't read each other's.
/// </summary>
public sealed class GuardCookieOptions
{
    public string Session { get; set; } = "toda_session";

    public string Csrf { get; set; } = "toda_csrf";

    public string Embedded { get; set; } = "toda_embedded";

    public string Language { get; set; } = "NEXT_LOCALE";
}

/// <summary>The host's pages, as paths on its public address: where mailed links and the OAuth consent go.</summary>
public sealed class GuardPageOptions
{
    public string SignUpVerify { get; set; } = "/signup/verify";

    public string PasswordReset { get; set; } = "/reset-password";

    public string AddressVerify { get; set; } = "/emails/verify";

    public string Consent { get; set; } = "/oauth/consent";
}

/// <summary>
/// The host's own clients (OpenID Connect client ids): its web server, which may refresh with a password to step up, and
/// its phone app, whose sign-ins the person's list shows as their phone. Apps people allow are never these.
/// </summary>
public sealed class GuardClientOptions
{
    public string Web { get; set; } = "toda-web";

    public string Mobile { get; set; } = "toda-mobile";
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
