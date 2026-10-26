namespace Toda.Guard;

/// <summary>The kinds of message Guard sends (ADR 0087); each is also the key of its template.</summary>
public static class GuardMessageKinds
{
    /// <summary>Confirming the email of someone who signed up.</summary>
    public const string SignUpVerify = "guard.signup-verify";

    /// <summary>A link to choose a new password.</summary>
    public const string PasswordReset = "guard.password-reset";

    /// <summary>Confirming an address someone added to their account.</summary>
    public const string AddressVerify = "guard.email-verify";

    /// <summary>A second step's code by email (ADR 0082).</summary>
    public const string SecondFactorCode = "guard.second-factor-code";

    /// <summary>A second step's code in a line, by SMS, WhatsApp or another channel.</summary>
    public const string SecondFactorCodeMessage = SecondFactorCode + ".message";
}

/// <summary>A template's subject (an email's; null for a message) and body, in Markdown with <c>{{ name }}</c> values.</summary>
public sealed record GuardTemplateText(string? Subject, string Body);

/// <summary>A value a template may use, with what it holds by language.</summary>
public sealed record GuardTemplateVariable(string Name, IReadOnlyDictionary<string, string> Descriptions);

/// <summary>
/// The package's own texts for one kind of message (ADR 0087), by language: what the default messenger renders, and what a
/// host starts from (Toda registers them as templates its admins may reword). <paramref name="Email"/> is false for a
/// message (a line for SMS or chat), which has no subject.
/// </summary>
public sealed record GuardMessageTemplate(
    string Key,
    bool Email,
    IReadOnlyDictionary<string, string> Names,
    IReadOnlyDictionary<string, string> Descriptions,
    IReadOnlyDictionary<string, GuardTemplateText> Texts,
    IReadOnlyList<GuardTemplateVariable> Variables,
    IReadOnlyDictionary<string, object?> Sample);

/// <summary>Guard's own texts for every kind of message it sends (ADR 0087), English and Arabic.</summary>
public static class GuardMessageTemplates
{
    public static IReadOnlyList<GuardMessageTemplate> All { get; } =
    [
        Services.SelfServiceMail.VerifyDefinition,
        Services.SelfServiceMail.ResetDefinition,
        Services.AddressMail.VerifyDefinition,
        Services.TwoFactor.SecondFactorMail.CodeDefinition,
        Services.TwoFactor.SecondFactorMail.CodeMessageDefinition,
    ];

    public static GuardMessageTemplate? Find(string key) => All.FirstOrDefault(t => t.Key == key);
}
