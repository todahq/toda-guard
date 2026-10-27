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

    /// <summary>
    /// Whether the kind carries a link or a code that works for someone (all of Guard's do): then it's sent as a secret,
    /// so the mail log keeps neither its text nor its subject, and an admin reading it can't use a reset or a code.
    /// </summary>
    public static bool CarriesSecret(string kind) => kind is SignUpVerify or PasswordReset or AddressVerify or SecondFactorCode or SecondFactorCodeMessage;
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

/// <summary>
/// The texts a host gives Guard's messages without forking it (ADR 0087): the product's name in Guard's own texts, and a
/// whole template of its own for any kind. Toda keeps the defaults, so its texts are Guard's as they are.
/// </summary>
public sealed class GuardTextOptions
{
    /// <summary>The product's name by language, in place of Toda (تودا) in Guard's own texts; a language without one uses English's.</summary>
    public Dictionary<string, string> ProductName { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["en"] = GuardMessageTemplates.DefaultProductName,
        ["ar"] = GuardMessageTemplates.DefaultProductNameArabic,
    };

    /// <summary>
    /// A host's own template for a kind (<see cref="GuardMessageKinds"/>), in place of Guard's, set in code; start from
    /// <see cref="GuardMessageTemplates.For"/>'s and change what differs (<c>template with { Texts = ... }</c>).
    /// </summary>
    public Dictionary<string, GuardMessageTemplate> Messages { get; } = new(StringComparer.Ordinal);
}

/// <summary>Guard's own texts for every kind of message it sends (ADR 0087), English and Arabic.</summary>
public static class GuardMessageTemplates
{
    /// <summary>The product Guard's own texts name: Toda's, in English and Arabic.</summary>
    public const string DefaultProductName = "Toda";

    public const string DefaultProductNameArabic = "تودا";

    private static readonly GuardMessageTemplate[] Builtin =
    [
        Services.SelfServiceMail.VerifyDefinition,
        Services.SelfServiceMail.ResetDefinition,
        Services.AddressMail.VerifyDefinition,
        Services.TwoFactor.SecondFactorMail.CodeDefinition,
        Services.TwoFactor.SecondFactorMail.CodeMessageDefinition,
    ];

    /// <summary>Guard's own texts, as they are (naming Toda).</summary>
    public static IReadOnlyList<GuardMessageTemplate> All => Builtin;

    /// <summary>The templates a host's messages use: its own where it gave one, else Guard's, naming its product.</summary>
    public static IReadOnlyList<GuardMessageTemplate> For(GuardTextOptions texts) =>
        [.. Builtin.Select(t => texts.Messages.TryGetValue(t.Key, out GuardMessageTemplate? own) ? own : Named(t, texts.ProductName))];

    public static GuardMessageTemplate? Find(GuardTextOptions texts, string key) => For(texts).FirstOrDefault(t => t.Key == key);

    /// <summary>The template with the host's product named in place of Toda's, language by language; unchanged for Toda's.</summary>
    private static GuardMessageTemplate Named(GuardMessageTemplate template, IReadOnlyDictionary<string, string> product)
    {
        string Name(string language) =>
            product.TryGetValue(language, out string? name) && name is { Length: > 0 } ? name
            : product.TryGetValue("en", out string? english) && english is { Length: > 0 } ? english
            : DefaultProductName;
        string In(string language, string text) =>
            text.Replace(language == "ar" ? DefaultProductNameArabic : DefaultProductName, Name(language), StringComparison.Ordinal);
        Dictionary<string, string> Each(IReadOnlyDictionary<string, string> texts) => texts.ToDictionary(p => p.Key, p => In(p.Key, p.Value));

        return template with
        {
            Names = Each(template.Names),
            Descriptions = Each(template.Descriptions),
            Texts = template.Texts.ToDictionary(p => p.Key, p => new GuardTemplateText(p.Value.Subject is { } subject ? In(p.Key, subject) : null, In(p.Key, p.Value.Body))),
        };
    }
}
