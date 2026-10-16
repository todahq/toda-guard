using System.Text.RegularExpressions;
using Toda.Sdk;

namespace Toda.Guard.Services;

/// <summary>What a username looks like, for a user in an internal directory and for a service account alike.</summary>
public static partial class Usernames
{
    /// <summary>The rule as people read it, for when a username doesn't match <see cref="Pattern"/>.</summary>
    public const string Rule = "Usernames are 2–64 letters, digits, dots, dashes, underscores or @.";

    /// <summary>2 to 64 letters, digits, dots, dashes, underscores or @.</summary>
    [GeneratedRegex(@"^[A-Za-z0-9._@-]{2,64}$", RegexOptions.None, TextPatterns.TimeoutMilliseconds)]
    public static partial Regex Pattern();
}
