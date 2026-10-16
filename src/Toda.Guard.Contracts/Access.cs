using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Casl;
using Toda.Query;
using Toda.Sdk;

namespace Toda.Guard;

/// <summary>
/// What a person may do (ADR 0010, 0042), for modules other than guard: the one way to an ability. For the request's own
/// subject it carries the request's limits (a token's scopes, an impersonation's denies).
/// </summary>
public interface IAbilities
{
    /// <summary>The account's ability: its own for anyone else, and with the request's limits for the request's subject.</summary>
    Task<Ability> ForAccountAsync(Guid accountId, CancellationToken cancellationToken = default);

    /// <summary>What's granted to the Anonymous principal: a visitor who isn't signed in (ADR 0037).</summary>
    Task<Ability> ForAnonymousAsync(CancellationToken cancellationToken = default);
}

/// <summary>The permission stamp (ADR 0041): changes whenever anyone's rights may have, so what's kept by it is out of date.</summary>
public interface IPermissionStamp
{
    long Stamp { get; }
}

/// <summary>A role other modules define in code, such as a project role contributed by a feature.</summary>
public sealed record RoleDefinition(string Key, string Name, string? Description, IReadOnlyList<JsonObject> Rules);

public sealed record GrantInfo(
    Guid Id, Guid RoleId, string RoleKey, string RoleName, PrincipalType PrincipalType, Guid PrincipalId, string PrincipalName,
    JsonObject Scope, string? ScopeKey, DateTime? ValidUntil, DateTime CreatedAt);

/// <summary>Who a role is given to.</summary>
public enum PrincipalType
{
    Account,

    /// <summary>Everyone in the group, including through nested groups.</summary>
    Group,

    /// <summary>
    /// Whoever isn't signed in (ADR 0037), with <see cref="GuardConstants.AnonymousId"/>. What it's granted, everyone
    /// gets: signed in or not.
    /// </summary>
    Anonymous,
}

/// <summary>
/// Roles and grants for other modules (ADR 0010). Projects keep their roles here instead of in a second permission
/// system: a project role is a system role whose rules use ${grant.projectId}, and a member is a grant with scope
/// {"projectId": …} and scope key "project:{id}".
/// </summary>
public interface IRoleCatalog
{
    /// <summary>Creates a system role, or brings its name and rules up to date. Idempotent.</summary>
    Task<Guid> EnsureSystemRoleAsync(RoleDefinition definition, CancellationToken cancellationToken = default);

    Task<Guid?> FindRoleIdAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gives a role to an account or a group. Idempotent: the same role, principal and scope key returns the existing
    /// grant. The scope must fill every placeholder of the role's rules.
    /// </summary>
    Task<Guid> GrantAsync(Guid roleId, PrincipalType principalType, Guid principalId, JsonObject scope, string? scopeKey,
        DateTime? validUntil, Guid? createdBy, CancellationToken cancellationToken = default);

    Task RevokeAsync(Guid grantId, string? scopeKey = null, CancellationToken cancellationToken = default);

    Task<List<GrantInfo>> ListGrantsAsync(string scopeKey, CancellationToken cancellationToken = default);

    /// <summary>The keys of the roles an account has in a scope, directly or through its groups.</summary>
    Task<HashSet<string>> RoleKeysAsync(Guid accountId, string scopeKey, CancellationToken cancellationToken = default);
}

/// <summary>Checks a role's rules before they're used, such as a feature's roles as a plugin loads.</summary>
public interface IRoleRules
{
    /// <summary>Problems with one rule in CASL's raw format: subjects, fields, condition paths, operators.</summary>
    IReadOnlyList<string> Problems(JsonObject rule);
}

public static partial class RoleKeys
{
    /// <summary>What a role's key looks like: lowercase, a letter first, 2 to 64 characters.</summary>
    public static readonly Regex Pattern = Format();

    [GeneratedRegex("^[a-z][a-z0-9-]{1,63}$", RegexOptions.None, TextPatterns.TimeoutMilliseconds)]
    private static partial Regex Format();
}

/// <summary>Accounts for customers who write in (ADR 0039): mail and confirmed portal requests.</summary>
public interface ICustomerAccounts
{
    /// <summary>The account for an address that has been confirmed, made if there's none; null when it can't be.</summary>
    Task<Guid?> AccountForConfirmedEmailAsync(string email, string name, CancellationToken ct);
}

/// <summary>A person's clock for queries (ADR 0013): now, their time zone, and the site's first day of the week.</summary>
public interface IQueryClocks
{
    Task<QueryClock> ForAsync(Guid accountId, CancellationToken cancellationToken = default);
}

/// <summary>Exports go on the security log (ADR 0043).</summary>
public interface IExportAudit
{
    /// <summary>
    /// One export: what was exported (records, projects…), from which project, the query and columns, the format, and
    /// how many rows of how many (with the limit, when it cut the file short).
    /// </summary>
    Task ExportedAsync(AccountInfo? person, Guid accountId, string? ip, string entity, string? projectKey, string rql, IReadOnlyList<string>? columns,
        string format, int rows, int total, int? limit, CancellationToken cancellationToken = default);
}

/// <summary>Organizations (ADR 0037) from an import: the one it made before, else the one with that name, else a new one.</summary>
public interface IOrganizationImport
{
    /// <summary>The organization, with these members added by hand (members it has already stay).</summary>
    Task<Guid> EnsureAsync(Guid? known, string name, IReadOnlyCollection<Guid> members, CancellationToken cancellationToken);
}

public static class EmailDomains
{
    /// <summary>An address's domain, lowercase, or null when it has none.</summary>
    public static string? Of(string? email) =>
        email is not null && email.LastIndexOf('@') is > 0 and int at && at < email.Length - 1 ? email[(at + 1)..].Trim().ToLowerInvariant() : null;
}

/// <summary>
/// The subjects rules may name, and how rules combine (ADR 0010): one registry for guard and every module, each adding
/// its own subjects (guard its accounts and groups, projects its projects and records) before abilities are built.
/// </summary>
public static class AbilitySubjects
{
    public static SubjectRegistry Registry { get; } = new();

    /// <summary>
    /// Rules come from several roles and grants, so their order means nothing: any matching deny wins.
    /// (CASL .NET's default is CASL's "last rule wins".)
    /// </summary>
    public static AbilityOptions Options { get; } = new() { Semantics = RuleSemantics.DenyOverrides };
}

/// <summary>Rebuilding an ability from its own rules, narrowed: what the request limits (ADR 0042) are made of.</summary>
public static class AbilityRules
{
    /// <summary>The actions that only read.</summary>
    public static readonly IReadOnlyList<string> ReadActions = ["read", "browse", "portal"];

    /// <summary>Each rule of the ability, as <paramref name="rewrite"/> turns it into rules (none drops it), plus <paramref name="extra"/>.</summary>
    public static Ability Rebuild(Ability ability, Func<RawRule, IEnumerable<RawRule?>> rewrite, IEnumerable<RawRule>? extra = null) =>
        new AbilityBuilder(AbilitySubjects.Registry, AbilitySubjects.Options)
            .AddRange(ability.Rules.SelectMany(rewrite).OfType<RawRule>().Concat(extra ?? []), null)
            .Build();

    /// <summary>The rule with only these of its actions ("manage" counting as all of them); null when none is left.</summary>
    public static RawRule? WithActions(RawRule rule, IReadOnlyList<string> allowed)
    {
        List<string> actions = rule.Action.Contains("manage") ? [.. allowed] : rule.Action.Where(allowed.Contains).ToList();
        return actions.Count == 0 ? null : Copy(rule, actions, rule.Subject);
    }

    public static RawRule Copy(RawRule rule, IReadOnlyList<string> actions, IReadOnlyList<string> subjects) => new()
    {
        Action = actions,
        Subject = subjects,
        Conditions = rule.Conditions?.DeepClone().AsObject(),
        Fields = rule.Fields,
        Inverted = rule.Inverted,
        Reason = rule.Reason,
    };
}

public static class GuardConstants
{
    public const string InternalType = "internal";
    public static readonly Guid InternalDirectoryId = Guid.Parse("00000000-0000-0000-0000-00000000d001");
    public static readonly Guid AdminsGroupId = Guid.Parse("00000000-0000-0000-0000-00000000a001");
    public static readonly Guid UsersGroupId = Guid.Parse("00000000-0000-0000-0000-00000000a002");

    /// <summary>The Anonymous principal (ADR 0037): whoever isn't signed in. Granted nothing unless an admin grants it.</summary>
    public static readonly Guid AnonymousId = Guid.Parse("00000000-0000-0000-0000-00000000b001");

    public static string Normalize(string value) => value.Trim().ToLowerInvariant();
}
