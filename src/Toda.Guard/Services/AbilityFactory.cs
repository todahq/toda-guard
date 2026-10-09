using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Casl;
using Toda.Guard.Domain;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>Subjects guard exposes to rules, and the member paths rules may filter on.</summary>
public static class GuardSubjects
{
    public static SubjectRegistry Registry { get; } = new SubjectRegistry()
        .Add<Account>("Account", s => s
            .ConditionFields("id", "directoryId", "status", "username", "lockedLocally")
            .Fields("displayName", "email", "status"))
        .Add<Group>("Group", s => s.ConditionFields("id", "directoryId", "isLocal").Fields("name", "description"))
        .Add<UserDirectory>("Directory", s => s.ConditionFields("id", "type", "isActive"))
        .Add<RoleSubject>("Role")
        .Add<PluginSubject>("Plugin");

    /// <summary>
    /// Rules come from several roles and grants, so their order means nothing: any matching deny wins.
    /// (CASL .NET's default is CASL's "last rule wins".)
    /// </summary>
    public static AbilityOptions Options { get; } = new() { Semantics = RuleSemantics.DenyOverrides };

    /// <summary>Marker types for subjects that only get type-level checks for now.</summary>
    public sealed class RoleSubject;

    public sealed class PluginSubject;
}

/// <summary>
/// Builds an account's <see cref="Ability"/> from the roles granted to it directly or to any of its effective
/// groups (nested groups count). Each grant's scope fills that grant's ${grant.*} placeholders.
/// Built once per request.
/// </summary>
public class AbilityFactory(GuardDb guardDb, MembershipGraph graph, ILogger<AbilityFactory> logger, IEnumerable<IGrantScopeExpander> expanders) : IScopedDependency
{
    private readonly Dictionary<Guid, Ability> _cache = [];

    public static Ability None { get; } = new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).Build();

    public async Task<Ability> ForAccountAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        if (_cache.TryGetValue(accountId, out Ability? cached))
        {
            return cached;
        }

        Ability ability = await guardDb.RunAsync(async db =>
        {
            Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken);
            if (account is null || account.Status != AccountStatus.Active)
            {
                return None;
            }

            List<Guid> groupIds = (await graph.GetEffectiveGroupsAsync(db, account, cancellationToken)).Select(g => g.Group.Id).ToList();
            DateTime now = DateTime.UtcNow;
            List<RoleGrant> grants = await db.RoleGrants.AsNoTracking()
                .Where(g => (g.PrincipalType == PrincipalType.Account && g.PrincipalId == account.Id)
                         || (g.PrincipalType == PrincipalType.Group && groupIds.Contains(g.PrincipalId))
                         || g.PrincipalType == PrincipalType.Anonymous) // what anyone may do, a signed-in person may too
                .Where(g => g.ValidUntil == null || g.ValidUntil > now)
                .ToListAsync(cancellationToken);
            object user = new { user = new { id = account.Id, username = account.Username, directoryId = account.DirectoryId, groupIds } };
            return await BuildAsync(db, grants, user, account.Id, cancellationToken);
        }, cancellationToken: cancellationToken);

        _cache[accountId] = ability;
        return ability;
    }

    /// <summary>
    /// What someone who isn't signed in may do (ADR 0037): only what's granted to the Anonymous principal. Rules that
    /// name the person (${user.id}) match no one.
    /// </summary>
    public async Task<Ability> ForAnonymousAsync(CancellationToken cancellationToken = default)
    {
        if (_cache.TryGetValue(GuardConstants.AnonymousId, out Ability? cached))
        {
            return cached;
        }

        Ability ability = await guardDb.RunAsync(async db =>
        {
            DateTime now = DateTime.UtcNow;
            List<RoleGrant> grants = await db.RoleGrants.AsNoTracking()
                .Where(g => g.PrincipalType == PrincipalType.Anonymous && (g.ValidUntil == null || g.ValidUntil > now))
                .ToListAsync(cancellationToken);
            object user = new { user = new { id = GuardConstants.AnonymousId, username = "", directoryId = Guid.Empty, groupIds = new List<Guid>() } };
            return grants.Count == 0 ? None : await BuildAsync(db, grants, user, GuardConstants.AnonymousId, cancellationToken);
        }, cancellationToken: cancellationToken);

        _cache[GuardConstants.AnonymousId] = ability;
        return ability;
    }

    /// <summary>The ability the grants give, each grant in its own scope and in any scope a module widens it to.</summary>
    private async Task<Ability> BuildAsync(Data.GuardDbContext db, List<RoleGrant> grants, object user, Guid subject, CancellationToken cancellationToken)
    {
        List<Guid> roleIds = grants.Select(g => g.RoleId).Distinct().ToList();
        ILookup<Guid, string> ruleJson = (await db.RoleRules.AsNoTracking().Where(r => roleIds.Contains(r.RoleId)).OrderBy(r => r.Order).ToListAsync(cancellationToken))
            .ToLookup(r => r.RoleId, r => r.Json);
        ILookup<Guid, RawRule> rules = ruleJson.SelectMany(g => g.Select(j => (g.Key, Rule: RawRule.Parse(j)))).ToLookup(x => x.Key, x => x.Rule);

        // Rules for a widened scope (ADR 0033), made once per role, read-only or not, and list-valued placeholders.
        Dictionary<(Guid Role, bool ReadOnly, string Lists), List<RawRule>> widened = [];
        List<RawRule> Widened(Guid role, bool readOnly, JsonObject scope)
        {
            HashSet<string> lists = scope.Where(p => p.Value is JsonArray).Select(p => p.Key).ToHashSet(StringComparer.Ordinal);
            (Guid, bool, string) key = (role, readOnly, string.Join(",", lists.Order(StringComparer.Ordinal)));
            if (!widened.TryGetValue(key, out List<RawRule>? found))
            {
                found = ruleJson[role].Select(j => readOnly ? ReadOnly(j) : j).OfType<string>().Select(j => RawRule.Parse(ListValued(j, lists))).ToList();
                widened[key] = found;
            }

            return found;
        }

        AbilityBuilder builder = new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).WithVariables(user);
        // Each grant applies in its own scope, and in any scope a module widens it to (ADR 0033).
        List<(RoleGrant Grant, JsonObject Scope, bool ReadOnly)> applied = [];
        Dictionary<Guid, JsonObject> ownScopes = [];
        foreach (RoleGrant grant in grants)
        {
            JsonObject own = JsonNode.Parse(grant.ScopeJson) as JsonObject ?? [];
            ownScopes[grant.Id] = own;
            applied.Add((grant, own, false));
            foreach (IGrantScopeExpander expander in expanders)
            {
                foreach (GrantExpansion expansion in await expander.ExpandAsync(own, cancellationToken))
                {
                    applied.Add((grant, expansion.Scope, expansion.ReadOnly));
                }
            }
        }

        foreach ((RoleGrant grant, JsonObject grantScope, bool readOnly) in applied)
        {
            object scope = new { grant = grantScope };
            List<RawRule> grantRules = ReferenceEquals(grantScope, ownScopes[grant.Id]) ? rules[grant.RoleId].ToList() : Widened(grant.RoleId, readOnly, grantScope);
            if (grantRules.Count == 0)
            {
                continue;
            }

            try
            {
                // Check each grant on its own so one broken grant can't take down the others.
                _ = new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).WithVariables(user).AddRange(grantRules, scope).Build();
            }
            catch (CaslConfigurationException ex)
            {
                if (grantRules.Any(r => r.Inverted))
                {
                    // Skipping a grant with deny rules could widen access: deny everything instead.
                    logger.LogError("Grant {Grant} has an invalid deny rule ({Error}); account {Account} gets no access until it is fixed.", grant.Id, ex.Message, subject);
                    return None;
                }

                logger.LogWarning("Grant {Grant} skipped: {Error}", grant.Id, ex.Message);
                continue;
            }

            builder.AddRange(grantRules, scope);
        }

        return builder.Build();    }

    /// <summary>
    /// A rule narrowed to reading: its actions become "read" when it allows (or denies) reading or managing; any other
    /// rule is dropped. Used where a grant reaches further than where it was given, for reading only.
    /// </summary>
    /// <summary>
    /// A rule for a scope whose values may be lists: a condition that is exactly "${grant.X}" becomes
    /// { "$in": "${grant.X} } when X holds a list, so one rule covers every project a grant reaches instead of one rule
    /// per project.
    /// </summary>
    internal static string ListValued(string json, IReadOnlySet<string> lists)
    {
        if (lists.Count == 0 || JsonNode.Parse(json) is not JsonObject rule || rule["conditions"] is not JsonObject conditions)
        {
            return json;
        }

        void Walk(JsonObject node)
        {
            foreach ((string name, JsonNode? value) in node.ToList())
            {
                switch (value)
                {
                    case JsonValue v when v.TryGetValue(out string? text) && text.StartsWith("${grant.", StringComparison.Ordinal) && text.EndsWith('}')
                                          && lists.Contains(text[8..^1]):
                        node[name] = new JsonObject { ["$in"] = text };
                        break;
                    case JsonObject child:
                        Walk(child);
                        break;
                    case JsonArray items:
                        foreach (JsonObject item in items.OfType<JsonObject>())
                        {
                            Walk(item);
                        }

                        break;
                }
            }
        }

        Walk(conditions);
        return rule.ToJsonString();
    }

    internal static string? ReadOnly(string json)
    {
        if (JsonNode.Parse(json) is not JsonObject rule)
        {
            return null;
        }

        IEnumerable<string> actions = rule["action"] switch
        {
            JsonArray list => list.Select(a => a?.GetValue<string>() ?? ""),
            JsonValue one => [one.GetValue<string>()],
            _ => [],
        };
        if (!actions.Any(a => a is "read" or "manage"))
        {
            return null;
        }

        rule["action"] = "read";
        return rule.ToJsonString();
    }
}
