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
                         || (g.PrincipalType == PrincipalType.Group && groupIds.Contains(g.PrincipalId)))
                .Where(g => g.ValidUntil == null || g.ValidUntil > now)
                .ToListAsync(cancellationToken);
            List<Guid> roleIds = grants.Select(g => g.RoleId).Distinct().ToList();
            ILookup<Guid, string> ruleJson = (await db.RoleRules.AsNoTracking().Where(r => roleIds.Contains(r.RoleId)).OrderBy(r => r.Order).ToListAsync(cancellationToken))
                .ToLookup(r => r.RoleId, r => r.Json);
            ILookup<Guid, RawRule> rules = ruleJson.SelectMany(g => g.Select(j => (g.Key, Rule: RawRule.Parse(j)))).ToLookup(x => x.Key, x => x.Rule);
            // Read-only copies are only needed when a grant reaches up the project tree (ADR 0033); built on first use.
            ILookup<Guid, RawRule>? readRules = null;
            ILookup<Guid, RawRule> ReadRules() => readRules ??= ruleJson
                .SelectMany(g => g.Select(ReadOnly).OfType<string>().Select(j => (g.Key, Rule: RawRule.Parse(j)))).ToLookup(x => x.Key, x => x.Rule);

            object user = new { user = new { id = account.Id, username = account.Username, directoryId = account.DirectoryId, groupIds } };
            AbilityBuilder builder = new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).WithVariables(user);
            // Each grant applies in its own scope, and in any scope a module widens it to (ADR 0033).
            List<(RoleGrant Grant, JsonObject Scope, bool ReadOnly)> applied = [];
            foreach (RoleGrant grant in grants)
            {
                JsonObject own = JsonNode.Parse(grant.ScopeJson) as JsonObject ?? [];
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
                List<RawRule> grantRules = (readOnly ? ReadRules() : rules)[grant.RoleId].ToList();
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
                        logger.LogError("Grant {Grant} has an invalid deny rule ({Error}); account {Account} gets no access until it is fixed.", grant.Id, ex.Message, account.Id);
                        return None;
                    }

                    logger.LogWarning("Grant {Grant} skipped: {Error}", grant.Id, ex.Message);
                    continue;
                }

                builder.AddRange(grantRules, scope);
            }

            return builder.Build();
        }, cancellationToken: cancellationToken);

        _cache[accountId] = ability;
        return ability;
    }

    /// <summary>
    /// A rule narrowed to reading: its actions become "read" when it allows (or denies) reading or managing; any other
    /// rule is dropped. Used where a grant reaches further than where it was given, for reading only.
    /// </summary>
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
