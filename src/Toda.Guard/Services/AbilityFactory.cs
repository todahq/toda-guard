using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Toda.Authz;
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

    /// <summary>Marker types for subjects that only get type-level checks for now.</summary>
    public sealed class RoleSubject;

    public sealed class PluginSubject;
}

/// <summary>
/// Builds an account's <see cref="Ability"/> from the roles granted to it directly or to any of its effective
/// groups (nested groups count). Each grant's scope fills that grant's ${grant.*} placeholders.
/// Built once per request.
/// </summary>
public class AbilityFactory(GuardDb guardDb, MembershipGraph graph, ILogger<AbilityFactory> logger) : IScopedDependency
{
    private readonly Dictionary<Guid, Ability> _cache = [];

    public static Ability None { get; } = new AbilityBuilder(GuardSubjects.Registry).Build();

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
            ILookup<Guid, RawRule> rules = (await db.RoleRules.AsNoTracking().Where(r => roleIds.Contains(r.RoleId)).OrderBy(r => r.Order).ToListAsync(cancellationToken))
                .ToLookup(r => r.RoleId, r => RawRule.Parse(r.Json));

            object user = new { user = new { id = account.Id, username = account.Username, directoryId = account.DirectoryId, groupIds } };
            AbilityBuilder builder = new AbilityBuilder(GuardSubjects.Registry).WithVariables(user);
            foreach (RoleGrant grant in grants)
            {
                object scope = new { grant = JsonNode.Parse(grant.ScopeJson) };
                List<RawRule> grantRules = rules[grant.RoleId].ToList();
                try
                {
                    // Check each grant on its own so one broken grant can't take down the others.
                    _ = new AbilityBuilder(GuardSubjects.Registry).WithVariables(user).AddRange(grantRules, scope).Build();
                }
                catch (AuthzConfigurationException ex)
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
}
