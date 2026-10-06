using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Toda.Guard.Data;
using Toda.Guard.Domain;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

public sealed record EffectiveGroup(Group Group, bool Direct, IReadOnlyList<string> Path);

public sealed record EffectiveMember(Account Account, IReadOnlyList<string> Path);

/// <summary>
/// Resolves nested group membership. Nesting works across directories (an internal group can contain an
/// LDAP group), because every edge points at a group id. Groups in inactive directories are skipped,
/// and cycles in synced data are tolerated by tracking visited groups.
///
/// The PoC loads the edge list per call; the real build keeps a materialized closure table that sync
/// and membership changes update, so other modules can join on it.
/// </summary>
public class MembershipGraph(IConfiguration configuration) : ITransientDependency
{
    /// <summary>
    /// Default (false): memberships come only from the directory that owns the account.
    /// Aggregating (true): any directory that knows the username contributes memberships.
    /// </summary>
    private bool AggregateAcrossDirectories => configuration.GetValue("Guard:AggregateMemberships", false);

    public async Task<List<EffectiveGroup>> GetEffectiveGroupsAsync(GuardDbContext db, Account account, CancellationToken cancellationToken = default)
    {
        Snapshot snapshot = await LoadAsync(db, cancellationToken);

        HashSet<Guid> directoryUserIds = [];
        if (account.DirectoryUserId is { } winningId)
        {
            directoryUserIds.Add(winningId);
        }

        if (AggregateAcrossDirectories)
        {
            List<Guid> others = await db.DirectoryUsers
                .Where(u => u.NormalizedUsername == account.NormalizedUsername && snapshot.ActiveDirectoryIds.Contains(u.DirectoryId))
                .Select(u => u.Id)
                .ToListAsync(cancellationToken);
            directoryUserIds.UnionWith(others);
        }

        return ResolveEffectiveGroups(snapshot, account, directoryUserIds);
    }

    public async Task<List<EffectiveMember>> GetEffectiveMembersAsync(GuardDbContext db, Guid groupId, CancellationToken cancellationToken = default)
    {
        Snapshot snapshot = await LoadAsync(db, cancellationToken);
        if (!snapshot.Groups.ContainsKey(groupId))
        {
            return [];
        }

        Dictionary<Guid, List<string>> groupPaths = DescendantGroupPaths(snapshot, groupId);

        List<Account> accounts = await db.Accounts.Where(a => a.Status == AccountStatus.Active).ToListAsync(cancellationToken);
        Dictionary<Guid, Account> byId = accounts.ToDictionary(a => a.Id);
        Dictionary<Guid, Account> byWinningDirectoryUser = accounts
            .Where(a => a.DirectoryUserId.HasValue)
            .ToDictionary(a => a.DirectoryUserId!.Value);

        Dictionary<Guid, List<string>>? byUsernameUsers = null;
        if (AggregateAcrossDirectories)
        {
            byUsernameUsers = (await db.DirectoryUsers
                    .Where(u => snapshot.ActiveDirectoryIds.Contains(u.DirectoryId))
                    .Select(u => new { u.Id, u.NormalizedUsername })
                    .ToListAsync(cancellationToken))
                .ToDictionary(u => u.Id, u => new List<string> { u.NormalizedUsername });
        }

        Dictionary<string, Account> byUsername = accounts.ToDictionary(a => a.NormalizedUsername);
        Dictionary<Guid, EffectiveMember> members = [];
        foreach (GroupMembership membership in snapshot.Memberships.Where(m => groupPaths.ContainsKey(m.GroupId)))
        {
            Account? account = membership.MemberType switch
            {
                MemberType.Account => byId.GetValueOrDefault(membership.MemberId),
                MemberType.DirectoryUser => byWinningDirectoryUser.GetValueOrDefault(membership.MemberId)
                    ?? (byUsernameUsers?.GetValueOrDefault(membership.MemberId) is { } names ? byUsername.GetValueOrDefault(names[0]) : null),
                _ => null,
            };

            if (account is null)
            {
                continue;
            }

            List<string> path = groupPaths[membership.GroupId];
            if (!members.TryGetValue(account.Id, out EffectiveMember? existing) || existing.Path.Count > path.Count)
            {
                members[account.Id] = new EffectiveMember(account, path);
            }
        }

        return members.Values.OrderBy(m => m.Path.Count).ThenBy(m => m.Account.Username).ToList();
    }

    /// <summary>Returns the cycle that adding child to parent would create, or null if it is safe.</summary>
    public async Task<List<string>?> FindCycleAsync(GuardDbContext db, Guid parentGroupId, Guid childGroupId, CancellationToken cancellationToken = default)
    {
        Snapshot snapshot = await LoadAsync(db, cancellationToken, includeInactiveDirectories: true);
        return FindCycle(snapshot, parentGroupId, childGroupId);
    }

    /// <summary>Pure: the groups an account reaches, each with its shortest path, from an in-memory snapshot.</summary>
    internal static List<EffectiveGroup> ResolveEffectiveGroups(Snapshot snapshot, Account account, IReadOnlySet<Guid> directoryUserIds)
    {
        if (account.Status != AccountStatus.Active)
        {
            return [];
        }

        List<Guid> direct = snapshot.Memberships
            .Where(m => (m.MemberType == MemberType.DirectoryUser && directoryUserIds.Contains(m.MemberId))
                     || (m.MemberType == MemberType.Account && m.MemberId == account.Id))
            .Select(m => m.GroupId)
            .Where(snapshot.Groups.ContainsKey)
            .Distinct()
            .ToList();

        // Breadth-first upward walk; the first path found to each group is the shortest.
        Dictionary<Guid, EffectiveGroup> result = [];
        Queue<(Guid GroupId, List<string> Path)> queue = new();
        foreach (Guid groupId in direct)
        {
            queue.Enqueue((groupId, [snapshot.Groups[groupId].Name]));
        }

        while (queue.Count > 0)
        {
            (Guid groupId, List<string> path) = queue.Dequeue();
            if (result.ContainsKey(groupId))
            {
                continue;
            }

            result[groupId] = new EffectiveGroup(snapshot.Groups[groupId], path.Count == 1, path);
            foreach (Guid parentId in snapshot.ParentsOf(groupId))
            {
                if (!result.ContainsKey(parentId))
                {
                    queue.Enqueue((parentId, [.. path, snapshot.Groups[parentId].Name]));
                }
            }
        }

        return result.Values.OrderBy(g => g.Path.Count).ThenBy(g => g.Group.Name).ToList();
    }

    /// <summary>Pure: every group at or below the given one, with the path from it back up to the given group.</summary>
    internal static Dictionary<Guid, List<string>> DescendantGroupPaths(Snapshot snapshot, Guid groupId)
    {
        // Walk down through nested groups, remembering the path from each descendant back up to this group.
        Dictionary<Guid, List<string>> groupPaths = new() { [groupId] = [snapshot.Groups[groupId].Name] };
        Queue<Guid> queue = new([groupId]);
        while (queue.Count > 0)
        {
            Guid current = queue.Dequeue();
            foreach (Guid child in snapshot.ChildGroupsOf(current))
            {
                if (groupPaths.ContainsKey(child))
                {
                    continue;
                }

                groupPaths[child] = [snapshot.Groups[child].Name, .. groupPaths[current]];
                queue.Enqueue(child);
            }
        }

        return groupPaths;
    }

    /// <summary>Pure: the loop that adding child to parent would create, or null if it is safe.</summary>
    internal static List<string>? FindCycle(Snapshot snapshot, Guid parentGroupId, Guid childGroupId)
    {
        string Name(Guid id) => snapshot.Groups.TryGetValue(id, out Group? g) ? g.Name : id.ToString();

        if (parentGroupId == childGroupId)
        {
            return [Name(parentGroupId), Name(parentGroupId)];
        }

        // A cycle appears if parent is already somewhere below child.
        Dictionary<Guid, Guid> cameFrom = [];
        Queue<Guid> queue = new([childGroupId]);
        HashSet<Guid> seen = [childGroupId];
        while (queue.Count > 0)
        {
            Guid current = queue.Dequeue();
            foreach (Guid next in snapshot.ChildGroupsOf(current))
            {
                if (!seen.Add(next))
                {
                    continue;
                }

                cameFrom[next] = current;
                if (next == parentGroupId)
                {
                    List<string> path = [Name(parentGroupId)];
                    Guid step = next;
                    while (cameFrom.TryGetValue(step, out Guid previous))
                    {
                        path.Insert(0, Name(previous));
                        step = previous;
                    }

                    path.Insert(0, Name(parentGroupId));
                    return path;
                }

                queue.Enqueue(next);
            }
        }

        return null;
    }

    private static async Task<Snapshot> LoadAsync(GuardDbContext db, CancellationToken cancellationToken, bool includeInactiveDirectories = false)
    {
        HashSet<Guid> activeDirectoryIds = (await db.Directories
                .Where(d => includeInactiveDirectories || d.IsActive)
                .Select(d => d.Id)
                .ToListAsync(cancellationToken))
            .ToHashSet();

        Dictionary<Guid, Group> groups = (await db.Groups.AsNoTracking().ToListAsync(cancellationToken))
            .Where(g => activeDirectoryIds.Contains(g.DirectoryId))
            .ToDictionary(g => g.Id);

        List<GroupMembership> memberships = (await db.Memberships.AsNoTracking().ToListAsync(cancellationToken))
            .Where(m => groups.ContainsKey(m.GroupId))
            .ToList();

        return new Snapshot(activeDirectoryIds, groups, memberships);
    }

    internal sealed class Snapshot(HashSet<Guid> activeDirectoryIds, Dictionary<Guid, Group> groups, List<GroupMembership> memberships)
    {
        private readonly ILookup<Guid, Guid> _parents = memberships
            .Where(m => m.MemberType == MemberType.Group && groups.ContainsKey(m.MemberId))
            .ToLookup(m => m.MemberId, m => m.GroupId);

        private readonly ILookup<Guid, Guid> _children = memberships
            .Where(m => m.MemberType == MemberType.Group && groups.ContainsKey(m.MemberId))
            .ToLookup(m => m.GroupId, m => m.MemberId);

        public HashSet<Guid> ActiveDirectoryIds { get; } = activeDirectoryIds;
        public Dictionary<Guid, Group> Groups { get; } = groups;
        public List<GroupMembership> Memberships { get; } = memberships;

        public IEnumerable<Guid> ParentsOf(Guid groupId) => _parents[groupId].Distinct();

        public IEnumerable<Guid> ChildGroupsOf(Guid groupId) => _children[groupId].Distinct();
    }
}
