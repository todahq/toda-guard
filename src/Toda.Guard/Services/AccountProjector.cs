using Microsoft.EntityFrameworkCore;
using Toda.Guard.Data;
using Toda.Guard.Domain;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>
/// Applies directory precedence: for every username, the first active directory (lowest Order) that
/// knows it owns the account. The account keeps its Id when the owning directory changes.
/// Returns the events to publish once the changes are saved.
/// </summary>
public class AccountProjector : ITransientDependency
{
    public async Task<List<object>> RebuildAsync(GuardDbContext db, IReadOnlyCollection<string>? normalizedUsernames = null, CancellationToken cancellationToken = default)
    {
        List<UserDirectory> directories = await db.Directories.OrderBy(d => d.Order).ToListAsync(cancellationToken);
        Dictionary<Guid, UserDirectory> byId = directories.ToDictionary(d => d.Id);
        HashSet<Guid> activeIds = directories.Where(d => d.IsActive).Select(d => d.Id).ToHashSet();

        IQueryable<DirectoryUser> usersQuery = db.DirectoryUsers.Where(u => activeIds.Contains(u.DirectoryId));
        IQueryable<Account> accountsQuery = db.Accounts;
        if (normalizedUsernames is not null)
        {
            usersQuery = usersQuery.Where(u => normalizedUsernames.Contains(u.NormalizedUsername));
            accountsQuery = accountsQuery.Where(a => normalizedUsernames.Contains(a.NormalizedUsername));
        }

        List<DirectoryUser> users = await usersQuery.ToListAsync(cancellationToken);
        Dictionary<string, Account> accounts = await accountsQuery.ToDictionaryAsync(a => a.NormalizedUsername, cancellationToken);

        Dictionary<string, DirectoryUser> winners = ResolveOwners(directories, users);

        List<object> events = [];
        foreach ((string username, DirectoryUser winner) in winners)
        {
            UserDirectory directory = byId[winner.DirectoryId];
            if (!accounts.TryGetValue(username, out Account? account))
            {
                account = new Account(Guid.NewGuid(), winner.Username);
                db.Accounts.Add(account);
                accounts[username] = account;
                Apply(account, winner, directory);
                events.Add(new AccountCreatedEto(account.Id, account.Username, directory.Id));
                continue;
            }

            AccountStatus before = account.Status;
            Guid directoryBefore = account.DirectoryId;
            Apply(account, winner, directory);
            AddStatusEvents(events, account, before);
            if (directoryBefore != account.DirectoryId)
            {
                events.Add(new AccountUpdatedEto(account.Id, account.Username, account.DirectoryId));
            }
        }

        foreach (Account orphan in accounts.Values.Where(a => !winners.ContainsKey(a.NormalizedUsername)))
        {
            AccountStatus before = orphan.Status;
            orphan.DirectoryUserId = null;
            orphan.Status = orphan.LockedLocally ? AccountStatus.Locked : AccountStatus.Inactive;
            orphan.StatusReason = orphan.LockedLocally ? "Locked in Toda" : "Not found in any active directory";
            AddStatusEvents(events, orphan, before);
        }

        return events;
    }

    /// <summary>
    /// Pure: for each username, the record from the first active directory (lowest Order) that has it.
    /// A disabled record still wins: a same-named user in a later directory never takes over a disabled account.
    /// </summary>
    internal static Dictionary<string, DirectoryUser> ResolveOwners(IReadOnlyCollection<UserDirectory> directories, IEnumerable<DirectoryUser> users)
    {
        Dictionary<Guid, UserDirectory> active = directories.Where(d => d.IsActive).ToDictionary(d => d.Id);
        return users
            .Where(u => active.ContainsKey(u.DirectoryId))
            .GroupBy(u => u.NormalizedUsername)
            .ToDictionary(g => g.Key, g => g.OrderBy(u => active[u.DirectoryId].Order).ThenBy(u => u.DirectoryId).First());
    }

    private static void Apply(Account account, DirectoryUser winner, UserDirectory directory)
    {
        account.Username = winner.Username;
        account.DisplayName = string.IsNullOrWhiteSpace(winner.DisplayName) ? winner.Username : winner.DisplayName!;
        account.Email = winner.Email;
        account.DirectoryId = directory.Id;
        account.DirectoryUserId = winner.Id;

        (account.Status, account.StatusReason) = account.LockedLocally
            ? (AccountStatus.Locked, "Locked in Toda")
            : winner.IsActive
                ? (AccountStatus.Active, null)
                : (AccountStatus.Inactive, $"Disabled in {directory.Name}");
    }

    private static void AddStatusEvents(List<object> events, Account account, AccountStatus before)
    {
        if (before == AccountStatus.Active && account.Status != AccountStatus.Active)
        {
            events.Add(new AccountDeactivatedEto(account.Id, account.Username, account.StatusReason ?? account.Status.ToString()));
        }
        else if (before != AccountStatus.Active && account.Status == AccountStatus.Active)
        {
            events.Add(new AccountReactivatedEto(account.Id, account.Username));
        }
    }
}
