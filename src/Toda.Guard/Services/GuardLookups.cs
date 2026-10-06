using Microsoft.EntityFrameworkCore;
using Toda.Guard.Directories;
using Toda.Guard.Domain;
using Toda.Platform.Plugins;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

[ExposeServices(typeof(IAccountLookup))]
public class AccountLookup(GuardDb guardDb) : IAccountLookup, ITransientDependency
{
    public Task<AccountInfo?> GetAsync(Guid accountId, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db => (await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken)) is { } a ? ToInfo(a) : null,
            cancellationToken: cancellationToken);

    public Task<IReadOnlyDictionary<Guid, AccountInfo>> GetManyAsync(IEnumerable<Guid> accountIds, CancellationToken cancellationToken = default)
    {
        List<Guid> ids = accountIds.Distinct().ToList();
        if (ids.Count == 0)
        {
            return Task.FromResult<IReadOnlyDictionary<Guid, AccountInfo>>(new Dictionary<Guid, AccountInfo>());
        }

        return guardDb.RunAsync<IReadOnlyDictionary<Guid, AccountInfo>>(async db =>
            (await db.Accounts.AsNoTracking().Where(a => ids.Contains(a.Id)).ToListAsync(cancellationToken)).ToDictionary(a => a.Id, ToInfo),
            cancellationToken: cancellationToken);
    }

    public Task<AccountInfo?> FindByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        string normalized = GuardConstants.Normalize(username);
        return guardDb.RunAsync(async db => (await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.NormalizedUsername == normalized, cancellationToken)) is { } a ? ToInfo(a) : null,
            cancellationToken: cancellationToken);
    }

    public Task<IReadOnlyList<AccountInfo>> SearchAsync(string text, int max = 20, CancellationToken cancellationToken = default)
    {
        string normalized = GuardConstants.Normalize(text);
        return guardDb.RunAsync<IReadOnlyList<AccountInfo>>(async db => (await db.Accounts.AsNoTracking()
                .Where(a => a.NormalizedUsername.Contains(normalized) || a.DisplayName.ToLower().Contains(normalized))
                .OrderBy(a => a.Username)
                .Take(max)
                .ToListAsync(cancellationToken))
            .Select(ToInfo)
            .ToList(), cancellationToken: cancellationToken);
    }

    internal static AccountInfo ToInfo(Account a) => new(a.Id, a.Username, a.DisplayName, a.Email, a.Status == AccountStatus.Active, a.DirectoryId);
}

[ExposeServices(typeof(IMembershipResolver))]
public class MembershipResolver(GuardDb guardDb, MembershipGraph graph) : IMembershipResolver, ITransientDependency
{
    public async Task<bool> IsMemberAsync(Guid accountId, Guid groupId, CancellationToken cancellationToken = default) =>
        (await GetEffectiveGroupsAsync(accountId, cancellationToken)).Any(g => g.Id == groupId);

    public Task<IReadOnlyList<GroupInfo>> GetEffectiveGroupsAsync(Guid accountId, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync<IReadOnlyList<GroupInfo>>(async db =>
        {
            Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken);
            if (account is null)
            {
                return [];
            }

            return (await graph.GetEffectiveGroupsAsync(db, account, cancellationToken))
                .Select(g => new GroupInfo(g.Group.Id, g.Group.Name, g.Group.Description, g.Group.DirectoryId))
                .ToList();
        }, cancellationToken: cancellationToken);
}

/// <summary>Built per plugin: only hands out directories of the connector types that plugin registered.</summary>
public class PluginDirectoryConnectionProvider(IServiceProvider hostScope, string pluginKey) : IDirectoryConnectionProvider
{
    public async Task<IReadOnlyList<DirectoryConnectionContext>> GetConnectionsAsync(CancellationToken cancellationToken = default)
    {
        PluginRuntime runtime = (PluginRuntime)hostScope.GetService(typeof(PluginRuntime))!;
        ConnectorCatalog catalog = (ConnectorCatalog)hostScope.GetService(typeof(ConnectorCatalog))!;
        GuardDb guardDb = (GuardDb)hostScope.GetService(typeof(GuardDb))!;

        HashSet<string> types;
        await using (ExtensionLease<IDirectoryConnector> lease = runtime.LeaseExtensions<IDirectoryConnector>(hostScope))
        {
            types = lease.Items.Where(i => i.PluginKey == pluginKey).Select(i => i.Instance.Type).ToHashSet();
        }

        if (types.Count == 0)
        {
            return [];
        }

        return await guardDb.RunAsync<IReadOnlyList<DirectoryConnectionContext>>(async db =>
            (await db.Directories.AsNoTracking().Where(d => types.Contains(d.Type)).OrderBy(d => d.Order).ToListAsync(cancellationToken))
                .Select(catalog.BuildContext)
                .ToList(), cancellationToken: cancellationToken);
    }
}
