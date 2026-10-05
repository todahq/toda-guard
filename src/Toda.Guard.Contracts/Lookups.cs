namespace Toda.Guard;

// Integration services other modules and plugins call. Every reference to a person or group is a GUID:
// group names are display-only, because two directories may each have a group called "admins".

public sealed record AccountInfo(Guid Id, string Username, string DisplayName, string? Email, bool IsActive, Guid DirectoryId);

public sealed record GroupInfo(Guid Id, string Name, string? Description, Guid DirectoryId);

public interface IAccountLookup
{
    Task<AccountInfo?> GetAsync(Guid accountId, CancellationToken cancellationToken = default);
    Task<AccountInfo?> FindByUsernameAsync(string username, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AccountInfo>> SearchAsync(string text, int max = 20, CancellationToken cancellationToken = default);
}

public interface IMembershipResolver
{
    /// <summary>True if the account is in the group directly or through nested groups.</summary>
    Task<bool> IsMemberAsync(Guid accountId, Guid groupId, CancellationToken cancellationToken = default);

    /// <summary>All groups the account belongs to, including through nesting.</summary>
    Task<IReadOnlyList<GroupInfo>> GetEffectiveGroupsAsync(Guid accountId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Lets a connector plugin read the directories of the types it serves, with decrypted settings.
/// A plugin only ever sees directories whose type matches a connector it registered.
/// </summary>
public interface IDirectoryConnectionProvider
{
    Task<IReadOnlyList<Directories.DirectoryConnectionContext>> GetConnectionsAsync(CancellationToken cancellationToken = default);
}
