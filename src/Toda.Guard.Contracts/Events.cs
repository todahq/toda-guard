namespace Toda.Guard;

// Events in the event catalog published by guard. Plugins subscribe with AddEventHandler<TEvent, THandler>().

public sealed record AccountCreatedEto(Guid AccountId, string Username, Guid DirectoryId);

public sealed record AccountUpdatedEto(Guid AccountId, string Username, Guid DirectoryId);

public sealed record AccountDeactivatedEto(Guid AccountId, string Username, string Reason);

public sealed record AccountReactivatedEto(Guid AccountId, string Username);

public sealed record GroupCreatedEto(Guid GroupId, string Name);

public sealed record MembershipChangedEto(Guid GroupId, string GroupName);

public sealed record DirectorySyncCompletedEto(
    Guid DirectoryId,
    string DirectoryName,
    bool Succeeded,
    int UsersAdded,
    int UsersUpdated,
    int UsersDeactivated,
    int GroupsSynced,
    TimeSpan Duration,
    string? Error);
