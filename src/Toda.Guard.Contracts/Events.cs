using Toda.Sdk;

namespace Toda.Guard;

// Events in the event catalog published by guard (ADR 0047). Plugins hear them distributed, from Guard's outbox
// (AddEventHandler<TEvent, THandler>()), or local, in the request (AddLocalEventHandler<TEvent, THandler>()).

public sealed record AccountCreatedEto(Guid AccountId, string Username, Guid DirectoryId) : CatalogEvent;

public sealed record AccountUpdatedEto(Guid AccountId, string Username, Guid DirectoryId) : CatalogEvent;

public sealed record AccountDeactivatedEto(Guid AccountId, string Username, string Reason) : CatalogEvent;

public sealed record AccountReactivatedEto(Guid AccountId, string Username) : CatalogEvent;

/// <summary>An account was folded into another (ADR 0044): its references now name the survivor; Automatic when Toda did it.</summary>
public sealed record AccountMergedEto(Guid MergeId, Guid SourceId, string SourceUsername, Guid SurvivorId, string SurvivorUsername, bool Automatic) : CatalogEvent;

public sealed record GroupCreatedEto(Guid GroupId, string Name) : CatalogEvent;

public sealed record MembershipChangedEto(Guid GroupId, string GroupName) : CatalogEvent;

public sealed record DirectorySyncCompletedEto(
    Guid DirectoryId,
    string DirectoryName,
    bool Succeeded,
    int UsersAdded,
    int UsersUpdated,
    int UsersDeactivated,
    int GroupsSynced,
    TimeSpan Duration,
    string? Error) : CatalogEvent;
