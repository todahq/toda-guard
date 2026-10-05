using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Toda.Guard.Domain;
using Toda.Sdk;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Uow;

namespace Toda.Guard.Controllers;

/// <summary>
/// Guard controllers manage their own units of work (GuardDb), so changes are committed before
/// events are published and plugin handlers always see committed data.
/// </summary>
[UnitOfWork(IsDisabled = true)]
public abstract class GuardControllerBase : AbpControllerBase
{
    protected Guid CurrentAccountId =>
        Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub"), out Guid id)
            ? id
            : throw new Volo.Abp.Authorization.AbpAuthorizationException("Not signed in.");

    protected string? ClientIp => HttpContext.Connection.RemoteIpAddress?.ToString();

    protected async Task PublishAsync(IEnumerable<object> events)
    {
        IEventPublisher publisher = HttpContext.RequestServices.GetRequiredService<IEventPublisher>();
        foreach (object e in events)
        {
            await GuardEvents.PublishAsync(publisher, e);
        }
    }
}

public static class GuardEvents
{
    public static Task PublishAsync(IEventPublisher publisher, object e, CancellationToken cancellationToken = default) => e switch
    {
        AccountCreatedEto x => publisher.PublishAsync(x, cancellationToken),
        AccountUpdatedEto x => publisher.PublishAsync(x, cancellationToken),
        AccountDeactivatedEto x => publisher.PublishAsync(x, cancellationToken),
        AccountReactivatedEto x => publisher.PublishAsync(x, cancellationToken),
        GroupCreatedEto x => publisher.PublishAsync(x, cancellationToken),
        MembershipChangedEto x => publisher.PublishAsync(x, cancellationToken),
        DirectorySyncCompletedEto x => publisher.PublishAsync(x, cancellationToken),
        _ => Task.CompletedTask,
    };
}

// ---- DTOs (see docs/api.md) ----

public sealed record AccountDto(
    Guid Id, string Username, string DisplayName, string? Email, string Status, string? StatusReason,
    Guid DirectoryId, string DirectoryName, DateTime? LastLoginAt)
{
    public static AccountDto From(Account a, string directoryName) =>
        new(a.Id, a.Username, a.DisplayName, a.Email, a.Status.ToString(), a.StatusReason, a.DirectoryId, directoryName, a.LastLoginAt);
}

public sealed record IdentityDto(
    Guid DirectoryId, string DirectoryName, int DirectoryOrder, string ExternalId, string Username,
    string? DisplayName, string? Email, bool IsActive, bool IsWinning, DateTime? LastSyncedAt);

public sealed record EffectiveGroupDto(Guid GroupId, string Name, Guid DirectoryId, string DirectoryName, bool Direct, IReadOnlyList<string> Path);

public sealed record AccountDetailDto(AccountDto Account, List<IdentityDto> Identities, List<EffectiveGroupDto> Groups);

public sealed record GroupDto(
    Guid Id, string Name, string? Description, Guid DirectoryId, string DirectoryName,
    bool IsLocal, bool Writable, int DirectMemberCount, int MemberGroupCount);

public sealed record GroupMemberDto(string MemberType, Guid MemberId, string Name, string? DisplayName, string DirectoryName, string Source, bool Removable);

public sealed record EffectiveMemberDto(Guid AccountId, string Username, string DisplayName, IReadOnlyList<string> Path);

public sealed record GroupDetailDto(GroupDto Group, List<GroupMemberDto> Members, List<GroupDto> Parents, List<EffectiveMemberDto> EffectiveMembers);

public sealed record DirectoryDto(
    Guid Id, string Name, string Type, string TypeDisplayName, int Order, bool IsActive, bool AuthenticationEnabled,
    Dictionary<string, string> Settings, int? SyncIntervalMinutes, DateTime? LastSyncAt, bool? LastSyncSucceeded,
    string? LastSyncMessage, int UserCount, int GroupCount, bool ConnectorAvailable, string? PluginKey);

public sealed record SyncRunDto(
    Guid Id, Guid DirectoryId, DateTime StartedAt, DateTime? FinishedAt, bool? Succeeded,
    int UsersAdded, int UsersUpdated, int UsersDeactivated, int GroupsSynced, int MembershipsSynced, string? Error)
{
    public static SyncRunDto From(SyncRun r) =>
        new(r.Id, r.DirectoryId, r.StartedAt, r.FinishedAt, r.Succeeded, r.UsersAdded, r.UsersUpdated, r.UsersDeactivated, r.GroupsSynced, r.MembershipsSynced, r.Error);
}
