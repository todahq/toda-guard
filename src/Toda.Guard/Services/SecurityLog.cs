using System.Text.Json;
using Toda.Guard.Data;
using Toda.Guard.Domain;
using Toda.Platform.Acting;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>What the security audit records (ADR 0042), besides sign-ins (auth.*) and plugins (plugin.*).</summary>
public static class SecurityAuditTypes
{
    /// <summary>A query's results downloaded as a file (ADR 0043).</summary>
    public const string QueryExport = "query.export";

    public const string GrantAdded = "grant.added";
    public const string GrantRemoved = "grant.removed";
    public const string RoleCreated = "role.created";
    public const string RoleUpdated = "role.updated";
    public const string GroupCreated = "group.created";
    public const string GroupUpdated = "group.updated";
    public const string GroupDeleted = "group.deleted";
    public const string MembershipAdded = "group.member.added";
    public const string MembershipRemoved = "group.member.removed";
    public const string DirectoryCreated = "directory.created";
    public const string DirectoryUpdated = "directory.updated";
    public const string DirectoriesReordered = "directory.reordered";
    public const string DirectoryDeleted = "directory.deleted";
    public const string AccountCreated = "account.created";
    public const string AccountLocked = "account.locked";
    public const string AccountUnlocked = "account.unlocked";
    public const string AccountMerged = "account.merged";
    public const string AddressAdded = "account.address.added";
    public const string AddressRemoved = "account.address.removed";
    public const string MailToChanged = "account.address.mail-to";
    public const string SignUpChanged = "settings.signup";
    public const string RetentionChanged = "settings.audit";
    public const string StepUpChanged = "settings.step-up";
    public const string StepUpSucceeded = "auth.step-up.succeeded";
    public const string StepUpFailed = "auth.step-up.failed";
    public const string StepUpEndedSession = "auth.step-up.session-ended";
}

/// <summary>
/// Writes to the security audit (<c>guard.security_events</c>, ADR 0042): sign-ins and their failures, what leaves the
/// site in bulk, and every change to who may do what, as whoever the request acts as. A change made in guard's database
/// is added to the same save as the change (<see cref="Add"/>); the rest commit on their own, whatever happens to the
/// work around them.
/// </summary>
[ExposeServices(typeof(SecurityLog), typeof(ISecurityAudit))]
public class SecurityLog(GuardDb guardDb, ActingContext acting) : ITransientDependency, ISecurityAudit
{
    /// <summary>A query's results downloaded as a file (ADR 0043).</summary>
    public const string QueryExport = SecurityAuditTypes.QueryExport;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public Task WriteAsync(string type, string? username, Guid? accountId, string? detail, string? ip, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            db.SecurityEvents.Add(new SecurityEvent(Guid.NewGuid(), type, username, accountId, detail, ip)
            {
                ActingAccountId = acting.ActorId,
                ActingMode = acting.Mode,
                SessionId = acting.SessionId,
            });
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);

    /// <summary>A change made outside guard's database (a plugin installed), committed on its own.</summary>
    public Task WriteAsync(string type, AuditTarget? target, object? detail, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            Add(db, type, target, detail);
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);

    /// <summary>A change to who may do what, saved with the change itself: both or neither.</summary>
    public void Add(GuardDbContext db, string type, AuditTarget? target, object? detail = null) =>
        db.SecurityEvents.Add(new SecurityEvent(Guid.NewGuid(), type, acting.SubjectName, acting.SubjectId,
            detail is null ? null : detail as string ?? JsonSerializer.Serialize(detail, Json), acting.Ip)
        {
            ActingAccountId = acting.ActorId,
            ActingMode = acting.Mode,
            SessionId = acting.SessionId,
            TargetType = target?.Type,
            TargetId = target?.Id,
            TargetName = target?.Name is { Length: > 256 } name ? name[..256] : target?.Name,
        });

    /// <summary>
    /// One export, said in JSON: what was exported (records, projects, accounts or groups), from which project, the
    /// query and columns, the format, and how many rows of how many (with the limit, when it cut the file short).
    /// </summary>
    public Task ExportedAsync(AccountInfo? person, Guid accountId, string? ip, string entity, string? projectKey, string rql, IReadOnlyList<string>? columns, string format,
        Toda.Platform.Query.QueryExportHead head, CancellationToken cancellationToken = default) =>
        WriteAsync(QueryExport, person?.Username, accountId, JsonSerializer.Serialize(new
        {
            entity,
            project = projectKey,
            rql,
            columns,
            format,
            rows = head.Rows,
            total = head.Total,
            limit = head.Truncated ? head.Limit : (int?)null,
        }), ip, cancellationToken);
}
