using System.Text.Json;
using Toda.Guard.Domain;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>
/// Writes to the security audit (<c>guard.security_events</c>): sign-ins and their failures, and what leaves the site in
/// bulk. Each write commits on its own, whatever happens to the work around it.
/// </summary>
public class SecurityLog(GuardDb guardDb) : ITransientDependency
{
    /// <summary>A query's results downloaded as a file (ADR 0043).</summary>
    public const string QueryExport = "query.export";

    public Task WriteAsync(string type, string? username, Guid? accountId, string? detail, string? ip, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            db.SecurityEvents.Add(new SecurityEvent(Guid.NewGuid(), type, username, accountId, detail, ip));
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);

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
