using Toda.Platform.Acting;
using System.Linq.Expressions;
using Casl;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Data;
using Toda.Guard.Domain;
using Toda.Guard.Services;
using Toda.Platform.Query;
using Toda.Query;

namespace Toda.Guard.Controllers;

/// <summary>
/// RQL over accounts and groups (catalog §6): the admin lists' filters, columns, sort and grouping. Accounts run inside
/// the person's ability (read Account); groups are visible to everyone signed in, as their list always was.
/// </summary>
[Route("api/query")]
[Authorize]
public class GuardQueryController(GuardDb guardDb, IAccountLookup accounts, IMembershipResolver membership, QueryClocks clocks, QueryExports exports,
    SecurityLog securityLog) : GuardControllerBase
{
    [HttpPost("accounts")]
    [Reads]
    public async Task<QueryResultDto> Accounts([FromBody] EntityQueryInput input, CancellationToken cancellationToken)
    {
        Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "read", "Account");
        return await guardDb.RunAsync(async db => await EntityQueryEngine.RunAsync(
            db.Accounts.AsNoTracking().AccessibleBy(ability, "read"), await AccountModelAsync(db, cancellationToken), input, Context(), cancellationToken),
            cancellationToken: cancellationToken);
    }

    /// <summary>The accounts list as a file (ADR 0043), inside the same rules as the list.</summary>
    [HttpPost("accounts/export")]
    [Reads]
    [ProducesResponseType(typeof(Stream), StatusCodes.Status200OK, QueryExports.CsvContentType, QueryExports.XlsxContentType)]
    public Task ExportAccounts([FromBody] EntityExportInput input, CancellationToken cancellationToken) =>
        ExportAsync("accounts", input, ability => Ensure(ability, "read", "Account"),
            (db, ability) => db.Accounts.AsNoTracking().AccessibleBy(ability, "read"), db => AccountModelAsync(db, cancellationToken), cancellationToken);

    /// <summary>The groups list as a file (ADR 0043).</summary>
    [HttpPost("groups/export")]
    [Reads]
    [ProducesResponseType(typeof(Stream), StatusCodes.Status200OK, QueryExports.CsvContentType, QueryExports.XlsxContentType)]
    public Task ExportGroups([FromBody] EntityExportInput input, CancellationToken cancellationToken) =>
        ExportAsync("groups", input, null, (db, _) => db.Groups.AsNoTracking(), db => GroupModelAsync(db, cancellationToken), cancellationToken);

    /// <summary>
    /// An export of one of guard's lists: checked as the list is (<paramref name="check"/>), then run as the list runs, in
    /// one snapshot, and written to the security log as its download starts.
    /// </summary>
    private Task ExportAsync<T>(string entity, EntityExportInput input, Action<Ability>? check, Func<GuardDbContext, Ability, IQueryable<T>> rows,
        Func<GuardDbContext, Task<EntityQueryModel<T>>> model, CancellationToken cancellationToken) =>
        QueryExports.RunAsync(HttpContext, Logger, async () =>
        {
            Ability ability = await AbilityAsync(cancellationToken);
            check?.Invoke(ability);
            QueryExportFormat format = QueryExports.Format(input.Format);
            AccountInfo? me = await accounts.GetAsync(CurrentAccountId, cancellationToken);
            ExportFormatting formatting = await exports.FormattingAsync(input.TimeZone, me?.TimeZone, cancellationToken);
            await guardDb.RunAsync(async db =>
            {
                await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction snapshot = await QueryExports.SnapshotAsync(db, cancellationToken);
                return await EntityQueryEngine.ExportAsync(rows(db, ability), await model(db), input, Context(), exports.Limit(input.MaxRows), formatting, async (head, ct) =>
                {
                    await securityLog.ExportedAsync(me?.Username, CurrentAccountId, ClientIp, entity, null, EntityQueryEngine.Rql(input), input.Columns, format.ToString().ToLowerInvariant(), head, ct);
                    string sheet = char.ToUpperInvariant(entity[0]) + entity[1..];
                    return await QueryExports.StartAsync(Response, format, QueryExports.FileStem(entity, null, formatting.Zone), sheet, head, ct);
                }, cancellationToken);
            }, cancellationToken: cancellationToken);
        });

    [HttpGet("accounts/fields")]
    public async Task<List<QueryFieldDto>> AccountFields(CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "read", "Account");
        return await guardDb.RunAsync(async db => EntityQueryEngine.Fields(await AccountModelAsync(db, cancellationToken)), cancellationToken: cancellationToken);
    }

    [HttpGet("accounts/suggest")]
    public async Task<SuggestionsDto> AccountSuggest([FromQuery] string? rql, [FromQuery] int? caret, CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "read", "Account");
        return await guardDb.RunAsync(async db => await EntityQueryEngine.SuggestAsync(await AccountModelAsync(db, cancellationToken), rql ?? "",
            caret ?? (rql ?? "").Length, Context(), cancellationToken), cancellationToken: cancellationToken);
    }

    [HttpPost("groups")]
    [Reads]
    public Task<QueryResultDto> Groups([FromBody] EntityQueryInput input, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db => await EntityQueryEngine.RunAsync(
            db.Groups.AsNoTracking(), await GroupModelAsync(db, cancellationToken), input, Context(), cancellationToken), cancellationToken: cancellationToken);

    [HttpGet("groups/fields")]
    public Task<List<QueryFieldDto>> GroupFields(CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db => EntityQueryEngine.Fields(await GroupModelAsync(db, cancellationToken)), cancellationToken: cancellationToken);

    [HttpGet("groups/suggest")]
    public Task<SuggestionsDto> GroupSuggest([FromQuery] string? rql, [FromQuery] int? caret, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db => await EntityQueryEngine.SuggestAsync(await GroupModelAsync(db, cancellationToken), rql ?? "",
            caret ?? (rql ?? "").Length, Context(), cancellationToken), cancellationToken: cancellationToken);

    private EntityQueryContext Context() => new(
        CurrentAccountId,
        async (username, ct) => (await accounts.FindByUsernameAsync(username, ct))?.Id,
        async (text, max, ct) => (await accounts.SearchAsync(text, max, ct)).Select(a => (a.Username, a.DisplayName)).ToList(),
        membership.GetEffectiveMemberIdsAsync,
        Clock: ct => clocks.ForAsync(CurrentAccountId, ct));

    private static async Task<EntityField<T>> DirectoryAsync<T>(GuardDbContext db, Expression<Func<T, Guid>> member, Func<T, Guid> id, CancellationToken ct)
    {
        Dictionary<Guid, string> directories = await db.Directories.AsNoTracking().ToDictionaryAsync(d => d.Id, d => d.Name, ct);
        Dictionary<string, Guid> byName = directories.ToDictionary(d => d.Value, d => d.Key, StringComparer.OrdinalIgnoreCase);
        return new EntityField<T>
        {
            Definition = new("directory", FieldKind.Choice, "Directory", FieldLabels.Ar("الدليل"), Sortable: true, Groupable: true, Nullable: false),
            Member = member,
            Choices = directories.Values.Distinct(StringComparer.OrdinalIgnoreCase).ToDictionary(n => n, n => n),
            ChoiceValue = name => byName[name],
            Display = row => directories.GetValueOrDefault(id(row)),
        };
    }

    private static async Task<EntityQueryModel<Account>> AccountModelAsync(GuardDbContext db, CancellationToken ct) => new(
    [
        new() { Definition = new("username", FieldKind.Text, "Username", FieldLabels.Ar("اسم المستخدم"), Sortable: true, Nullable: false), Member = (Expression<Func<Account, string>>)(a => a.Username) },
        new() { Definition = new("displayName", FieldKind.Text, "Display name", FieldLabels.Ar("الاسم المعروض"), Sortable: true, Nullable: false), Member = (Expression<Func<Account, string>>)(a => a.DisplayName) },
        new() { Definition = new("email", FieldKind.Text, "Email", FieldLabels.Ar("البريد الإلكتروني"), Sortable: true), Member = (Expression<Func<Account, string?>>)(a => a.Email) },
        await DirectoryAsync<Account>(db, a => a.DirectoryId, a => a.DirectoryId, ct),
        new()
        {
            Definition = new("status", FieldKind.Choice, "Status", FieldLabels.Ar("الحالة"), Sortable: true, Groupable: true, Nullable: false),
            Member = (Expression<Func<Account, AccountStatus>>)(a => a.Status),
            Choices = new Dictionary<string, string> { ["active"] = "Active", ["inactive"] = "Inactive", ["locked"] = "Locked" },
        },
        new() { Definition = new("lastSignIn", FieldKind.DateTime, "Last sign-in", FieldLabels.Ar("آخر تسجيل دخول"), Sortable: true), Member = (Expression<Func<Account, DateTime?>>)(a => a.LastLoginAt) },
    ], ["username", "displayName", "email", "directory", "status", "lastSignIn"], a => a.Id, a => a.Username, (Expression<Func<Account, string>>)(a => a.Username));

    private static async Task<EntityQueryModel<Group>> GroupModelAsync(GuardDbContext db, CancellationToken ct)
    {
        // Distinct members, as the group pages count them; a query in SQL for filters and sorting, loaded once per page for columns.
        // A directory's group has no rows: its members are the active accounts its directory owns (ADR 0037).
        Expression<Func<Group, int>> members = g => g.Kind == GroupKinds.Directory
            ? db.Accounts.Count(a => a.DirectoryId == g.DirectoryId && a.Status == AccountStatus.Active)
            : db.Memberships.Where(m => m.GroupId == g.Id && m.MemberType != MemberType.Group).Select(m => m.MemberId).Distinct().Count();
        Expression<Func<Group, int>> memberGroups = g => db.Memberships.Where(m => m.GroupId == g.Id && m.MemberType == MemberType.Group).Select(m => m.MemberId).Distinct().Count();
        async Task<IReadOnlyDictionary<Guid, object?>> CountAsync(IReadOnlyList<Group> rows, bool groups, CancellationToken token)
        {
            List<Guid> ids = rows.Select(g => g.Id).ToList();
            var counts = await db.Memberships.AsNoTracking()
                .Where(m => ids.Contains(m.GroupId) && (m.MemberType == MemberType.Group) == groups)
                .GroupBy(m => m.GroupId)
                .Select(x => new { x.Key, Count = x.Select(m => m.MemberId).Distinct().Count() })
                .ToDictionaryAsync(x => x.Key, x => x.Count, token);
            List<Guid> directories = groups ? [] : rows.Where(g => g.Kind == GroupKinds.Directory).Select(g => g.DirectoryId).ToList();
            Dictionary<Guid, int> owned = directories.Count == 0 ? [] : await db.Accounts.AsNoTracking()
                .Where(a => a.Status == AccountStatus.Active && directories.Contains(a.DirectoryId)).GroupBy(a => a.DirectoryId)
                .ToDictionaryAsync(x => x.Key, x => x.Count(), token);
            return rows.ToDictionary(g => g.Id, g => (object?)(!groups && g.Kind == GroupKinds.Directory ? owned.GetValueOrDefault(g.DirectoryId) : counts.GetValueOrDefault(g.Id)));
        }

        return new(
        [
            new() { Definition = new("name", FieldKind.Text, "Name", FieldLabels.Ar("الاسم"), Sortable: true, Nullable: false), Member = (Expression<Func<Group, string>>)(g => g.Name) },
            new() { Definition = new("description", FieldKind.Text, "Description", FieldLabels.Ar("الوصف")), Member = (Expression<Func<Group, string?>>)(g => g.Description) },
            await DirectoryAsync<Group>(db, g => g.DirectoryId, g => g.DirectoryId, ct),
            new()
            {
                Definition = new("source", FieldKind.Choice, "Source", FieldLabels.Ar("المصدر"), Sortable: true, Groupable: true, Nullable: false),
                Member = (Expression<Func<Group, bool>>)(g => g.IsLocal),
                Choices = new Dictionary<string, string> { ["local"] = "Local", ["directory"] = "From the directory" },
                ChoiceValue = key => key.Equals("local", StringComparison.OrdinalIgnoreCase),
                Display = g => g.IsLocal ? "local" : "directory",
            },
            new()
            {
                Definition = new("kind", FieldKind.Choice, "Kind", FieldLabels.Ar("النوع"), Sortable: true, Groupable: true, Nullable: false),
                Member = (Expression<Func<Group, string>>)(g => g.Kind),
                Choices = new Dictionary<string, string>
                {
                    [GroupKinds.Standard] = "Group", [GroupKinds.Directory] = "Everyone in a directory", [GroupKinds.Ou] = "OU", [GroupKinds.Organization] = "Organization",
                },
                ChoiceValue = key => key.ToLowerInvariant(),
                Display = g => g.Kind,
            },
            new() { Definition = new("members", FieldKind.Number, "Direct members", FieldLabels.Ar("الأعضاء المباشرون"), Sortable: true, Nullable: false), Member = members, Load = (rows, t) => CountAsync(rows, false, t) },
            new() { Definition = new("memberGroups", FieldKind.Number, "Member groups", FieldLabels.Ar("المجموعات الأعضاء"), Sortable: true, Nullable: false), Member = memberGroups, Load = (rows, t) => CountAsync(rows, true, t) },
        ], ["name", "kind", "description", "directory", "source", "members", "memberGroups"], g => g.Id, g => g.Name, (Expression<Func<Group, string>>)(g => g.Name));
    }
}
