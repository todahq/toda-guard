using System.Linq.Expressions;
using Casl;
using Microsoft.AspNetCore.Authorization;
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
public class GuardQueryController(GuardDb guardDb, IAccountLookup accounts) : GuardControllerBase
{
    [HttpPost("accounts")]
    public async Task<QueryResultDto> Accounts([FromBody] EntityQueryInput input, CancellationToken cancellationToken)
    {
        Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "read", "Account");
        return await guardDb.RunAsync(async db => await EntityQueryEngine.RunAsync(
            db.Accounts.AsNoTracking().AccessibleBy(ability, "read"), await AccountModelAsync(db, cancellationToken), input, Context(), cancellationToken),
            cancellationToken: cancellationToken);
    }

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
        async (text, max, ct) => (await accounts.SearchAsync(text, max, ct)).Select(a => (a.Username, a.DisplayName)).ToList());

    private static async Task<EntityField<T>> DirectoryAsync<T>(GuardDbContext db, Expression<Func<T, Guid>> member, Func<T, Guid> id, CancellationToken ct)
    {
        Dictionary<Guid, string> directories = await db.Directories.AsNoTracking().ToDictionaryAsync(d => d.Id, d => d.Name, ct);
        Dictionary<string, Guid> byName = directories.ToDictionary(d => d.Value, d => d.Key, StringComparer.OrdinalIgnoreCase);
        return new EntityField<T>
        {
            Definition = new("directory", FieldKind.Choice, "Directory", "الدليل", Sortable: true, Groupable: true, Nullable: false),
            Member = member,
            Choices = directories.Values.Distinct(StringComparer.OrdinalIgnoreCase).ToDictionary(n => n, n => n),
            ChoiceValue = name => byName[name],
            Display = row => directories.GetValueOrDefault(id(row)),
        };
    }

    private static async Task<EntityQueryModel<Account>> AccountModelAsync(GuardDbContext db, CancellationToken ct) => new(
    [
        new() { Definition = new("username", FieldKind.Text, "Username", "اسم المستخدم", Sortable: true, Nullable: false), Member = (Expression<Func<Account, string>>)(a => a.Username) },
        new() { Definition = new("displayName", FieldKind.Text, "Display name", "الاسم المعروض", Sortable: true, Nullable: false), Member = (Expression<Func<Account, string>>)(a => a.DisplayName) },
        new() { Definition = new("email", FieldKind.Text, "Email", "البريد الإلكتروني", Sortable: true), Member = (Expression<Func<Account, string?>>)(a => a.Email) },
        await DirectoryAsync<Account>(db, a => a.DirectoryId, a => a.DirectoryId, ct),
        new()
        {
            Definition = new("status", FieldKind.Choice, "Status", "الحالة", Sortable: true, Groupable: true, Nullable: false),
            Member = (Expression<Func<Account, AccountStatus>>)(a => a.Status),
            Choices = new Dictionary<string, string> { ["active"] = "Active", ["inactive"] = "Inactive", ["locked"] = "Locked" },
        },
        new() { Definition = new("lastSignIn", FieldKind.DateTime, "Last sign-in", "آخر تسجيل دخول", Sortable: true), Member = (Expression<Func<Account, DateTime?>>)(a => a.LastLoginAt) },
    ], ["username", "displayName", "email", "directory", "status", "lastSignIn"], a => a.Id, a => a.Username, (Expression<Func<Account, string>>)(a => a.Username));

    private static async Task<EntityQueryModel<Group>> GroupModelAsync(GuardDbContext db, CancellationToken ct)
    {
        // Distinct members, as the group pages count them; a query in SQL for filters and sorting, loaded once per page for columns.
        Expression<Func<Group, int>> members = g => db.Memberships.Where(m => m.GroupId == g.Id && m.MemberType != MemberType.Group).Select(m => m.MemberId).Distinct().Count();
        Expression<Func<Group, int>> memberGroups = g => db.Memberships.Where(m => m.GroupId == g.Id && m.MemberType == MemberType.Group).Select(m => m.MemberId).Distinct().Count();
        async Task<IReadOnlyDictionary<Guid, object?>> CountAsync(IReadOnlyList<Group> rows, bool groups, CancellationToken token)
        {
            List<Guid> ids = rows.Select(g => g.Id).ToList();
            var counts = await db.Memberships.AsNoTracking()
                .Where(m => ids.Contains(m.GroupId) && (m.MemberType == MemberType.Group) == groups)
                .GroupBy(m => m.GroupId)
                .Select(x => new { x.Key, Count = x.Select(m => m.MemberId).Distinct().Count() })
                .ToDictionaryAsync(x => x.Key, x => x.Count, token);
            return ids.ToDictionary(id => id, id => (object?)counts.GetValueOrDefault(id));
        }

        return new(
        [
            new() { Definition = new("name", FieldKind.Text, "Name", "الاسم", Sortable: true, Nullable: false), Member = (Expression<Func<Group, string>>)(g => g.Name) },
            new() { Definition = new("description", FieldKind.Text, "Description", "الوصف"), Member = (Expression<Func<Group, string?>>)(g => g.Description) },
            await DirectoryAsync<Group>(db, g => g.DirectoryId, g => g.DirectoryId, ct),
            new()
            {
                Definition = new("source", FieldKind.Choice, "Source", "المصدر", Sortable: true, Groupable: true, Nullable: false),
                Member = (Expression<Func<Group, bool>>)(g => g.IsLocal),
                Choices = new Dictionary<string, string> { ["local"] = "Local", ["directory"] = "From the directory" },
                ChoiceValue = key => key.Equals("local", StringComparison.OrdinalIgnoreCase),
                Display = g => g.IsLocal ? "local" : "directory",
            },
            new() { Definition = new("members", FieldKind.Number, "Direct members", "الأعضاء المباشرون", Sortable: true, Nullable: false), Member = members, Load = (rows, t) => CountAsync(rows, false, t) },
            new() { Definition = new("memberGroups", FieldKind.Number, "Member groups", "المجموعات الأعضاء", Sortable: true, Nullable: false), Member = memberGroups, Load = (rows, t) => CountAsync(rows, true, t) },
        ], ["name", "description", "directory", "source", "members", "memberGroups"], g => g.Id, g => g.Name, (Expression<Func<Group, string>>)(g => g.Name));
    }
}
