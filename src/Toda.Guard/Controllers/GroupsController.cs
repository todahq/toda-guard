using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Data;
using Toda.Guard.Domain;
using Toda.Guard.Services;
using Toda.Platform.Controllers;
using Volo.Abp;
using Volo.Abp.Domain.Entities;

namespace Toda.Guard.Controllers;

[Route("api/guard/groups")]
[Authorize(Policy = TodaPolicies.Admin)]
public class GroupsController(GuardDb guardDb, MembershipGraph graph) : GuardControllerBase
{
    [HttpGet]
    public Task<List<GroupDto>> List([FromQuery] string? search, [FromQuery] Guid? directoryId, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            IQueryable<Group> query = db.Groups.AsNoTracking();
            if (!string.IsNullOrWhiteSpace(search))
            {
                string s = GuardConstants.Normalize(search);
                query = query.Where(g => g.NormalizedName.Contains(s));
            }

            if (directoryId is { } d)
            {
                query = query.Where(g => g.DirectoryId == d);
            }

            List<Group> groups = await query.OrderBy(g => g.Name).Take(500).ToListAsync(cancellationToken);
            return await ToDtosAsync(db, groups, cancellationToken);
        }, cancellationToken: cancellationToken);

    [HttpGet("{id:guid}")]
    public Task<GroupDetailDto> Get(Guid id, CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db =>
        {
            Group group = await db.Groups.AsNoTracking().FirstOrDefaultAsync(g => g.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Group), id);
            Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
            bool writable = IsWritable(group);

            List<GroupMembership> memberships = await db.Memberships.AsNoTracking().Where(m => m.GroupId == id).ToListAsync(cancellationToken);
            List<Guid> userIds = memberships.Where(m => m.MemberType == MemberType.DirectoryUser).Select(m => m.MemberId).ToList();
            List<Guid> accountIds = memberships.Where(m => m.MemberType == MemberType.Account).Select(m => m.MemberId).ToList();
            List<Guid> groupIds = memberships.Where(m => m.MemberType == MemberType.Group).Select(m => m.MemberId).ToList();
            Dictionary<Guid, DirectoryUser> users = await db.DirectoryUsers.AsNoTracking().Where(u => userIds.Contains(u.Id)).ToDictionaryAsync(u => u.Id, cancellationToken);
            Dictionary<Guid, Account> accounts = await db.Accounts.AsNoTracking().Where(a => accountIds.Contains(a.Id)).ToDictionaryAsync(a => a.Id, cancellationToken);
            Dictionary<Guid, Group> childGroups = await db.Groups.AsNoTracking().Where(g => groupIds.Contains(g.Id)).ToDictionaryAsync(g => g.Id, cancellationToken);
            // Synced memberships point at a directory record; show the account that record belongs to.
            Dictionary<Guid, Account> accountsByRecord = await db.Accounts.AsNoTracking()
                .Where(a => a.DirectoryUserId != null && userIds.Contains(a.DirectoryUserId.Value))
                .ToDictionaryAsync(a => a.DirectoryUserId!.Value, cancellationToken);

            List<GroupMemberDto> members = [];
            foreach (GroupMembership m in memberships)
            {
                bool removable = writable && m.Source == MembershipSource.Manual;
                switch (m.MemberType)
                {
                    case MemberType.DirectoryUser when users.TryGetValue(m.MemberId, out DirectoryUser? u):
                        // A shadowed record (its username is owned by an earlier directory) has no account of its own.
                        Guid memberId = accountsByRecord.TryGetValue(u.Id, out Account? owner) ? owner.Id : u.Id;
                        string? display = owner is null ? $"{u.DisplayName} (shadowed)" : u.DisplayName;
                        members.Add(new GroupMemberDto("Account", memberId, u.Username, display, directories.GetValueOrDefault(u.DirectoryId, "?"), m.Source.ToString(), removable));
                        break;
                    case MemberType.Account when accounts.TryGetValue(m.MemberId, out Account? a):
                        members.Add(new GroupMemberDto("Account", a.Id, a.Username, a.DisplayName, directories.GetValueOrDefault(a.DirectoryId, "?"), m.Source.ToString(), removable));
                        break;
                    case MemberType.Group when childGroups.TryGetValue(m.MemberId, out Group? g):
                        members.Add(new GroupMemberDto("Group", g.Id, g.Name, g.Description, directories.GetValueOrDefault(g.DirectoryId, "?"), m.Source.ToString(), removable));
                        break;
                }
            }

            List<Guid> parentIds = await db.Memberships.AsNoTracking()
                .Where(m => m.MemberType == MemberType.Group && m.MemberId == id)
                .Select(m => m.GroupId)
                .Distinct()
                .ToListAsync(cancellationToken);
            List<Group> parents = await db.Groups.AsNoTracking().Where(g => parentIds.Contains(g.Id)).OrderBy(g => g.Name).ToListAsync(cancellationToken);

            List<EffectiveMemberDto> effective = (await graph.GetEffectiveMembersAsync(db, id, cancellationToken))
                .Select(e => new EffectiveMemberDto(e.Account.Id, e.Account.Username, e.Account.DisplayName, e.Path))
                .ToList();

            GroupDto dto = (await ToDtosAsync(db, [group], cancellationToken))[0];
            return new GroupDetailDto(
                dto,
                members.OrderBy(m => m.MemberType).ThenBy(m => m.Name).ToList(),
                await ToDtosAsync(db, parents, cancellationToken),
                effective);
        }, cancellationToken: cancellationToken);

    public sealed record CreateGroupInput(string Name, string? Description, Guid? DirectoryId);

    [HttpPost]
    public async Task<GroupDto> Create([FromBody] CreateGroupInput input, CancellationToken cancellationToken)
    {
        Guid directoryId = input.DirectoryId ?? GuardConstants.InternalDirectoryId;
        if (directoryId != GuardConstants.InternalDirectoryId)
        {
            throw new UserFriendlyException("In this PoC, groups are created in the internal directory. Nest a synced group inside it to reuse a directory group.");
        }

        if (string.IsNullOrWhiteSpace(input.Name) || input.Name.Trim().Length > 128)
        {
            throw new UserFriendlyException("Group names are 1–128 characters.");
        }

        GroupDto dto = await guardDb.RunAsync(async db =>
        {
            string normalized = GuardConstants.Normalize(input.Name);
            if (await db.Groups.AnyAsync(g => g.DirectoryId == directoryId && g.NormalizedName == normalized, cancellationToken))
            {
                throw new UserFriendlyException($"The internal directory already has a group called '{input.Name.Trim()}'.");
            }

            Group group = new(Guid.NewGuid(), directoryId, input.Name, isLocal: true) { Description = input.Description?.Trim() };
            db.Groups.Add(group);
            await db.SaveChangesAsync(cancellationToken);
            return (await ToDtosAsync(db, [group], cancellationToken))[0];
        }, requiresNew: true, cancellationToken);

        await PublishAsync([new GroupCreatedEto(dto.Id, dto.Name)]);
        return dto;
    }

    [HttpDelete("{id:guid}")]
    public async Task<NoContentResult> Delete(Guid id, CancellationToken cancellationToken)
    {
        if (id == GuardConstants.AdminsGroupId || id == GuardConstants.UsersGroupId)
        {
            throw new UserFriendlyException("toda-admins and toda-users are system groups and can't be deleted.");
        }

        await guardDb.RunAsync(async db =>
        {
            Group group = await db.Groups.FirstOrDefaultAsync(g => g.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Group), id);
            if (!IsWritable(group))
            {
                throw new UserFriendlyException($"'{group.Name}' is synced from a directory. Delete it there.");
            }

            await db.Memberships.Where(m => m.GroupId == id || (m.MemberType == MemberType.Group && m.MemberId == id)).ExecuteDeleteAsync(cancellationToken);
            db.Groups.Remove(group);
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        return NoContent();
    }

    public sealed record AddMemberInput(Guid? AccountId, Guid? GroupId);

    [HttpPost("{id:guid}/members")]
    public async Task<NoContentResult> AddMember(Guid id, [FromBody] AddMemberInput input, CancellationToken cancellationToken)
    {
        if (input.AccountId is null == input.GroupId is null)
        {
            throw new UserFriendlyException("Give either an accountId or a groupId.");
        }

        string groupName = await guardDb.RunAsync(async db =>
        {
            Group group = await db.Groups.FirstOrDefaultAsync(g => g.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Group), id);
            if (!IsWritable(group))
            {
                throw new UserFriendlyException($"'{group.Name}' is synced from a directory, so its members are managed there. Nest it inside an internal group instead.");
            }

            (MemberType type, Guid memberId) = input.AccountId is { } accountId
                ? (MemberType.Account, accountId)
                : (MemberType.Group, input.GroupId!.Value);

            if (type == MemberType.Account && !await db.Accounts.AnyAsync(a => a.Id == memberId, cancellationToken))
            {
                throw new EntityNotFoundException(typeof(Account), memberId);
            }

            if (type == MemberType.Group)
            {
                if (!await db.Groups.AnyAsync(g => g.Id == memberId, cancellationToken))
                {
                    throw new EntityNotFoundException(typeof(Group), memberId);
                }

                List<string>? cycle = await graph.FindCycleAsync(db, id, memberId, cancellationToken);
                if (cycle is not null)
                {
                    throw new UserFriendlyException($"That would create a loop: {string.Join(" → ", cycle)}.");
                }
            }

            if (!await db.Memberships.AnyAsync(m => m.GroupId == id && m.MemberType == type && m.MemberId == memberId && m.Source == MembershipSource.Manual, cancellationToken))
            {
                db.Memberships.Add(new GroupMembership(Guid.NewGuid(), id, type, memberId, MembershipSource.Manual));
                await db.SaveChangesAsync(cancellationToken);
            }

            return group.Name;
        }, requiresNew: true, cancellationToken, isTransactional: true);

        await PublishAsync([new MembershipChangedEto(id, groupName)]);
        return NoContent();
    }

    [HttpDelete("{id:guid}/members/{memberType}/{memberId:guid}")]
    public async Task<NoContentResult> RemoveMember(Guid id, string memberType, Guid memberId, CancellationToken cancellationToken)
    {
        string groupName = await guardDb.RunAsync(async db =>
        {
            Group group = await db.Groups.FirstOrDefaultAsync(g => g.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Group), id);

            MemberType[] types = memberType.Equals("Group", StringComparison.OrdinalIgnoreCase)
                ? [MemberType.Group]
                : [MemberType.Account, MemberType.DirectoryUser];
            // An account can be a member through a Manual row (its account id) or a Directory row (its directory record).
            Guid? recordId = types.Contains(MemberType.Account)
                ? await db.Accounts.Where(a => a.Id == memberId).Select(a => a.DirectoryUserId).FirstOrDefaultAsync(cancellationToken)
                : null;
            List<GroupMembership> rows = await db.Memberships
                .Where(m => m.GroupId == id && types.Contains(m.MemberType) && (m.MemberId == memberId || (recordId != null && m.MemberId == recordId)))
                .ToListAsync(cancellationToken);

            GroupMembership? manual = rows.FirstOrDefault(r => r.Source == MembershipSource.Manual);
            if (manual is null)
            {
                if (rows.Count > 0)
                {
                    string directory = await db.Directories.Where(d => d.Id == group.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken);
                    throw new UserFriendlyException($"This membership comes from {directory}. Change it there; the next sync will update Toda.");
                }

                throw new EntityNotFoundException(typeof(GroupMembership), memberId);
            }

            db.Memberships.Remove(manual);
            await db.SaveChangesAsync(cancellationToken);
            return group.Name;
        }, requiresNew: true, cancellationToken);

        await PublishAsync([new MembershipChangedEto(id, groupName)]);
        return NoContent();
    }

    private static bool IsWritable(Group group) => group.IsLocal || group.DirectoryId == GuardConstants.InternalDirectoryId;

    private static async Task<List<GroupDto>> ToDtosAsync(GuardDbContext db, List<Group> groups, CancellationToken cancellationToken)
    {
        List<Guid> ids = groups.Select(g => g.Id).ToList();
        Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
        var counts = await db.Memberships.AsNoTracking()
            .Where(m => ids.Contains(m.GroupId))
            .GroupBy(m => new { m.GroupId, IsGroup = m.MemberType == MemberType.Group })
            .Select(x => new { x.Key.GroupId, x.Key.IsGroup, Count = x.Select(m => m.MemberId).Distinct().Count() })
            .ToListAsync(cancellationToken);

        return groups.Select(g => new GroupDto(
                g.Id, g.Name, g.Description, g.DirectoryId, directories.GetValueOrDefault(g.DirectoryId, "?"), g.IsLocal, IsWritable(g),
                counts.Where(c => c.GroupId == g.Id && !c.IsGroup).Sum(c => c.Count),
                counts.Where(c => c.GroupId == g.Id && c.IsGroup).Sum(c => c.Count)))
            .ToList();
    }
}
