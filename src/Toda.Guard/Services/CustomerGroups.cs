using Microsoft.EntityFrameworkCore;
using Toda.Guard.Data;
using Toda.Guard.Domain;

namespace Toda.Guard.Services;

/// <summary>
/// Each directory's group (ADR 0037): "{directory} (everyone)", whose members are worked out from the directory itself
/// (see <see cref="MembershipGraph"/>), so granting a role to a whole directory is granting it to this group.
/// </summary>
public static class DirectoryGroups
{
    public const string Description = "Everyone whose account comes from this directory. Toda keeps it in step.";

    public static string NameFor(string directoryName) => $"{directoryName} (everyone)";

    /// <summary>Gives every directory its group, named after it; renames it when the directory is renamed. Doesn't save.</summary>
    public static async Task EnsureAsync(GuardDbContext db, CancellationToken ct)
    {
        List<UserDirectory> directories = await db.Directories.ToListAsync(ct);
        List<Group> groups = await db.Groups.Where(g => directories.Select(d => d.Id).Contains(g.DirectoryId)).ToListAsync(ct);
        foreach (UserDirectory directory in directories)
        {
            Group? mine = groups.FirstOrDefault(g => g.DirectoryId == directory.Id && g.Kind == GroupKinds.Directory);
            string name = Free(groups, directory.Id, NameFor(directory.Name), mine);
            if (mine is null)
            {
                mine = new Group(Guid.NewGuid(), directory.Id, name, isLocal: true) { Kind = GroupKinds.Directory, Description = Description };
                db.Groups.Add(mine);
                groups.Add(mine);
            }
            else if (mine.Name != name)
            {
                mine.SetName(name);
            }
        }
    }

    /// <summary>The name, or with a number after it when another group in the directory already has it.</summary>
    private static string Free(List<Group> groups, Guid directoryId, string name, Group? mine)
    {
        string candidate = name;
        for (int i = 2; groups.Any(g => g != mine && g.DirectoryId == directoryId && g.NormalizedName == GuardConstants.Normalize(candidate)); i++)
        {
            candidate = $"{name} {i}";
        }

        return candidate;
    }
}

/// <summary>
/// Organizations (ADR 0037): groups customers belong to, by hand or because their email is in one of the
/// organization's domains. Domain memberships are Toda's to keep: added and removed here, never by hand.
/// </summary>
public static class Organizations
{
    /// <summary>A domain as stored: lower case, without a leading "@"; null when it isn't one.</summary>
    public static string? NormalizeDomain(string value)
    {
        string domain = value.Trim().TrimStart('@').ToLowerInvariant();
        return domain.Length is > 0 and <= 253 && domain.Contains('.') && !domain.StartsWith('.') && !domain.EndsWith('.')
            && domain.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-') ? domain : null;
    }

    public static string? DomainOf(string? email) =>
        email is not null && email.LastIndexOf('@') is > 0 and int at && at < email.Length - 1 ? email[(at + 1)..].Trim().ToLowerInvariant() : null;

    /// <summary>
    /// Puts every active account whose email is in an organization's domains in it, and takes out those no longer
    /// there. Reads what's saved; saves. Returns the organizations whose members changed.
    /// </summary>
    public static async Task<List<Guid>> ApplyDomainsAsync(GuardDbContext db, CancellationToken ct)
    {
        List<Group> organizations = await db.Groups.AsNoTracking().Where(g => g.Kind == GroupKinds.Organization).ToListAsync(ct);
        List<Guid> ids = organizations.Select(o => o.Id).ToList();
        // Every address an active account has: its directory's and the ones it verified (ADR 0044).
        var accounts = (await db.Accounts.AsNoTracking().Where(a => a.Status == AccountStatus.Active && a.Email != null).Select(a => new { a.Id, a.Email }).ToListAsync(ct))
            .Concat(await db.AccountEmails.AsNoTracking()
                .Where(e => e.VerifiedAt != null && db.Accounts.Any(a => a.Id == e.AccountId && a.Status == AccountStatus.Active))
                .Select(e => new { Id = e.AccountId, Email = (string?)e.Email }).ToListAsync(ct))
            .ToList();
        HashSet<(Guid Group, Guid Account)> wanted = [];
        foreach (Group organization in organizations.Where(o => o.EmailDomains.Count > 0))
        {
            HashSet<string> domains = organization.EmailDomains.ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var account in accounts.Where(a => DomainOf(a.Email) is { } d && domains.Contains(d)))
            {
                wanted.Add((organization.Id, account.Id));
            }
        }

        List<GroupMembership> existing = await db.Memberships.Where(m => m.Source == MembershipSource.Domain && ids.Contains(m.GroupId)).ToListAsync(ct);
        HashSet<Guid> changed = [];
        foreach (GroupMembership row in existing.Where(m => !wanted.Contains((m.GroupId, m.MemberId))))
        {
            db.Memberships.Remove(row);
            changed.Add(row.GroupId);
        }

        HashSet<(Guid, Guid)> have = existing.Select(m => (m.GroupId, m.MemberId)).ToHashSet();
        foreach ((Guid group, Guid account) in wanted.Where(w => !have.Contains(w)))
        {
            db.Memberships.Add(new GroupMembership(Guid.NewGuid(), group, MemberType.Account, account, MembershipSource.Domain));
            changed.Add(group);
        }

        await db.SaveChangesAsync(ct);
        return changed.ToList();
    }
}
