using Volo.Abp.Domain.Entities;

namespace Toda.Guard.Domain;

public static class GuardRoles
{
    public static readonly Guid AdministratorId = Guid.Parse("00000000-0000-0000-0000-0000000000b1");
    public static readonly Guid DirectoryHelpdeskId = Guid.Parse("00000000-0000-0000-0000-0000000000b2");
}

/// <summary>A named set of rules in CASL's format, for example "Directory helpdesk".</summary>
public class Role : Entity<Guid>
{
    protected Role()
    {
    }

    public Role(Guid id, string key, string name, bool isSystem) : base(id)
    {
        Key = key;
        Name = name;
        IsSystem = isSystem;
    }

    public string Key { get; private set; } = null!;
    public string Name { get; set; } = null!;
    public string? Description { get; set; }
    public bool IsSystem { get; private set; }
}

/// <summary>One rule of a role, stored as CASL raw-rule JSON. Placeholders like ${grant.directoryIds} are filled per grant.</summary>
public class RoleRule : Entity<Guid>
{
    protected RoleRule()
    {
    }

    public RoleRule(Guid id, Guid roleId, int order, string json) : base(id)
    {
        RoleId = roleId;
        Order = order;
        Json = json;
    }

    public Guid RoleId { get; private set; }
    public int Order { get; set; }
    public string Json { get; set; } = null!;
}

public enum PrincipalType
{
    Account,

    /// <summary>Everyone in the group, including through nested groups.</summary>
    Group,
}

/// <summary>Gives a role to an account or a group, with a scope that fills the role's ${grant.*} placeholders.</summary>
public class RoleGrant : Entity<Guid>
{
    protected RoleGrant()
    {
    }

    public RoleGrant(Guid id, Guid roleId, PrincipalType principalType, Guid principalId, string scopeJson) : base(id)
    {
        RoleId = roleId;
        PrincipalType = principalType;
        PrincipalId = principalId;
        ScopeJson = scopeJson;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid RoleId { get; private set; }
    public PrincipalType PrincipalType { get; private set; }
    public Guid PrincipalId { get; private set; }

    /// <summary>JSON object, e.g. {"directoryIds":["..."]}. Read by rules as ${grant.directoryIds}.</summary>
    public string ScopeJson { get; set; } = "{}";

    public DateTime? ValidUntil { get; set; }
    public DateTime CreatedAt { get; private set; }
    public Guid? CreatedBy { get; set; }
}
