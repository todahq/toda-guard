using Volo.Abp.Domain.Entities;

namespace Toda.Guard.Domain;

public static class GuardConstants
{
    public const string InternalType = "internal";
    public static readonly Guid InternalDirectoryId = Guid.Parse("00000000-0000-0000-0000-00000000d001");
    public static readonly Guid AdminsGroupId = Guid.Parse("00000000-0000-0000-0000-00000000a001");
    public static readonly Guid UsersGroupId = Guid.Parse("00000000-0000-0000-0000-00000000a002");

    /// <summary>The Anonymous principal (ADR 0037): whoever isn't signed in. Granted nothing unless an admin grants it.</summary>
    public static readonly Guid AnonymousId = Guid.Parse("00000000-0000-0000-0000-00000000b001");

    public static string Normalize(string value) => value.Trim().ToLowerInvariant();
}

/// <summary>A source of users and groups. Lower Order wins when two directories know the same username.</summary>
public class UserDirectory : Entity<Guid>
{
    protected UserDirectory()
    {
    }

    public UserDirectory(Guid id, string name, string type, int order) : base(id)
    {
        Name = name;
        Type = type;
        Order = order;
        IsActive = true;
        AuthenticationEnabled = true;
        CreatedAt = DateTime.UtcNow;
    }

    public string Name { get; set; } = null!;
    public string Type { get; private set; } = null!;
    public int Order { get; set; }
    public bool IsActive { get; set; }

    /// <summary>False makes the directory sync-only: its users can't sign in with it.</summary>
    public bool AuthenticationEnabled { get; set; }

    /// <summary>Non-secret settings as JSON.</summary>
    public string SettingsJson { get; set; } = "{}";

    /// <summary>Secret settings (bind passwords), encrypted with ASP.NET Core Data Protection. Never returned by the API.</summary>
    public string? ProtectedSecrets { get; set; }

    public int? SyncIntervalMinutes { get; set; }
    public DateTime? LastSyncAt { get; set; }
    public bool? LastSyncSucceeded { get; set; }
    public string? LastSyncMessage { get; set; }
    public DateTime CreatedAt { get; private set; }

    public bool IsInternal => Type == GuardConstants.InternalType;
}

/// <summary>A user exactly as one directory reports it. Several directories may report the same username.</summary>
public class DirectoryUser : Entity<Guid>
{
    protected DirectoryUser()
    {
    }

    public DirectoryUser(Guid id, Guid directoryId, string externalId, string username) : base(id)
    {
        DirectoryId = directoryId;
        ExternalId = externalId;
        SetUsername(username);
        IsActive = true;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid DirectoryId { get; private set; }
    public string ExternalId { get; set; } = null!;
    public string Username { get; private set; } = null!;
    public string NormalizedUsername { get; private set; } = null!;
    public string? DisplayName { get; set; }
    public string? Email { get; set; }
    public bool IsActive { get; set; }

    /// <summary>Only for the internal directory.</summary>
    public string? PasswordHash { get; set; }

    /// <summary>
    /// When someone signed up and hasn't confirmed their email yet (ADR 0037): the record stays inactive until they do.
    /// Null for everyone else.
    /// </summary>
    public DateTime? PendingSince { get; set; }

    public DateTime? LastSyncedAt { get; set; }
    public DateTime CreatedAt { get; private set; }

    public void SetUsername(string username)
    {
        Username = username.Trim();
        NormalizedUsername = GuardConstants.Normalize(username);
    }
}

public enum AccountStatus
{
    Active,
    Inactive,
    Locked,
}

/// <summary>
/// The person Toda knows, after directory order is applied. The Id never changes, so every other
/// module references it; renames and email changes are just field updates. Accounts are deactivated,
/// never deleted, so history keeps resolving.
/// </summary>
public class Account : Entity<Guid>
{
    protected Account()
    {
    }

    public Account(Guid id, string username) : base(id)
    {
        Username = username.Trim();
        NormalizedUsername = GuardConstants.Normalize(username);
        DisplayName = Username;
        CreatedAt = DateTime.UtcNow;
    }

    public string Username { get; set; } = null!;
    public string NormalizedUsername { get; private set; } = null!;
    public string DisplayName { get; set; } = null!;
    public string? Email { get; set; }
    public AccountStatus Status { get; set; }
    public string? StatusReason { get; set; }

    /// <summary>The directory that owns this username right now.</summary>
    public Guid DirectoryId { get; set; }

    /// <summary>The winning directory record.</summary>
    public Guid? DirectoryUserId { get; set; }

    /// <summary>Locked by an admin in Toda, independent of any directory.</summary>
    public bool LockedLocally { get; set; }

    public DateTime? LastLoginAt { get; set; }
    public DateTime CreatedAt { get; private set; }

    /// <summary>The person's language (a site language code); null follows the site's default (ADR 0039).</summary>
    public string? Language { get; set; }

    /// <summary>The person's time zone (IANA or Windows id); null follows the site's.</summary>
    public string? TimeZone { get; set; }

    /// <summary>
    /// The account this one was merged into (ADR 0044): it stays inactive, keeps its username, and lookups follow this to
    /// the survivor. Null for everyone else.
    /// </summary>
    public Guid? MergedIntoId { get; set; }

    /// <summary>
    /// Where mail goes when it isn't the directory's address: one of the account's verified addresses (ADR 0044). Null
    /// means the directory's.
    /// </summary>
    public string? MailTo { get; set; }

    /// <summary>The address mail goes to: the one chosen, else the directory's.</summary>
    public string? MailAddress => MailTo ?? Email;

    /// <summary>
    /// An account that isn't a person (M7): it has roles like anyone, never signs in, and acts only through the
    /// personal access tokens an admin makes for it.
    /// </summary>
    public bool IsService { get; set; }
}

/// <summary>
/// What a group is (ADR 0037). Standard groups are made in Toda or synced; Toda keeps the others in step itself: a
/// directory's group (everyone whose account comes from it), an LDAP OU's group (everyone under the OU), and
/// organizations (customers, by hand or by their email's domain).
/// </summary>
public static class GroupKinds
{
    public const string Standard = "standard";
    public const string Directory = "directory";
    public const string Ou = "ou";
    public const string Organization = "organization";

    public static readonly IReadOnlyList<string> All = [Standard, Directory, Ou, Organization];
}

/// <summary>
/// A group in one directory. Groups are identified by id, never by name: two directories can both have
/// "admins", and an LDAP admin creating a same-named group must not gain anything in Toda.
/// </summary>
public class Group : Entity<Guid>
{
    protected Group()
    {
    }

    public Group(Guid id, Guid directoryId, string name, bool isLocal) : base(id)
    {
        DirectoryId = directoryId;
        IsLocal = isLocal;
        SetName(name);
        CreatedAt = DateTime.UtcNow;
    }

    public Guid DirectoryId { get; private set; }
    public string? ExternalId { get; set; }
    public string Name { get; private set; } = null!;
    public string NormalizedName { get; private set; } = null!;
    public string? Description { get; set; }

    /// <summary>Created in Toda rather than synced from the directory.</summary>
    public bool IsLocal { get; private set; }

    /// <summary>One of <see cref="GroupKinds"/>.</summary>
    public string Kind { get; set; } = GroupKinds.Standard;

    /// <summary>An organization's attributes (customer number, region...): names to values.</summary>
    public Dictionary<string, string> Attributes { get; set; } = [];

    /// <summary>An organization's email domains: active accounts whose email is in one of them are its members.</summary>
    public List<string> EmailDomains { get; set; } = [];

    /// <summary>Whether Toda works out the members itself (a directory's or an OU's group): no one adds or removes them.</summary>
    public bool Computed => Kind is GroupKinds.Directory or GroupKinds.Ou;

    public DateTime CreatedAt { get; private set; }

    public void SetName(string name)
    {
        Name = name.Trim();
        NormalizedName = GuardConstants.Normalize(name);
    }
}

public enum MemberType
{
    /// <summary>A user record in one directory (synced memberships).</summary>
    DirectoryUser,

    /// <summary>An account, regardless of directory (memberships added in Toda).</summary>
    Account,

    /// <summary>A nested group.</summary>
    Group,
}

public enum MembershipSource
{
    /// <summary>Asserted by the directory during sync. Only sync adds or removes these.</summary>
    Directory,

    /// <summary>Added in Toda. Never touched by sync.</summary>
    Manual,

    /// <summary>An organization's member because their email is in one of its domains; Toda adds and removes these.</summary>
    Domain,
}

/// <summary>One row of the membership ledger: a member of a group, and who asserted it.</summary>
public class GroupMembership : Entity<Guid>
{
    protected GroupMembership()
    {
    }

    public GroupMembership(Guid id, Guid groupId, MemberType memberType, Guid memberId, MembershipSource source) : base(id)
    {
        GroupId = groupId;
        MemberType = memberType;
        MemberId = memberId;
        Source = source;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid GroupId { get; private set; }
    public MemberType MemberType { get; private set; }
    public Guid MemberId { get; private set; }
    public MembershipSource Source { get; private set; }
    public DateTime CreatedAt { get; private set; }
}

public class SyncRun : Entity<Guid>
{
    protected SyncRun()
    {
    }

    public SyncRun(Guid id, Guid directoryId) : base(id)
    {
        DirectoryId = directoryId;
        StartedAt = DateTime.UtcNow;
    }

    public Guid DirectoryId { get; private set; }
    public DateTime StartedAt { get; private set; }
    public DateTime? FinishedAt { get; set; }
    public bool? Succeeded { get; set; }
    public int UsersAdded { get; set; }
    public int UsersUpdated { get; set; }
    public int UsersDeactivated { get; set; }
    public int GroupsSynced { get; set; }
    public int MembershipsSynced { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// The security audit (ADR 0042): sign-ins and their failures, exports, and every change to who may do what. The
/// account is whoever the event counts as (who signed in, who made the change); the actor, who acted for them when that
/// was someone else; the target, what the change was made to. Nothing edits or deletes a row but the retention.
/// </summary>
public class SecurityEvent : Entity<Guid>
{
    protected SecurityEvent()
    {
    }

    public SecurityEvent(Guid id, string type, string? username, Guid? accountId, string? detail, string? ip) : base(id)
    {
        Type = type;
        Username = username;
        AccountId = accountId;
        Detail = detail;
        Ip = ip;
        Time = DateTime.UtcNow;
    }

    public DateTime Time { get; private set; }
    public string Type { get; private set; } = null!;
    public string? Username { get; private set; }
    public Guid? AccountId { get; private set; }
    public string? Detail { get; private set; }
    public string? Ip { get; private set; }

    public Guid? ActingAccountId { get; init; }
    public string? ActingMode { get; init; }

    /// <summary>The impersonation session the change was made in.</summary>
    public Guid? SessionId { get; init; }

    public string? TargetType { get; init; }
    public Guid? TargetId { get; init; }
    public string? TargetName { get; init; }
}

/// <summary>
/// The site's security settings (one row): how long the security audit keeps its events, and how recently a person must
/// have signed in or stepped up to do something sensitive (ADR 0042).
/// </summary>
public class SecuritySettings : Entity<Guid>
{
    public static readonly Guid SingletonId = new("5ec0a0d1-0000-4000-8000-000000000001");

    public const int DefaultRetentionDays = 730;
    public const int MinRetentionDays = 90;
    public const int MaxRetentionDays = 3650;

    protected SecuritySettings()
    {
    }

    public SecuritySettings(Guid id) : base(id)
    {
    }

    public int RetentionDays { get; set; } = DefaultRetentionDays;

    public const int DefaultStepUpMinutes = 10;
    public const int MinStepUpMinutes = 1;
    public const int MaxStepUpMinutes = 30;

    public int StepUpMinutes { get; set; } = DefaultStepUpMinutes;

    public const int DefaultTokenMaxDays = 90;
    public const int MinTokenMaxDays = 1;
    public const int MaxTokenMaxDays = 366;

    /// <summary>The longest a personal access token may live: every token expires, within this.</summary>
    public int TokenMaxDays { get; set; } = DefaultTokenMaxDays;
}

/// <summary>Whether a personal access token may change things or only read.</summary>
public static class TokenAccess
{
    public const string Read = "read";
    public const string Write = "write";
}

/// <summary>
/// A personal access token (M7, ADR 0042): a secret an account uses as a bearer token, shown once and kept only as its
/// hash. It can do no more than the account; it may be limited to reading, to some projects and to some tools (an
/// agent's), it always expires, and it can never do a sensitive action.
/// </summary>
public class PersonalAccessToken : Entity<Guid>
{
    protected PersonalAccessToken()
    {
    }

    public PersonalAccessToken(Guid id, Guid accountId, string name, string prefix, string secretHash, string access, List<Guid>? projectIds, DateTime expiresAt, Guid createdBy,
        List<string>? tools = null)
        : base(id)
    {
        Tools = tools;
        AccountId = accountId;
        Name = name;
        Prefix = prefix;
        SecretHash = secretHash;
        Access = access;
        ProjectIds = projectIds;
        ExpiresAt = expiresAt;
        CreatedBy = createdBy;
        CreatedAt = DateTime.UtcNow;
    }

    public Guid AccountId { get; private set; }
    public string Name { get; private set; } = null!;

    /// <summary>The token's first characters, to recognise it in a list.</summary>
    public string Prefix { get; private set; } = null!;

    /// <summary>SHA-256 of the whole token, in hex.</summary>
    public string SecretHash { get; private set; } = null!;

    public string Access { get; private set; } = null!;

    /// <summary>The projects it's limited to; null for every project the account may use.</summary>
    public List<Guid>? ProjectIds { get; private set; }

    /// <summary>The tools it may use (their catalog names, M7); null for every tool the account may use.</summary>
    public List<string>? Tools { get; private set; }

    public DateTime ExpiresAt { get; private set; }
    public DateTime CreatedAt { get; private set; }

    /// <summary>Who made it: the account itself, or an admin for a service account.</summary>
    public Guid CreatedBy { get; private set; }

    public DateTime? LastUsedAt { get; set; }
    public string? LastUsedIp { get; set; }
    public DateTime? RevokedAt { get; set; }
    public Guid? RevokedBy { get; set; }

    public bool IsActive(DateTime now) => RevokedAt is null && ExpiresAt > now;
}
