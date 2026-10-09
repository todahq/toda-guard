using Microsoft.EntityFrameworkCore;
using Toda.Guard.Domain;
using Volo.Abp.Data;
using Volo.Abp.EntityFrameworkCore;

namespace Toda.Guard.Data;

[ConnectionStringName("Default")]
public class GuardDbContext(DbContextOptions<GuardDbContext> options) : AbpDbContext<GuardDbContext>(options)
{
    public const string Schema = "guard";

    public DbSet<UserDirectory> Directories => Set<UserDirectory>();
    public DbSet<DirectoryUser> DirectoryUsers => Set<DirectoryUser>();
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Group> Groups => Set<Group>();
    public DbSet<GroupMembership> Memberships => Set<GroupMembership>();
    public DbSet<SyncRun> SyncRuns => Set<SyncRun>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<RoleRule> RoleRules => Set<RoleRule>();
    public DbSet<RoleGrant> RoleGrants => Set<RoleGrant>();
    public DbSet<SignUpSettings> SignUpSettings => Set<SignUpSettings>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.HasDefaultSchema(Schema);

        builder.Entity<UserDirectory>(b =>
        {
            b.ToTable("directories");
            b.Property(x => x.Name).HasMaxLength(200).IsRequired();
            b.Property(x => x.Type).HasMaxLength(64).IsRequired();
            b.Property(x => x.SettingsJson).HasColumnType("jsonb");
            b.HasIndex(x => x.Order);
        });

        builder.Entity<DirectoryUser>(b =>
        {
            b.ToTable("directory_users");
            b.Property(x => x.ExternalId).HasMaxLength(256).IsRequired();
            b.Property(x => x.Username).HasMaxLength(256).IsRequired();
            b.Property(x => x.NormalizedUsername).HasMaxLength(256).IsRequired();
            b.HasIndex(x => new { x.DirectoryId, x.NormalizedUsername }).IsUnique();
            b.HasIndex(x => new { x.DirectoryId, x.ExternalId }).IsUnique();
            b.HasIndex(x => x.NormalizedUsername);
        });

        builder.Entity<Account>(b =>
        {
            b.ToTable("accounts");
            b.Property(x => x.Username).HasMaxLength(256).IsRequired();
            b.Property(x => x.NormalizedUsername).HasMaxLength(256).IsRequired();
            b.Property(x => x.Status).HasConversion<string>().HasMaxLength(16);
            b.Property(x => x.Language).HasMaxLength(35);
            b.Property(x => x.TimeZone).HasMaxLength(64);
            b.HasIndex(x => x.NormalizedUsername).IsUnique();
        });

        builder.Entity<Group>(b =>
        {
            b.ToTable("groups");
            b.Property(x => x.Name).HasMaxLength(256).IsRequired();
            b.Property(x => x.NormalizedName).HasMaxLength(256).IsRequired();
            b.Property(x => x.Kind).HasMaxLength(16).IsRequired().HasDefaultValue(GroupKinds.Standard);
            System.Text.Json.JsonSerializerOptions json = new(System.Text.Json.JsonSerializerDefaults.Web);
            b.Property(x => x.Attributes).HasColumnType("jsonb").HasConversion(
                v => System.Text.Json.JsonSerializer.Serialize(v, json),
                v => System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(v, json) ?? new(),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<Dictionary<string, string>>(
                    (a, b) => System.Text.Json.JsonSerializer.Serialize(a, json) == System.Text.Json.JsonSerializer.Serialize(b, json),
                    v => System.Text.Json.JsonSerializer.Serialize(v, json).GetHashCode(),
                    v => new Dictionary<string, string>(v)));
            b.Property(x => x.EmailDomains).HasColumnType("jsonb").HasConversion(
                v => System.Text.Json.JsonSerializer.Serialize(v, json),
                v => System.Text.Json.JsonSerializer.Deserialize<List<string>>(v, json) ?? new(),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<List<string>>(
                    (a, b) => a!.SequenceEqual(b!),
                    v => string.Join(",", v).GetHashCode(),
                    v => v.ToList()));
            b.Ignore(x => x.Computed);
            b.HasIndex(x => new { x.DirectoryId, x.NormalizedName }).IsUnique();
            b.HasIndex(x => x.Kind);
        });

        builder.Entity<GroupMembership>(b =>
        {
            b.ToTable("memberships");
            b.Property(x => x.MemberType).HasConversion<string>().HasMaxLength(16);
            b.Property(x => x.Source).HasConversion<string>().HasMaxLength(16);
            b.HasIndex(x => new { x.GroupId, x.MemberType, x.MemberId, x.Source }).IsUnique();
            b.HasIndex(x => new { x.MemberType, x.MemberId });
        });

        builder.Entity<SyncRun>(b =>
        {
            b.ToTable("sync_runs");
            b.HasIndex(x => new { x.DirectoryId, x.StartedAt });
        });

        builder.Entity<Role>(b =>
        {
            b.ToTable("roles");
            b.Property(x => x.Key).HasMaxLength(64).IsRequired();
            b.Property(x => x.Name).HasMaxLength(200).IsRequired();
            b.HasIndex(x => x.Key).IsUnique();
        });

        builder.Entity<RoleRule>(b =>
        {
            b.ToTable("role_rules");
            b.Property(x => x.Json).HasColumnType("jsonb").IsRequired();
            b.HasIndex(x => new { x.RoleId, x.Order });
        });

        builder.Entity<RoleGrant>(b =>
        {
            b.ToTable("role_grants");
            b.Property(x => x.PrincipalType).HasConversion<string>().HasMaxLength(16);
            b.Property(x => x.ScopeJson).HasColumnType("jsonb").IsRequired();
            b.Property(x => x.ScopeKey).HasMaxLength(128);
            b.HasIndex(x => new { x.PrincipalType, x.PrincipalId });
            b.HasIndex(x => x.ScopeKey);
            b.HasIndex(x => x.RoleId);
        });

        builder.Entity<SignUpSettings>(b =>
        {
            b.ToTable("signup_settings");
            b.Property(x => x.Id).ValueGeneratedNever();
            System.Text.Json.JsonSerializerOptions json = new(System.Text.Json.JsonSerializerDefaults.Web);
            b.Property(x => x.EmailDomains).HasColumnType("jsonb").HasConversion(
                v => System.Text.Json.JsonSerializer.Serialize(v, json),
                v => System.Text.Json.JsonSerializer.Deserialize<List<string>>(v, json) ?? new(),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<List<string>>(
                    (a, b) => a!.SequenceEqual(b!),
                    v => string.Join(",", v).GetHashCode(),
                    v => v.ToList()));
        });

        builder.Entity<SecurityEvent>(b =>
        {
            b.ToTable("security_events");
            b.Property(x => x.Type).HasMaxLength(64).IsRequired();
            b.HasIndex(x => x.Time);
        });
    }
}
