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
            b.HasIndex(x => x.NormalizedUsername).IsUnique();
        });

        builder.Entity<Group>(b =>
        {
            b.ToTable("groups");
            b.Property(x => x.Name).HasMaxLength(256).IsRequired();
            b.Property(x => x.NormalizedName).HasMaxLength(256).IsRequired();
            b.HasIndex(x => new { x.DirectoryId, x.NormalizedName }).IsUnique();
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

        builder.Entity<SecurityEvent>(b =>
        {
            b.ToTable("security_events");
            b.Property(x => x.Type).HasMaxLength(64).IsRequired();
            b.HasIndex(x => x.Time);
        });
    }
}
