using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Toda.Guard.Data;
using Toda.Guard.Domain;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>Creates the internal directory, the first admin, and the toda-admins and toda-users groups.</summary>
public class GuardSeeder(GuardDb guardDb, AccountProjector projector, IConfiguration configuration) : ITransientDependency
{
    public Task SeedAsync(CancellationToken cancellationToken = default) => guardDb.RunAsync(async db =>
    {
        if (!await db.Directories.AnyAsync(d => d.Id == GuardConstants.InternalDirectoryId, cancellationToken))
        {
            db.Directories.Add(new UserDirectory(GuardConstants.InternalDirectoryId, "Toda internal", GuardConstants.InternalType, order: 0));
        }

        string adminPassword = configuration["Guard:Seed:AdminPassword"]
            ?? throw new InvalidOperationException("Guard:Seed:AdminPassword is not configured.");
        if (!await db.DirectoryUsers.AnyAsync(u => u.DirectoryId == GuardConstants.InternalDirectoryId && u.NormalizedUsername == "admin", cancellationToken))
        {
            DirectoryUser admin = new(Guid.NewGuid(), GuardConstants.InternalDirectoryId, "internal:admin", "admin")
            {
                DisplayName = "Toda Administrator",
                Email = "admin@toda.local",
            };
            admin.PasswordHash = AuthService.HashPassword(admin, adminPassword);
            db.DirectoryUsers.Add(admin);
        }

        await EnsureGroupAsync(db, GuardConstants.AdminsGroupId, "toda-admins", "Toda administrators. Members, direct or nested, can administer Toda.", cancellationToken);
        await EnsureGroupAsync(db, GuardConstants.UsersGroupId, "toda-users", "Everyone who may sign in to Toda.", cancellationToken);
        await db.SaveChangesAsync(cancellationToken);

        await projector.RebuildAsync(db, cancellationToken: cancellationToken);
        await db.SaveChangesAsync(cancellationToken);

        Account adminAccount = await db.Accounts.FirstAsync(a => a.NormalizedUsername == "admin", cancellationToken);
        if (!await db.Memberships.AnyAsync(m => m.GroupId == GuardConstants.AdminsGroupId && m.MemberType == MemberType.Account && m.MemberId == adminAccount.Id, cancellationToken))
        {
            db.Memberships.Add(new GroupMembership(Guid.NewGuid(), GuardConstants.AdminsGroupId, MemberType.Account, adminAccount.Id, MembershipSource.Manual));
            await db.SaveChangesAsync(cancellationToken);
        }
    }, requiresNew: true, cancellationToken);

    private static async Task EnsureGroupAsync(GuardDbContext db, Guid id, string name, string description, CancellationToken cancellationToken)
    {
        if (!await db.Groups.AnyAsync(g => g.Id == id, cancellationToken))
        {
            db.Groups.Add(new Group(id, GuardConstants.InternalDirectoryId, name, isLocal: true) { Description = description });
        }
    }
}

/// <summary>Runs each directory's sync on its interval.</summary>
public class DirectorySyncScheduler(IServiceScopeFactory scopes, ILogger<DirectorySyncScheduler> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
        using PeriodicTimer timer = new(TimeSpan.FromSeconds(30));
        do
        {
            try
            {
                await using AsyncServiceScope scope = scopes.CreateAsyncScope();
                GuardDb guardDb = scope.ServiceProvider.GetRequiredService<GuardDb>();
                DateTime now = DateTime.UtcNow;
                List<UserDirectory> due = await guardDb.RunAsync(db => db.Directories.AsNoTracking()
                    .Where(d => d.IsActive && d.Type != GuardConstants.InternalType && d.SyncIntervalMinutes != null)
                    .ToListAsync(stoppingToken), requiresNew: true, stoppingToken);

                foreach (UserDirectory directory in due.Where(d => d.LastSyncAt is null || d.LastSyncAt.Value.AddMinutes(d.SyncIntervalMinutes!.Value) <= now))
                {
                    await scope.ServiceProvider.GetRequiredService<DirectorySyncService>().SyncAsync(directory.Id, stoppingToken);
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Scheduled directory sync failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
