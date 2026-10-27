using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Toda.Guard.Data;
using Toda.Guard.Services;

namespace Toda.Guard;

/// <summary>
/// What a host calls at start (ADR 0087): Guard's migrations (its own tables, then OpenIddict's, in schema guard), and its
/// seed (the internal directory, the first admin from Guard:Seed:AdminPassword, the admins and users groups, the system
/// roles). A host with several servers calls them under a lock all of them share. Toda migrates and seeds Guard itself,
/// in its own order.
/// </summary>
public static class GuardDatabase
{
    public static async Task MigrateAsync(IServiceProvider services, CancellationToken cancellationToken = default)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<GuardDbContext>().Database.MigrateAsync(cancellationToken);
        await scope.ServiceProvider.GetRequiredService<OidcDbContext>().Database.MigrateAsync(cancellationToken);
    }

    public static async Task SeedAsync(IServiceProvider services, CancellationToken cancellationToken = default)
    {
        await using AsyncServiceScope scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<GuardSeeder>().SeedAsync(cancellationToken);
    }
}
