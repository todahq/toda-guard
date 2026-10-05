using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Toda.Guard.Data;

/// <summary>For `dotnet ef migrations add` only.</summary>
public class GuardDbContextFactory : IDesignTimeDbContextFactory<GuardDbContext>
{
    public GuardDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<GuardDbContext>()
            .UseNpgsql(DesignTime.ConnectionString, b => b.MigrationsHistoryTable("__EFMigrationsHistory", GuardDbContext.Schema))
            .Options);
}

internal static class DesignTime
{
    public const string ConnectionString = "Host=localhost;Port=55432;Database=toda;Username=toda;Password=toda";
}
