using Microsoft.Extensions.Configuration;

namespace Toda.Guard.Data;

/// <summary>
/// Which database Guard keeps its tables in (ADR 0087): ConnectionStrings:Guard, else ConnectionStrings:Default, so a
/// host that keeps everything in one database (Toda does, and must) sets nothing new.
/// </summary>
public static class GuardConnection
{
    public const string Name = "Guard";

    public static string? Of(IConfiguration configuration) =>
        configuration.GetConnectionString(Name) is { Length: > 0 } own ? own : configuration.GetConnectionString("Default");
}
