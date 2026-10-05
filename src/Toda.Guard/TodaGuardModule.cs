using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Toda.Guard.Data;
using Toda.Guard.Domain;
using Toda.Guard.Directories;
using Toda.Guard.Services;
using Toda.Platform;
using Toda.Platform.Controllers;
using Toda.Platform.Plugins;
using Volo.Abp.EntityFrameworkCore;
using Volo.Abp.Modularity;

namespace Toda.Guard;

[DependsOn(typeof(TodaPlatformModule))]
public class TodaGuardModule : AbpModule
{
    public const string Version = "0.1.0";

    public override void ConfigureServices(ServiceConfigurationContext context)
    {
        IConfiguration configuration = context.Services.GetConfiguration();

        context.Services.AddAbpDbContext<GuardDbContext>();
        Configure<AbpDbContextOptions>(options =>
            options.Configure<GuardDbContext>(c => c.UseNpgsql(npgsql =>
                npgsql.MigrationsHistoryTable("__EFMigrationsHistory", GuardDbContext.Schema))));

        context.Services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = configuration["Guard:Jwt:Issuer"] ?? "toda",
                    ValidAudience = configuration["Guard:Jwt:Audience"] ?? "toda",
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                        configuration["Guard:Jwt:SigningKey"] ?? throw new InvalidOperationException("Guard:Jwt:SigningKey is not configured."))),
                    NameClaimType = "unique_name",
                };
            });

        context.Services.AddAuthorization(options =>
            options.AddPolicy(TodaPolicies.Admin, policy => policy.RequireAuthenticatedUser().AddRequirements(new TodaAdminRequirement())));
        context.Services.AddTransient<IAuthorizationHandler, TodaAdminHandler>();

        context.Services.AddHostedService<DirectorySyncScheduler>();

        Configure<TodaPlatformOptions>(options => options.ModuleVersions["toda-guard"] = Version);

        // What guard offers to plugins. Connector plugins only ever see their own directory types.
        Configure<PluginHostServiceOptions>(options =>
        {
            options.Expose<IAccountLookup>();
            options.Expose<IMembershipResolver>();
            options.Expose<IDirectoryConnectionProvider>((hostScope, plugin) => new PluginDirectoryConnectionProvider(hostScope, plugin.Key));
        });
    }
}

public sealed class TodaAdminRequirement : IAuthorizationRequirement;

/// <summary>Admin = effective member, directly or through any nesting, of the internal toda-admins group (by id, never by name).</summary>
public sealed class TodaAdminHandler(IMembershipResolver memberships) : AuthorizationHandler<TodaAdminRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, TodaAdminRequirement requirement)
    {
        string? sub = context.User.FindFirst("sub")?.Value ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (Guid.TryParse(sub, out Guid accountId) && await memberships.IsMemberAsync(accountId, GuardConstants.AdminsGroupId))
        {
            context.Succeed(requirement);
        }
    }
}
