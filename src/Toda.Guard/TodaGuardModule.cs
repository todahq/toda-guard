using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Toda.Guard.Controllers;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
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

        // Sign-in: OpenIddict issues short-lived access tokens and rotating refresh tokens to the
        // first-party Next.js server; APIs validate them locally (ADR 0007).
        string contentRoot = context.Services.GetHostingEnvironment().ContentRootPath;
        string keysFolder = Path.GetFullPath(Path.Combine(contentRoot, configuration["Guard:Oidc:KeysPath"] ?? "App_Data/oidc-keys"));
        (SecurityKey signingKey, SecurityKey encryptionKey) = OidcKeys.LoadOrCreate(keysFolder);

        context.Services.AddDbContext<OidcDbContext>(options =>
        {
            options.UseNpgsql(configuration.GetConnectionString("Default"),
                npgsql => npgsql.MigrationsHistoryTable(OidcDbContext.HistoryTable, GuardDbContext.Schema));
            options.UseOpenIddict<Guid>();
        });

        context.Services.AddOpenIddict()
            .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<OidcDbContext>().ReplaceDefaultEntities<Guid>())
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("connect/token")
                    .SetRevocationEndpointUris("connect/revoke");
                options.AllowPasswordFlow().AllowRefreshTokenFlow();
                options.RegisterScopes(OpenIddictConstants.Scopes.OfflineAccess, GuardOidc.ApiScope);
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15))
                    .SetRefreshTokenLifetime(TimeSpan.FromDays(14))
                    .SetRefreshTokenReuseLeeway(TimeSpan.FromSeconds(30));
                options.AddSigningKey(signingKey).AddEncryptionKey(encryptionKey);
                if (configuration["Guard:Oidc:Issuer"] is { Length: > 0 } issuer)
                {
                    options.SetIssuer(new Uri(issuer));
                }

                OpenIddictServerAspNetCoreBuilder aspNetCore = options.UseAspNetCore().EnableTokenEndpointPassthrough();
                if (configuration.GetValue("Guard:Oidc:AllowHttp", false))
                {
                    aspNetCore.DisableTransportSecurityRequirement();
                }
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        context.Services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);

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

/// <summary>
/// Admin = may "manage" "all". Out of the box that comes from the Administrator role, granted to the
/// internal toda-admins group (by id, never by name), so it follows group membership including nesting.
/// </summary>
public sealed class TodaAdminHandler(AbilityFactory abilities) : AuthorizationHandler<TodaAdminRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, TodaAdminRequirement requirement)
    {
        string? sub = context.User.FindFirst("sub")?.Value ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (Guid.TryParse(sub, out Guid accountId) && (await abilities.ForAccountAsync(accountId)).Can("manage", "all"))
        {
            context.Succeed(requirement);
        }
    }
}
