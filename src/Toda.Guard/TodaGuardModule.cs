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
using Volo.Abp.EntityFrameworkCore.DistributedEvents;
using Volo.Abp.EventBus.Distributed;
using Volo.Abp.Modularity;

namespace Toda.Guard;

[DependsOn(typeof(TodaPlatformModule))]
public class TodaGuardModule : AbpModule
{
    /// <summary>The default authentication scheme: it sends each bearer token to the handler for its kind.</summary>
    public const string TodaBearer = "TodaBearer";

    public const string Version = "0.1.0";

    public override void ConfigureServices(ServiceConfigurationContext context)
    {
        IConfiguration configuration = context.Services.GetConfiguration();

        context.Services.AddAbpDbContext<GuardDbContext>();
        Configure<AbpDbContextOptions>(options =>
            options.Configure<GuardDbContext>(c => c.UseNpgsql(npgsql =>
                npgsql.MigrationsHistoryTable("__EFMigrationsHistory", GuardDbContext.Schema))));
        // The events Guard publishes for other modules and plugins (ADR 0047), sent from its outbox.
        Configure<EventCatalogOptions>(options => options.AddAssembly(typeof(AccountCreatedEto).Assembly, GuardDbContext.Schema));
        Configure<AbpDistributedEventBusOptions>(options => options.Outboxes.Configure(GuardDbContext.Schema, outbox =>
        {
            outbox.UseDbContext<GuardDbContext>();
            outbox.Selector = type => EventCatalogOptions.IsEvent(type, typeof(AccountCreatedEto).Assembly);
        }));

        // Sign-in: OpenIddict issues short-lived access tokens and rotating refresh tokens to the
        // first-party Next.js server; APIs validate them locally (ADR 0007).
        string dataRoot = configuration["Toda:DataRoot"] ?? Path.Combine(context.Services.GetHostingEnvironment().ContentRootPath, "App_Data");
        string keysFolder = Path.GetFullPath(configuration["Guard:Oidc:KeysPath"] ?? Path.Combine(dataRoot, "oidc-keys"));
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
                    .SetRevocationEndpointUris("connect/revoke")
                    // Apps and agents (M7): the authorization code flow, always with PKCE, behind a consent page.
                    .SetAuthorizationEndpointUris("connect/authorize");
                options.AllowPasswordFlow().AllowRefreshTokenFlow().AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
                options.RegisterScopes(OpenIddictConstants.Scopes.OfflineAccess, GuardOidc.ApiScope, OAuthAgents.ReadScope);
                // MCP clients register themselves (RFC 7591) at the endpoint the discovery document names.
                options.AddEventHandler<OpenIddict.Server.OpenIddictServerEvents.HandleConfigurationRequestContext>(handler => handler.UseInlineHandler(context =>
                {
                    if (context.Issuer is { } issuer)
                    {
                        context.Metadata["registration_endpoint"] = new Uri(issuer, "connect/register").AbsoluteUri;
                        // Behind the web app, the endpoints are where the issuer is (the site's public address), not
                        // where this request came in.
                        context.AuthorizationEndpoint = new Uri(issuer, "connect/authorize");
                        context.TokenEndpoint = new Uri(issuer, "connect/token");
                        context.RevocationEndpoint = new Uri(issuer, "connect/revoke");
                        context.JsonWebKeySetEndpoint = new Uri(issuer, ".well-known/jwks");
                    }

                    return default;
                }).SetOrder(int.MaxValue - 100_000));
                // PKCE with S256 only: "plain" would hand the verifier over in the clear (MCP requires S256).
                options.Configure(server => server.CodeChallengeMethods.Remove(OpenIddictConstants.CodeChallengeMethods.Plain));
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15))
                    .SetRefreshTokenLifetime(TimeSpan.FromDays(14))
                    .SetRefreshTokenReuseLeeway(TimeSpan.FromSeconds(30));
                options.AddSigningKey(signingKey).AddEncryptionKey(encryptionKey);
                if (configuration["Guard:Oidc:Issuer"] is { Length: > 0 } issuer)
                {
                    options.SetIssuer(new Uri(issuer));
                }

                OpenIddictServerAspNetCoreBuilder aspNetCore = options.UseAspNetCore().EnableTokenEndpointPassthrough().EnableAuthorizationEndpointPassthrough();
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

        // A bearer token is either an access token from the token endpoint (OpenIddict) or a personal access token (M7).
        context.Services.AddAuthentication(TodaBearer)
            .AddPolicyScheme(TodaBearer, null, options => options.ForwardDefaultSelector = http =>
                PersonalTokenHandler.Carries(http.Request) ? PersonalTokenHandler.Scheme : OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
            .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, PersonalTokenHandler>(PersonalTokenHandler.Scheme, null);

        context.Services.AddAuthorization(options =>
            options.AddPolicy(TodaPolicies.Admin, policy => policy.RequireAuthenticatedUser().AddRequirements(new TodaAdminRequirement())));
        context.Services.AddTransient<IAuthorizationHandler, TodaAdminHandler>();

        context.Services.AddHostedService<DirectorySyncScheduler>();
        context.Services.AddHostedService<SecurityAuditRetention>();

        Configure<TodaPlatformOptions>(options => options.ModuleVersions["toda-guard"] = Version);

        // What guard offers to plugins. Connector plugins only ever see their own directory types.
        Configure<PluginHostServiceOptions>(options =>
        {
            options.Expose<IAccountLookup>();
            options.Expose<IGroupLookup>();
            options.Expose<IMembershipResolver>();
            options.Expose<IAccountProvisioning>();
            options.Expose<IDirectoryConnectionProvider>((hostScope, plugin) => new PluginDirectoryConnectionProvider(hostScope, plugin.Key));
        });
    }

    public override void OnApplicationInitialization(Volo.Abp.ApplicationInitializationContext context)
    {
        // The mails self-service sends (ADR 0037), as templates admins can reword (ADR 0039).
        Toda.Platform.Templates.TemplateCatalog templates = context.ServiceProvider.GetRequiredService<Toda.Platform.Templates.TemplateCatalog>();
        templates.Register(SelfServiceMail.VerifyDefinition);
        templates.Register(SelfServiceMail.ResetDefinition);
        templates.Register(AddressMail.VerifyDefinition);
    }
}

public sealed class TodaAdminRequirement : IAuthorizationRequirement;

/// <summary>
/// Admin = may "manage" "all". Out of the box that comes from the Administrator role, granted to the
/// internal toda-admins group (by id, never by name), so it follows group membership including nesting. The ability
/// is the request's, through the acting context, so a token's limits apply here too (ADR 0042).
/// </summary>
public sealed class TodaAdminHandler(AbilityFactory abilities, Toda.Platform.Acting.ActingContext acting) : AuthorizationHandler<TodaAdminRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, TodaAdminRequirement requirement)
    {
        if (acting.SubjectId is Guid accountId && (await abilities.ForAccountAsync(accountId)).Can("manage", "all"))
        {
            context.Succeed(requirement);
        }
    }
}
