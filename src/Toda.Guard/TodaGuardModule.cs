using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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
    /// <summary>The default authentication scheme: it sends each bearer token to the handler for its kind, and a browser's cookie to its session's.</summary>
    public const string TodaBearer = "TodaBearer";

    public const string Version = "0.1.0";

    /// <summary>
    /// The scheme for a request (ADR 0075): a personal access token, any other bearer token (OpenIddict's), or with no
    /// bearer token a browser's session cookie. A bearer token always wins, so a phone or tool never acts on a cookie.
    /// </summary>
    public static string SchemeFor(Microsoft.AspNetCore.Http.HttpRequest request) =>
        PersonalTokenHandler.Carries(request) ? PersonalTokenHandler.SchemeName
        : request.Headers.Authorization.Count == 0 && WebSessionHandler.Carries(request) ? WebSessionHandler.SchemeName
        : OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

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
            // The outbox sender's lock is named after this: the module's own, or Projects' sender and this one wait on each other.
            outbox.DatabaseName = GuardDbContext.Schema;
            outbox.Selector = type => EventCatalogOptions.IsEvent(type, typeof(AccountCreatedEto).Assembly);
        }));

        // Sign-in: OpenIddict issues short-lived access tokens and rotating refresh tokens to the
        // first-party Next.js server; APIs validate them locally (ADR 0007).
        // Their keys (ADR 0050): certificates, a folder mounted from a secret store, or Postgres (made once, shared by every node).
        string dataRoot = Path.GetFullPath(configuration["Toda:DataRoot"] ?? Path.Combine(context.Services.GetHostingEnvironment().ContentRootPath, "App_Data"));
        (SecurityKey signingKey, SecurityKey encryptionKey) = OidcKeys.Resolve(configuration, dataRoot);

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
                options.AllowPasswordFlow().AllowRefreshTokenFlow().AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange()
                    .AllowCustomFlow(Controllers.TokenController.SecondFactorGrant); // the second step (ADR 0082)
                options.RegisterScopes(OpenIddictConstants.Scopes.OfflineAccess, GuardOidc.ApiScope, OAuthAgents.ReadScope);
                // Revoking the phone app's (or a script's) refresh token ends its whole sign-in (ADR 0075).
                options.AddEventHandler(EndSignInOnRevocation.Descriptor);
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
                    // After OpenIddict sets the issuer, before it fills in the endpoints still empty. Not the issuer's own
                    // order: with two handlers on one order, which runs first changes as handlers are added.
                }).SetOrder(OpenIddict.Server.OpenIddictServerHandlers.Discovery.AttachIssuer.Descriptor.Order + 500));
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

        // A bearer token is either an access token from the token endpoint (OpenIddict) or a personal access token (M7). A
        // request without one is a browser's, signed in by its session cookie (ADR 0075).
        context.Services.AddMemoryCache();
        // A session ended or stepped up on another server is forgotten here at once (docs/ha.md step 2).
        context.Services.AddSingleton<Toda.Platform.Changes.IChangeHandler, Services.WebSessionChanged>();
        context.Services.AddAuthentication(TodaBearer)
            .AddPolicyScheme(TodaBearer, null, options => options.ForwardDefaultSelector = http => SchemeFor(http.Request))
            .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, PersonalTokenHandler>(PersonalTokenHandler.SchemeName, null)
            .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, WebSessionHandler>(WebSessionHandler.SchemeName, null);

        // Anti-forgery for the session cookie is the handler's own check (the X-Toda-Csrf header); ABP's, for its own
        // cookie schemes, doesn't apply.
        Configure<Volo.Abp.AspNetCore.Mvc.AntiForgery.AbpAntiForgeryOptions>(options => options.AutoValidate = false);

        context.Services.AddAuthorizationBuilder()
            .AddPolicy(TodaPolicies.Admin, policy => policy.RequireAuthenticatedUser().AddRequirements(new TodaAdminRequirement()));
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

        // A test site shows accounts' passwords on its sign-in page: said once at start, so a site people use doesn't by mistake.
        if (context.ServiceProvider.GetRequiredService<TestAccounts>().List() is { Count: > 0 } shown)
        {
            context.ServiceProvider.GetRequiredService<ILogger<TodaGuardModule>>().LogWarning(
                "The sign-in page shows {Count} test accounts with their passwords ({Section}): only for a test site", shown.Count, TestAccounts.Section);
        }
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
