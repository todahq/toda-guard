using Microsoft.Extensions.Configuration;
using Toda.Guard.Controllers;
using OpenIddict.Abstractions;
using Volo.Abp.DependencyInjection;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Toda.Guard.Services;

/// <summary>
/// Registers Toda's first-party clients with OpenIddict: the Next.js server (confidential, its secret kept in step with
/// configuration) and the mobile app (public, ADR 0062).
/// </summary>
public class OidcClientSeeder(IOpenIddictApplicationManager applications, IConfiguration configuration) : ITransientDependency
{
    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        string secret = configuration["Guard:Oidc:WebClientSecret"]
            ?? throw new InvalidOperationException("Guard:Oidc:WebClientSecret is not configured.");

        OpenIddictApplicationDescriptor descriptor = new()
        {
            ClientId = GuardOidc.WebClientId,
            ClientSecret = secret,
            ClientType = ClientTypes.Confidential,
            DisplayName = "Toda web",
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.Endpoints.Revocation,
                Permissions.GrantTypes.Password,
                Permissions.GrantTypes.RefreshToken,
                Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                Permissions.Prefixes.Scope + GuardOidc.ApiScope,
            },
        };

        await UpsertAsync(descriptor, cancellationToken);

        // The mobile app: no secret (a phone can't keep one), the same grants and scopes as the web.
        await UpsertAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = GuardOidc.MobileClientId,
            ClientType = ClientTypes.Public,
            DisplayName = "Toda mobile",
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.Endpoints.Revocation,
                Permissions.GrantTypes.Password,
                Permissions.GrantTypes.RefreshToken,
                Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                Permissions.Prefixes.Scope + GuardOidc.ApiScope,
            },
        }, cancellationToken);
    }

    private async Task UpsertAsync(OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken)
    {
        object? existing = await applications.FindByClientIdAsync(descriptor.ClientId!, cancellationToken);
        if (existing is null)
        {
            await applications.CreateAsync(descriptor, cancellationToken);
        }
        else
        {
            await applications.UpdateAsync(existing, descriptor, cancellationToken);
        }
    }
}
