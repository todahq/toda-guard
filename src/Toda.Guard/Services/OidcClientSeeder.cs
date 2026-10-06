using Microsoft.Extensions.Configuration;
using Toda.Guard.Controllers;
using OpenIddict.Abstractions;
using Volo.Abp.DependencyInjection;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Toda.Guard.Services;

/// <summary>Registers the first-party Next.js server as a confidential OpenIddict client, and keeps its secret in step with configuration.</summary>
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

        object? existing = await applications.FindByClientIdAsync(GuardOidc.WebClientId, cancellationToken);
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
