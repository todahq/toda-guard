using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Domain;
using Toda.Guard.Services;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Uow;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Toda.Guard.Controllers;

/// <summary>
/// The OpenIddict token endpoint. In M0 it serves the first-party Next.js server only: the password
/// grant (checked against guard's directories, with rate limiting and audit) and refresh tokens
/// (re-checking that the account is still active). See ADR 0007.
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)]
[UnitOfWork(IsDisabled = true)]
public class TokenController(AuthService auth, GuardDb guardDb) : AbpControllerBase
{
    [HttpPost("~/connect/token")]
    [AllowAnonymous]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange(CancellationToken cancellationToken)
    {
        OpenIddictRequest request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenIddict server request cannot be retrieved.");

        if (request.IsPasswordGrantType())
        {
            string? ip = HttpContext.Connection.RemoteIpAddress?.ToString();
            LoginResult result = await auth.LoginAsync(request.Username ?? string.Empty, request.Password ?? string.Empty, ip, cancellationToken);
            if (!result.Succeeded)
            {
                return Refuse(result.ErrorCode switch
                {
                    "too_many_attempts" => "Too many failed attempts. Try again in 15 minutes.",
                    "account_merged" => $"This account was merged into {result.MergedInto}. Sign in as {result.MergedInto}.",
                    _ => "The username or password is incorrect.",
                });
            }

            return SignIn(CreatePrincipal(result.Account!, request.GetScopes()), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsRefreshTokenGrantType())
        {
            AuthenticateResult refreshed = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (!Guid.TryParse(refreshed.Principal?.GetClaim(Claims.Subject), out Guid accountId))
            {
                return Refuse("The session is no longer valid.");
            }

            // Re-check on every refresh, so a deactivated or locked account loses access within one access-token lifetime.
            Account? account = await guardDb.RunAsync(db => db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken),
                cancellationToken: cancellationToken);
            if (account is null || account.Status != AccountStatus.Active)
            {
                return Refuse("The account is no longer active.");
            }

            return SignIn(CreatePrincipal(account, refreshed.Principal!.GetScopes()), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Refuse("This grant type is not supported.", Errors.UnsupportedGrantType);
    }

    private static ClaimsPrincipal CreatePrincipal(Account account, IEnumerable<string> scopes)
    {
        ClaimsIdentity identity = new(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            Claims.Name,
            Claims.Role);

        identity.SetClaim(Claims.Subject, account.Id.ToString())
            .SetClaim(Claims.Name, account.Username)
            .SetClaim("display_name", account.DisplayName);

        identity.SetScopes(scopes.Intersect([Scopes.OfflineAccess, GuardOidc.ApiScope]));
        identity.SetDestinations(_ => [Destinations.AccessToken]);
        return new ClaimsPrincipal(identity);
    }

    private ForbidResult Refuse(string description, string error = Errors.InvalidGrant) =>
        Forbid(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}

public static class GuardOidc
{
    /// <summary>The scope every Toda API call needs.</summary>
    public const string ApiScope = "toda.api";

    /// <summary>The first-party Next.js server (a confidential client).</summary>
    public const string WebClientId = "toda-web";
}
