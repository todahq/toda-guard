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
/// Tokens say when the person last proved who they are (<c>auth_time</c>, <c>amr</c>), and a refresh keeps it. A
/// refresh that carries <c>step_up_password</c> is a step-up (ADR 0042): the account's own directory checks the password
/// and the new tokens start a new window; only Toda's own web server may ask, and too many failures end the session.
/// </summary>
[ApiExplorerSettings(IgnoreApi = true)]
[UnitOfWork(IsDisabled = true)]
public class TokenController(AuthService auth, GuardDb guardDb, IOpenIddictTokenManager tokens) : AbpControllerBase
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

            return SignIn(CreatePrincipal(result.Account!, request.GetScopes(), DateTimeOffset.UtcNow), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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

            // When the person last proved who they are travels with the session; a step-up moves it on.
            DateTimeOffset? authTime = long.TryParse(refreshed.Principal!.GetClaim(Claims.AuthenticationTime), out long seconds)
                ? DateTimeOffset.FromUnixTimeSeconds(seconds)
                : null;
            if (request.GetParameter(StepUpParameter)?.ToString() is { } password)
            {
                if (request.ClientId != GuardOidc.WebClientId)
                {
                    return Refuse("Only Toda's own web app can ask for a step-up.", Errors.UnauthorizedClient);
                }

                StepUpResult stepUp = await auth.StepUpAsync(account.Id, password, HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken);
                if (!stepUp.Succeeded)
                {
                    if (stepUp.EndSession && refreshed.Principal.GetTokenId() is { } tokenId && await tokens.FindByIdAsync(tokenId, cancellationToken) is { } token)
                    {
                        await tokens.TryRevokeAsync(token, cancellationToken);
                    }

                    return Refuse(stepUp.EndSession ? "Too many wrong passwords: the session has ended. Sign in again." : "The password is incorrect.",
                        stepUp.EndSession ? SessionEndedError : StepUpFailedError);
                }

                authTime = DateTimeOffset.UtcNow;
            }

            return SignIn(CreatePrincipal(account, refreshed.Principal.GetScopes(), authTime), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Refuse("This grant type is not supported.", Errors.UnsupportedGrantType);
    }

    /// <summary>The token parameter that makes a refresh a step-up, with the password.</summary>
    public const string StepUpParameter = "step_up_password";

    /// <summary>The step-up's password was wrong; the session goes on.</summary>
    public const string StepUpFailedError = "step_up_failed";

    /// <summary>Too many wrong step-up passwords: the refresh token is revoked.</summary>
    public const string SessionEndedError = "session_ended";

    private static ClaimsPrincipal CreatePrincipal(Account account, IEnumerable<string> scopes, DateTimeOffset? authTime)
    {
        ClaimsIdentity identity = new(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            Claims.Name,
            Claims.Role);

        identity.SetClaim(Claims.Subject, account.Id.ToString())
            .SetClaim(Claims.Name, account.Username)
            .SetClaim("display_name", account.DisplayName);
        if (authTime is { } proved)
        {
            // Every sign-in so far is a password checked by the account's directory (OpenID Connect's "pwd").
            identity.SetClaim(Claims.AuthenticationTime, proved.ToUnixTimeSeconds())
                .SetClaims(Claims.AuthenticationMethodReference, ["pwd"]);
        }

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
