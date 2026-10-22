using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Toda.Guard.Domain;
using Toda.Guard.Services;
using OpenIddict.Abstractions;

namespace Toda.Guard.Controllers;

public sealed record SessionStartInput(string? Username, string? Password);

public sealed record SessionStepUpInput(string? Password);

/// <summary>A browser just signed in: its account and preferences, when the session ends unless it's used, and when the person proved who they are.</summary>
public sealed record SessionDto(AccountDto Account, PreferencesDto Preferences, DateTime ExpiresAt, DateTime AuthTime);

/// <summary>When a step-up passed: the session's new proof of who the person is.</summary>
public sealed record SessionStepUpDto(DateTime AuthTime);

/// <summary>
/// The web's sign-in, sign-out and step-up (ADR 0075). Signing in checks the password with the account's directory, as
/// the token endpoint does, and answers with the session's cookies: <c>toda_session</c> (only the server reads it) and
/// <c>toda_csrf</c>, which the page sends back as the X-Toda-Csrf header on every request that changes something. Phones
/// and tools keep bearer tokens from the token endpoint.
/// </summary>
[Route("api/guard/session")]
public class SessionController(AuthService auth, WebSessions sessions, GuardDb guardDb, Toda.Platform.SiteCalendar calendar, IConfiguration configuration)
    : GuardControllerBase
{
    /// <summary>Signs in with a username and password; a session this browser had before ends.</summary>
    [HttpPost]
    [AllowAnonymous]
    [ProducesResponseType<SessionDto>(200)]
    public async Task<IActionResult> Start([FromBody] SessionStartInput input, CancellationToken cancellationToken)
    {
        if (WebSessionHandler.IsCrossSite(Request, configuration["Toda:PublicUrl"]))
        {
            return Error(403, "cross_site_request", "This request came from another site and was refused.");
        }

        if (input.Username is not { Length: > 0 } username || input.Password is not { } password)
        {
            return Error(400, "invalid_request", "Expected a JSON body with username and password.");
        }

        LoginResult result = await auth.LoginAsync(username, password, ClientIp, cancellationToken);
        if (!result.Succeeded)
        {
            return result.ErrorCode switch
            {
                "too_many_attempts" => Error(429, "too_many_attempts", "Too many failed attempts. Try again in 15 minutes."),
                "account_merged" => Error(401, "account_merged", $"This account was merged into {result.MergedInto}. Sign in as {result.MergedInto}."),
                _ => Error(401, "invalid_credentials", "The username or password is incorrect."),
            };
        }

        if (Request.Cookies[WebSessionHandler.CookieName] is { Length: > 0 } before && await sessions.FindAsync(before, cancellationToken) is { } previous)
        {
            await sessions.EndAsync(previous.Info.Id, "signed-out", cancellationToken);
        }

        (WebSession session, string secret) = await sessions.StartAsync(result.Account!.Id, Request.Headers.UserAgent.ToString(), ClientIp, cancellationToken);
        WebSessionHandler.Issue(HttpContext, secret);
        return Ok(await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstAsync(a => a.Id == session.AccountId, cancellationToken);
            string directory = await db.Directories.Where(d => d.Id == account.DirectoryId).Select(d => d.Name).FirstOrDefaultAsync(cancellationToken) ?? "?";
            return new SessionDto(AccountDto.From(account, directory), PreferencesDto.For(account, calendar), session.ExpiresAt, session.AuthTime);
        }, cancellationToken: cancellationToken));
    }

    /// <summary>Signs out: the session ends and the browser forgets its cookies.</summary>
    [HttpDelete]
    [AllowAnonymous]
    public async Task<NoContentResult> End(CancellationToken cancellationToken)
    {
        if (Guid.TryParse(User.FindFirst(WebSessionHandler.SessionIdClaim)?.Value, out Guid sessionId))
        {
            await sessions.EndAsync(sessionId, "signed-out", cancellationToken);
        }

        WebSessionHandler.Clear(HttpContext);
        return NoContent();
    }

    /// <summary>
    /// A step-up (ADR 0042): the password again, checked by the account's directory, marks the session for the site's
    /// step-up minutes. A wrong password answers 400 and the session goes on; too many end it (401, cookies cleared).
    /// </summary>
    [HttpPost("step-up")]
    [Authorize]
    [ProducesResponseType<SessionStepUpDto>(200)]
    public async Task<IActionResult> StepUp([FromBody] SessionStepUpInput input, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(User.FindFirst(WebSessionHandler.SessionIdClaim)?.Value, out Guid sessionId))
        {
            return Error(400, "not_a_session", "Only a browser's session steps up here.");
        }

        if (input.Password is not { Length: > 0 } password)
        {
            return Error(400, "invalid_request", "Enter your password.");
        }

        StepUpResult result = await auth.StepUpAsync(CurrentAccountId, password, ClientIp, cancellationToken);
        if (!result.Succeeded && result.EndSession)
        {
            await sessions.EndAsync(sessionId, "step-up", cancellationToken);
            WebSessionHandler.Clear(HttpContext);
            return Error(401, "session_ended", "Too many wrong passwords: the session has ended. Sign in again.");
        }

        if (!result.Succeeded)
        {
            return Error(400, "step_up_failed", "The password is incorrect.");
        }

        return await sessions.MarkSteppedUpAsync(sessionId, cancellationToken) is { } authTime
            ? Ok(new SessionStepUpDto(authTime))
            : Error(401, "session_ended", "Your session has ended. Sign in again.");
    }

    private static ObjectResult Error(int status, string code, string message) => new(new { error = new { code, message } }) { StatusCode = status };
}

/// <summary>
/// Where the person is signed in (ADR 0075): browsers, the phone app, scripts. Each can be ended, or all but this one
/// ("sign out everywhere else"). Ending this browser's session here is signing out.
/// </summary>
[Route("api/guard/me/sessions")]
[Authorize]
public class MySessionsController(AccountSessions sessions) : GuardControllerBase
{
    [HttpGet]
    public Task<List<AccountSessionDto>> List(CancellationToken cancellationToken) =>
        sessions.ListAsync(CurrentAccountId, CurrentSession, User.GetAuthorizationId(), cancellationToken);

    [HttpDelete("{kind}/{id}")]
    public async Task<NoContentResult> End(string kind, string id, CancellationToken cancellationToken)
    {
        await sessions.EndAsync(CurrentAccountId, kind, id, cancellationToken);
        if (kind == SessionKinds.Browser && CurrentSession?.ToString() == id)
        {
            WebSessionHandler.Clear(HttpContext);
        }

        return NoContent();
    }

    /// <summary>Signs out everywhere else: every other browser, the phone app and scripts; this one goes on.</summary>
    [HttpPost("everywhere")]
    public Task<SessionsEndedDto> EndEverywhere(CancellationToken cancellationToken) =>
        sessions.EndEverywhereAsync(CurrentAccountId, CurrentSession, User.GetAuthorizationId(), "everywhere", cancellationToken);

    private Guid? CurrentSession => Guid.TryParse(User.FindFirst(WebSessionHandler.SessionIdClaim)?.Value, out Guid id) ? id : null;
}
