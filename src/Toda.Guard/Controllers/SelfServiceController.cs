using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Toda.Guard.Services;
using Toda.Platform.Acting;
using Toda.Platform;
using Toda.Platform.Controllers;
using Volo.Abp;

namespace Toda.Guard.Controllers;

/// <summary>
/// What people do for themselves without signing in (ADR 0037): sign up where the site allows it, confirm their email,
/// and reset a forgotten password by mail. Limited per address and per email. Each action allows anonymous callers
/// on its own: [AllowAnonymous] on a controller would override any admin policy on its actions.
/// </summary>
[Route("api/guard")]
public class SelfServiceController(SelfService self, SelfServiceLimiter limiter, Toda.Platform.Security.Captchas captchas) : GuardControllerBase
{
    /// <summary>
    /// A CAPTCHA for a sign-up (M10 step 7): a plugin's, or Toda's own proof of work, fresh each time it's asked for, as an
    /// answer counts once. Null when the site has none.
    /// </summary>
    [AllowAnonymous]
    [HttpGet("signup/captcha")]
    public Task<Toda.Sdk.CaptchaChallenge?> Captcha(CancellationToken cancellationToken) => captchas.ChallengeAsync(cancellationToken);

    /// <summary>Whether people may sign up here, and with which email domains (all when empty).</summary>
    [AllowAnonymous]
    [HttpGet("signup")]
    public Task<SignUpInfoDto> Info(CancellationToken cancellationToken) => self.InfoAsync(cancellationToken);

    /// <summary>Creates an account that's active once its email is confirmed, and mails the link.</summary>
    [AllowAnonymous]
    [HttpPost("signup")]
    public async Task<NoContentResult> SignUp([FromBody] SignUpInput input, CancellationToken cancellationToken)
    {
        Limit("signup", input.Email);
        if (!await captchas.VerifyAsync(input.Captcha, HttpContext.Connection.RemoteIpAddress?.ToString(), cancellationToken))
        {
            throw new UserFriendlyException("Answer the question that shows you're a person.");
        }

        await self.SignUpAsync(input, cancellationToken);
        return NoContent();
    }

    /// <summary>Confirms an email from the link in the mail; the account can sign in from then on.</summary>
    [AllowAnonymous]
    [HttpPost("signup/verify")]
    public async Task<object> Verify([FromBody] TokenInput input, CancellationToken cancellationToken)
    {
        Limit("verify", null);
        (string username, List<object> events) = await self.VerifyAsync(input.Token, cancellationToken);
        await PublishAsync(events);
        return new { username };
    }

    /// <summary>Mails a reset link if an account Toda keeps has this email. Always the same answer.</summary>
    [AllowAnonymous]
    [HttpPost("password/forgot")]
    public async Task<NoContentResult> Forgot([FromBody] ForgotPasswordInput input, CancellationToken cancellationToken)
    {
        Limit("forgot", input.Email);
        await self.ForgotAsync(input.Email, cancellationToken);
        return NoContent();
    }

    /// <summary>Sets a new password from a reset link.</summary>
    [AllowAnonymous]
    [HttpPost("password/reset")]
    public async Task<object> Reset([FromBody] ResetPasswordInput input, CancellationToken cancellationToken)
    {
        Limit("reset", null);
        return new { username = await self.ResetAsync(input.Token, input.Password, cancellationToken) };
    }

    private void Limit(string action, string? email)
    {
        if (!limiter.Allow(action, HttpContext.Connection.RemoteIpAddress?.ToString(), email))
        {
            throw new UserFriendlyException("Too many tries. Wait a while and try again.", TodaErrorCodes.TooManyRequests);
        }
    }
}

/// <summary>Sign-up as site admins set it (ADR 0037): on or off, the internal directory accounts go to, and the email domains it takes.</summary>
[Route("api/guard/signup/settings")]
[Authorize(Policy = TodaPolicies.Admin)]
public class SignUpSettingsController(SelfService self) : GuardControllerBase
{
    [HttpGet]
    public Task<SignUpSettingsDto> Get(CancellationToken cancellationToken) => self.SettingsAsync(cancellationToken);

    [HttpPut]
    [StepUp]
    public Task<SignUpSettingsDto> Save([FromBody] SignUpSettingsInput input, CancellationToken cancellationToken) => self.SaveSettingsAsync(input, cancellationToken);
}
