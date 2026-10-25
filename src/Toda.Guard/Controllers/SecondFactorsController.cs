using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Toda.Guard.Services.TwoFactor;
using Toda.Platform.Acting;

namespace Toda.Guard.Controllers;

/// <summary>Setting up a second factor at sign-in: the ticket the password gave (ADR 0082).</summary>
public sealed record SecondFactorTicketInput(string? Ticket);

/// <summary>The authenticator app's first code; with the sign-in's ticket when setting up at sign-in.</summary>
public sealed record SecondFactorConfirmInput(string? Code, string? Ticket = null);

/// <summary>New recovery codes, shown this once.</summary>
public sealed record RecoveryCodesDto(List<string> RecoveryCodes);

/// <summary>
/// Setting up a second factor at sign-in (ADR 0082), when a group of the person's requires one and they have none yet:
/// the ticket from the password, then the app's first code. The ticket then passes the second step with no code
/// (<c>POST /api/guard/session/second-factor</c>, or the token endpoint's <c>urn:toda:grant-type:second-factor</c>).
/// </summary>
[Route("api/guard/second-factor/enrol")]
[AllowAnonymous]
public class SecondFactorEnrolmentController(SecondFactors secondFactors) : GuardControllerBase
{
    /// <summary>Starts setting up the authenticator app: its secret, address and QR code.</summary>
    [HttpPost("app")]
    [ProducesResponseType<AppEnrolmentDto>(200)]
    public async Task<IActionResult> StartApp([FromBody] SecondFactorTicketInput input, CancellationToken cancellationToken) =>
        await AccountAsync(input.Ticket, cancellationToken) is { } accountId
            ? Ok(await secondFactors.StartAppAsync(accountId, cancellationToken))
            : TicketRefused();

    /// <summary>Finishes with the app's first code: the recovery codes, shown once, and the ticket passes the second step.</summary>
    [HttpPost("app/confirm")]
    [ProducesResponseType<SecondFactorEnrolledDto>(200)]
    public async Task<IActionResult> ConfirmApp([FromBody] SecondFactorConfirmInput input, CancellationToken cancellationToken)
    {
        if (await AccountAsync(input.Ticket, cancellationToken) is not { } accountId)
        {
            return TicketRefused();
        }

        if (await secondFactors.FinishAppAsync(accountId, input.Code, cancellationToken) is not { } enrolled)
        {
            await secondFactors.SpendTicketTryAsync(input.Ticket!, cancellationToken);
            return SessionController.Error(400, "second_factor_failed", "The code is incorrect. Check the time on your phone, and enter the code it shows now.");
        }

        await secondFactors.ProveTicketAsync(input.Ticket!, cancellationToken);
        return Ok(enrolled);
    }

    private Task<Guid?> AccountAsync(string? ticket, CancellationToken cancellationToken) =>
        ticket is { Length: > 0 } ? secondFactors.TicketAccountAsync(ticket, cancellationToken) : Task.FromResult<Guid?>(null);

    private static ObjectResult TicketRefused() => SessionController.Error(401, "ticket_expired", "This sign-in has expired. Sign in again.");
}

/// <summary>
/// A person's own second factors (ADR 0082): what their groups ask, the factors they have, setting up the authenticator
/// app, removing one (not the last while a group requires one) and new recovery codes. Changing them needs a step-up.
/// </summary>
[Route("api/guard/me/second-factors")]
[Authorize]
public class MySecondFactorsController(SecondFactors secondFactors) : GuardControllerBase
{
    [HttpGet]
    public Task<MySecondFactorsDto> Get(CancellationToken cancellationToken) => secondFactors.ListAsync(CurrentAccountId, cancellationToken);

    /// <summary>Starts setting up the authenticator app: its secret, address and QR code.</summary>
    [HttpPost("app")]
    [StepUp]
    public Task<AppEnrolmentDto> StartApp(CancellationToken cancellationToken) => secondFactors.StartAppAsync(CurrentAccountId, cancellationToken);

    /// <summary>Finishes with the app's first code; the first second factor comes with recovery codes, shown once.</summary>
    [HttpPost("app/confirm")]
    [StepUp]
    [ProducesResponseType<SecondFactorEnrolledDto>(200)]
    public async Task<IActionResult> ConfirmApp([FromBody] SecondFactorConfirmInput input, CancellationToken cancellationToken) =>
        await secondFactors.FinishAppAsync(CurrentAccountId, input.Code, cancellationToken) is { } enrolled
            ? Ok(enrolled)
            : SessionController.Error(400, "second_factor_failed", "The code is incorrect. Check the time on your phone, and enter the code it shows now.");

    [HttpDelete("{id:guid}")]
    [StepUp]
    public async Task<NoContentResult> Remove(Guid id, CancellationToken cancellationToken)
    {
        await secondFactors.RemoveAsync(CurrentAccountId, id, cancellationToken);
        return NoContent();
    }

    /// <summary>Ten new recovery codes in place of the old ones.</summary>
    [HttpPost("recovery-codes")]
    [StepUp]
    public async Task<RecoveryCodesDto> RenewRecoveryCodes(CancellationToken cancellationToken) =>
        new(await secondFactors.RenewRecoveryCodesAsync(CurrentAccountId, cancellationToken));
}
