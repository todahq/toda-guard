using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Domain;
using Toda.Guard.Services;

namespace Toda.Guard.Controllers;

[Route("api/guard")]
public class AuthController(AuthService auth, GuardDb guardDb, MembershipGraph graph) : GuardControllerBase
{
    public sealed record LoginInput(string Username, string Password);

    [HttpPost("auth/login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginInput input, CancellationToken cancellationToken)
    {
        LoginResult result = await auth.LoginAsync(input.Username ?? string.Empty, input.Password ?? string.Empty, ClientIp, cancellationToken);
        if (!result.Succeeded)
        {
            return result.ErrorCode == "too_many_attempts"
                ? StatusCode(StatusCodes.Status429TooManyRequests, Error("too_many_attempts", "Too many failed attempts. Try again in 15 minutes."))
                : Unauthorized(Error("invalid_credentials", "The username or password is incorrect."));
        }

        string directoryName = await guardDb.RunAsync(db => db.Directories.Where(d => d.Id == result.Account!.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken),
            cancellationToken: cancellationToken);
        return Ok(new { accessToken = result.Token, expiresAt = result.ExpiresAt, account = AccountDto.From(result.Account!, directoryName) });
    }

    [HttpGet("me")]
    [Authorize]
    public async Task<object> Me(CancellationToken cancellationToken)
    {
        Toda.Authz.Ability ability = await AbilityAsync(cancellationToken);
        return await guardDb.RunAsync<object>(async db =>
    {
        Account account = await db.Accounts.FirstAsync(a => a.Id == CurrentAccountId, cancellationToken);
        Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
        List<EffectiveGroup> groups = await graph.GetEffectiveGroupsAsync(db, account, cancellationToken);
        return new
        {
            account = AccountDto.From(account, directories.GetValueOrDefault(account.DirectoryId, "?")),
            groups = groups.Select(g => new EffectiveGroupDto(g.Group.Id, g.Group.Name, g.Group.DirectoryId, directories.GetValueOrDefault(g.Group.DirectoryId, "?"), g.Direct, g.Path)),
            isAdmin = ability.Can("manage", "all"),
            // CASL raw rules for the browser (@toda/authz-casl): the UI hides what the server would refuse.
            rules = ability.ToCaslRules(),
        };
    }, cancellationToken: cancellationToken);
    }

    private static object Error(string code, string message) => new { error = new { code, message } };
}
