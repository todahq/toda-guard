using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Domain;
using Toda.Guard.Services;

namespace Toda.Guard.Controllers;

[Route("api/guard")]
public class AuthController(GuardDb guardDb, MembershipGraph graph) : GuardControllerBase
{
    [HttpGet("me")]
    [Authorize]
    public async Task<object> Me(CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
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
            // CASL raw rules for the browser (casl-net): the UI hides what the server would refuse.
            rules = ability.ToCaslRules(),
        };
    }, cancellationToken: cancellationToken);
    }

    private static object Error(string code, string message) => new { error = new { code, message } };
}
