using Toda.Platform.Acting;
using Toda.Platform.Tools;
using Toda.Sdk;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>
/// Who may see and use a tool (ADR 0025, M7): a read-only caller (a read-only token) reaches only tools that read, and a
/// tool's requirement is checked against the caller's rules, with the request's limits (a token's projects) applied as
/// everywhere; a token limited to some tools reaches only those. Each record is still checked when the tool runs.
/// </summary>
[ExposeServices(typeof(IToolAccess))]
public class GuardToolAccess(AbilityFactory abilities, ActingContext? acting = null) : IToolAccess, ITransientDependency
{
    public async Task<bool> AllowsAsync(ToolInfo tool, ToolContext context, CancellationToken cancellationToken)
    {
        if (context.ReadOnly && !tool.Hints.ReadOnly)
        {
            return false;
        }

        // The token's own list, when the call is the request's (an agent's): a skill's calls carry no token.
        if (acting?.TokenTools is { } allowed && acting.SubjectId == context.AccountId && !allowed.Contains(tool.Name, StringComparer.Ordinal))
        {
            return false;
        }

        if (tool.Requires is not { } requires)
        {
            return true;
        }

        Casl.Ability ability = await abilities.ForAccountAsync(context.AccountId, cancellationToken);
        return ability.Can(requires.Action, requires.Subject);
    }
}
