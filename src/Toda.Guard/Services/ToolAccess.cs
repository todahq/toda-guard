using Toda.Platform.Tools;
using Toda.Sdk;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>
/// Who may see and use a tool (ADR 0025, M7): a read-only caller (a read-only token) reaches only tools that read, and a
/// tool's requirement is checked against the caller's rules, with the request's limits (a token's projects) applied as
/// everywhere. Each record is still checked when the tool runs.
/// </summary>
[ExposeServices(typeof(IToolAccess))]
public class GuardToolAccess(AbilityFactory abilities) : IToolAccess, ITransientDependency
{
    public async Task<bool> AllowsAsync(ToolInfo tool, ToolContext context, CancellationToken cancellationToken)
    {
        if (context.ReadOnly && !tool.Hints.ReadOnly)
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
