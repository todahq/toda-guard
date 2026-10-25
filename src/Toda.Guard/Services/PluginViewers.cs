using Casl;
using Toda.Platform.Plugins;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>
/// Who's looking at the plugins' menus (ADR 0078, amended 26 Oct), from the account's ability, built once a request: a
/// customer when they may use some project's portal and neither browse nor manage any (the Customer role's, ADR 0037),
/// as the phone draws it; and every question a plugin's page check asks (<c>Can("triage", "Project")</c>) answered from
/// the same ability.
/// </summary>
[ExposeServices(typeof(IPluginViewers))]
public class PluginViewers(AbilityFactory abilities) : IPluginViewers, ITransientDependency
{
    public async Task<PluginViewer> ForAsync(Guid accountId, bool admin, CancellationToken cancellationToken)
    {
        Ability ability = await abilities.ForAccountAsync(accountId, cancellationToken);
        bool customer = !admin && ability.Can("portal", "Project") && !ability.Can("browse", "Project") && !ability.Can("manage", "Project");
        return new PluginViewer(accountId, admin, customer, (action, subject) => ability.Can(action, subject));
    }
}
