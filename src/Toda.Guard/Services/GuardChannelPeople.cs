using Toda.Platform.Mail;
using Toda.Sdk;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>People for channels (ADR 0039): active accounts with their email and preferences, and the members of groups.</summary>
[ExposeServices(typeof(IChannelPeople))]
public class GuardChannelPeople(IAccountLookup accounts, IMembershipResolver memberships) : IChannelPeople, ITransientDependency
{
    public async Task<IReadOnlyList<ChannelPerson>> PeopleAsync(IEnumerable<Guid> accountIds, CancellationToken cancellationToken = default)
    {
        IReadOnlyDictionary<Guid, AccountInfo> found = await accounts.GetManyAsync(accountIds.Distinct(), cancellationToken);
        return found.Values.Where(a => a.IsActive).OrderBy(a => a.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .Select(a => new ChannelPerson(a.Id, a.DisplayName, a.Email, a.Language, a.TimeZone)).ToList();
    }

    public async Task<IReadOnlyList<Guid>> GroupMembersAsync(Guid groupId, CancellationToken cancellationToken = default) =>
        await memberships.GetEffectiveMemberIdsAsync(groupId.ToString(), cancellationToken) ?? [];
}
