using Toda.Platform;
using Toda.Query;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>
/// The clock a person's queries run on (ADR 0013): now, in their time zone, else the site's, with the site's first day of
/// the week. The system (an empty id) and Anonymous visitors run on the site's.
/// </summary>
public class QueryClocks(IAccountLookup accounts, SiteCalendar calendar) : ITransientDependency
{
    public async Task<QueryClock> ForAsync(Guid accountId, CancellationToken cancellationToken = default) =>
        calendar.Clock(accountId == Guid.Empty ? null : (await accounts.GetAsync(accountId, cancellationToken))?.TimeZone);
}
