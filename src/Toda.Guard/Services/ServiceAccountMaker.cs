using Microsoft.EntityFrameworkCore;
using Toda.Guard.Acting;
using Toda.Guard.Controllers;
using Toda.Guard.Domain;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>
/// Makes service accounts, for the admin page and for the host (<see cref="IServiceAccounts"/>): an internal directory
/// user with no password and no address, projected into an account marked as a service account, or an agent's.
/// </summary>
[ExposeServices(typeof(IServiceAccounts), typeof(ServiceAccountMaker))]
public class ServiceAccountMaker(GuardDb guardDb, AccountProjector projector, SecurityLog audit, IGuardEventSink events) : IServiceAccounts, ITransientDependency
{
    public async Task<AccountInfo> CreateAsync(ServiceAccountInput input, CancellationToken cancellationToken = default) =>
        AccountLookup.ToInfo((await MakeAsync(input, cancellationToken)).Account);

    /// <summary>Makes the account and publishes what changed; returns it with its directory's name.</summary>
    internal async Task<(Account Account, string Directory)> MakeAsync(ServiceAccountInput input, CancellationToken cancellationToken)
    {
        string username = (input.Username ?? "").Trim();
        if (!Usernames.Pattern().IsMatch(username))
        {
            throw new UserFriendlyException(Usernames.Rule);
        }

        string normalized = GuardConstants.Normalize(username);
        (Account account, string directory, List<object> raised) = await guardDb.RunAsync(async db =>
        {
            if (await db.DirectoryUsers.AnyAsync(u => u.DirectoryId == GuardConstants.InternalDirectoryId && u.NormalizedUsername == normalized, cancellationToken)
                || await db.Accounts.AnyAsync(a => a.NormalizedUsername == normalized, cancellationToken))
            {
                throw new UserFriendlyException($"There's already an account called '{username}'.");
            }

            // No password and no address: it can't sign in, and no reset or mail reaches it.
            db.DirectoryUsers.Add(new DirectoryUser(Guid.NewGuid(), GuardConstants.InternalDirectoryId, $"internal:{normalized}", username)
            {
                DisplayName = string.IsNullOrWhiteSpace(input.DisplayName) ? username : input.DisplayName.Trim(),
            });
            await db.SaveChangesAsync(cancellationToken);
            List<object> raised = await projector.RebuildAsync(db, [normalized], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            Account account = await db.Accounts.FirstAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            account.MakeService(input.Agent);
            string directory = await db.Directories.Where(d => d.Id == account.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken);
            audit.Add(db, SecurityAuditTypes.AccountCreated, new AuditTarget("Account", account.Id, account.Username),
                input.Agent ? new { directory, service = true, agent = true } : new { directory, service = true });
            await db.SaveChangesAsync(cancellationToken);
            return (account, directory, raised);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        foreach (object e in raised)
        {
            await GuardEvents.PublishAsync(events, e, cancellationToken);
        }

        return (account, directory);
    }
}
