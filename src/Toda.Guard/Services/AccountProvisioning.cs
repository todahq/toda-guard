using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Domain;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>
/// People from imports (ADR 0012): match by username, then by email; otherwise a deactivated placeholder in an
/// "Imported from {source}" directory, with sign-in off, ranked after every other directory.
/// </summary>
[ExposeServices(typeof(IAccountProvisioning))]
public class AccountProvisioning(GuardDb guardDb, AccountProjector projector) : IAccountProvisioning, ITransientDependency
{
    public const string ImportedType = "imported";

    public Task<ProvisionedAccount> MatchOrCreatePlaceholderAsync(string source, string username, string? displayName, string? email, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(source) || string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("A source and a username are needed.");
        }

        string normalized = GuardConstants.Normalize(username);
        return guardDb.RunAsync(async db =>
        {
            Account? byName = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            if (byName is not null)
            {
                return new ProvisionedAccount(byName.Id, "username");
            }

            if (!string.IsNullOrWhiteSpace(email))
            {
                string lower = email.Trim().ToLowerInvariant();
                List<Guid> byEmail = await db.Accounts.AsNoTracking().Where(a => a.Email != null && a.Email.ToLower() == lower).Select(a => a.Id).Take(2).ToListAsync(cancellationToken);
                if (byEmail.Count == 1)
                {
                    return new ProvisionedAccount(byEmail[0], "email");
                }
            }

            Guid directoryId = DirectoryIdFor(source);
            if (!await db.Directories.AnyAsync(d => d.Id == directoryId, cancellationToken))
            {
                int last = await db.Directories.MaxAsync(d => (int?)d.Order, cancellationToken) ?? 0;
                db.Directories.Add(new UserDirectory(directoryId, $"Imported from {source}", ImportedType, last + 1) { AuthenticationEnabled = false });
            }

            db.DirectoryUsers.Add(new DirectoryUser(Guid.NewGuid(), directoryId, $"{ImportedType}:{normalized}", username)
            {
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName.Trim(),
                Email = email?.Trim(),
                IsActive = false, // deactivated until an admin acts, or a ranking directory takes the username over
            });
            await db.SaveChangesAsync(cancellationToken);
            await projector.RebuildAsync(db, [normalized], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            Account created = await db.Accounts.AsNoTracking().FirstAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            return new ProvisionedAccount(created.Id, "placeholder");
        }, requiresNew: true, cancellationToken, isTransactional: true);
    }

    /// <summary>One directory per source, with an id derived from its name, so reruns and other importers share it.</summary>
    public static Guid DirectoryIdFor(string source) =>
        new(SHA256.HashData(Encoding.UTF8.GetBytes("toda-imported-directory:" + source.Trim().ToLowerInvariant()))[..16]);
}
