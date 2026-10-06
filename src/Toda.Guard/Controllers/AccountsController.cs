using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Domain;
using Toda.Guard.Services;
using Casl;
using Volo.Abp;
using Volo.Abp.Domain.Entities;

namespace Toda.Guard.Controllers;

/// <summary>
/// Account APIs authorized row by row with CASL .NET: the list is filtered in SQL with AccessibleBy, and each
/// action is checked against the account it targets. Admins see everything through "manage all".
/// </summary>
[Route("api/guard/accounts")]
[Authorize]
public class AccountsController(GuardDb guardDb, MembershipGraph graph, AccountProjector projector) : GuardControllerBase
{
    [HttpGet]
    public async Task<List<AccountDto>> List([FromQuery] string? search, [FromQuery] string? status, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "read", "Account");
        return await guardDb.RunAsync(async db =>
        {
            Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
            IQueryable<Account> query = db.Accounts.AsNoTracking().AccessibleBy(ability, "read"); // filtered in SQL
            if (!string.IsNullOrWhiteSpace(search))
            {
                string s = GuardConstants.Normalize(search);
                query = query.Where(a => a.NormalizedUsername.Contains(s) || a.DisplayName.ToLower().Contains(s) || (a.Email != null && a.Email.ToLower().Contains(s)));
            }

            if (Enum.TryParse(status, ignoreCase: true, out AccountStatus parsed))
            {
                query = query.Where(a => a.Status == parsed);
            }

            return (await query.OrderBy(a => a.Username).Take(500).ToListAsync(cancellationToken))
                .Select(a => AccountDto.From(a, directories.GetValueOrDefault(a.DirectoryId, "?")))
                .ToList();
        }, cancellationToken: cancellationToken);
    }

    [HttpGet("{id:guid}")]
    public async Task<AccountDetailDto> Get(Guid id, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        return await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Account), id);
            Ensure(ability, "read", account);
            Dictionary<Guid, UserDirectory> directories = await db.Directories.ToDictionaryAsync(d => d.Id, cancellationToken);

            List<IdentityDto> identities = (await db.DirectoryUsers.AsNoTracking()
                    .Where(u => u.NormalizedUsername == account.NormalizedUsername)
                    .ToListAsync(cancellationToken))
                .Select(u => new IdentityDto(
                    u.DirectoryId, directories[u.DirectoryId].Name, directories[u.DirectoryId].Order, u.ExternalId, u.Username,
                    u.DisplayName, u.Email, u.IsActive && directories[u.DirectoryId].IsActive, u.Id == account.DirectoryUserId, u.LastSyncedAt))
                .OrderBy(i => i.DirectoryOrder)
                .ToList();

            List<EffectiveGroupDto> groups = (await graph.GetEffectiveGroupsAsync(db, account, cancellationToken))
                .Select(g => new EffectiveGroupDto(g.Group.Id, g.Group.Name, g.Group.DirectoryId, directories[g.Group.DirectoryId].Name, g.Direct, g.Path))
                .ToList();

            return new AccountDetailDto(AccountDto.From(account, directories[account.DirectoryId].Name), identities, groups);
        }, cancellationToken: cancellationToken);
    }

    public sealed record CreateAccountInput(string Username, string DisplayName, string? Email, string Password);

    /// <summary>Creates a user in the internal directory.</summary>
    [HttpPost]
    public async Task<AccountDto> Create([FromBody] CreateAccountInput input, CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "create", "Account");
        if (string.IsNullOrWhiteSpace(input.Username) || !System.Text.RegularExpressions.Regex.IsMatch(input.Username.Trim(), @"^[A-Za-z0-9._@-]{2,64}$"))
        {
            throw new UserFriendlyException("Usernames are 2–64 letters, digits, dots, dashes, underscores or @.");
        }

        if (string.IsNullOrEmpty(input.Password) || input.Password.Length < 10)
        {
            throw new UserFriendlyException("Passwords need at least 10 characters.");
        }

        string normalized = GuardConstants.Normalize(input.Username);
        (AccountDto dto, List<object> events) = await guardDb.RunAsync(async db =>
        {
            if (await db.DirectoryUsers.AnyAsync(u => u.DirectoryId == GuardConstants.InternalDirectoryId && u.NormalizedUsername == normalized, cancellationToken))
            {
                throw new UserFriendlyException($"The internal directory already has a user called '{input.Username}'.");
            }

            DirectoryUser user = new(Guid.NewGuid(), GuardConstants.InternalDirectoryId, $"internal:{normalized}", input.Username)
            {
                DisplayName = string.IsNullOrWhiteSpace(input.DisplayName) ? input.Username : input.DisplayName.Trim(),
                Email = input.Email?.Trim(),
            };
            user.PasswordHash = AuthService.HashPassword(user, input.Password);
            db.DirectoryUsers.Add(user);
            await db.SaveChangesAsync(cancellationToken);

            List<object> events = await projector.RebuildAsync(db, [normalized], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);

            Account account = await db.Accounts.FirstAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            string directoryName = await db.Directories.Where(d => d.Id == account.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken);
            return (AccountDto.From(account, directoryName), events);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        await PublishAsync(events);
        return dto;
    }

    [HttpPost("{id:guid}/lock")]
    public Task<AccountDto> Lock(Guid id, CancellationToken cancellationToken) => SetLockedAsync(id, locked: true, cancellationToken);

    [HttpPost("{id:guid}/unlock")]
    public Task<AccountDto> Unlock(Guid id, CancellationToken cancellationToken) => SetLockedAsync(id, locked: false, cancellationToken);

    private async Task<AccountDto> SetLockedAsync(Guid id, bool locked, CancellationToken cancellationToken)
    {
        if (locked && id == CurrentAccountId)
        {
            throw new UserFriendlyException("You can't lock your own account.");
        }

        Casl.Ability ability = await AbilityAsync(cancellationToken);
        (AccountDto dto, List<object> events) = await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.FirstOrDefaultAsync(a => a.Id == id, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Account), id);
            Ensure(ability, locked ? "lock" : "unlock", account);
            account.LockedLocally = locked;
            await db.SaveChangesAsync(cancellationToken);
            List<object> events = await projector.RebuildAsync(db, [account.NormalizedUsername], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            string directoryName = await db.Directories.Where(d => d.Id == account.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken);
            return (AccountDto.From(account, directoryName), events);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        await PublishAsync(events);
        return dto;
    }
}
