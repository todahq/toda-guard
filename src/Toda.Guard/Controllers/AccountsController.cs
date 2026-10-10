using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Domain;
using Toda.Guard.Services;
using Toda.Platform.Acting;
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
public class AccountsController(GuardDb guardDb, MembershipGraph graph, AccountProjector projector, AccountMergeService merges, AccountEmailService emails,
    SecurityLog audit)
    : GuardControllerBase
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
        List<AccountMergeDto> merged = await merges.ListAsync(id, 50, cancellationToken);
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

            string? into = account.MergedIntoId is { } survivor ? await db.Accounts.Where(a => a.Id == survivor).Select(a => a.Username).FirstOrDefaultAsync(cancellationToken) : null;
            return new AccountDetailDto(AccountDto.From(account, directories[account.DirectoryId].Name), identities, groups,
                await AccountEmailService.LoadAsync(db, id, cancellationToken), merged, into);
        }, cancellationToken: cancellationToken);
    }

    /// <summary>A user to create in an internal directory: Toda's own, or another such as Customers (ADR 0037).</summary>
    public sealed record CreateAccountInput(string Username, string DisplayName, string? Email, string Password, Guid? DirectoryId = null);

    /// <summary>Creates a user in an internal directory (Toda's own by default).</summary>
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
        Guid directoryId = input.DirectoryId ?? GuardConstants.InternalDirectoryId;
        (AccountDto dto, List<object> events) = await guardDb.RunAsync(async db =>
        {
            UserDirectory directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == directoryId, cancellationToken)
                ?? throw new UserFriendlyException("There's no such directory.");
            if (!directory.IsInternal)
            {
                throw new UserFriendlyException($"{directory.Name} keeps its own users: create them there.");
            }

            if (await db.DirectoryUsers.AnyAsync(u => u.DirectoryId == directoryId && u.NormalizedUsername == normalized, cancellationToken))
            {
                throw new UserFriendlyException($"{directory.Name} already has a user called '{input.Username}'.");
            }

            DirectoryUser user = new(Guid.NewGuid(), directoryId, $"internal:{normalized}", input.Username)
            {
                DisplayName = string.IsNullOrWhiteSpace(input.DisplayName) ? input.Username : input.DisplayName.Trim(),
                Email = input.Email?.Trim(),
            };
            user.PasswordHash = AuthService.HashPassword(user, input.Password);
            db.DirectoryUsers.Add(user);
            await db.SaveChangesAsync(cancellationToken);

            List<object> events = await projector.RebuildAsync(db, [normalized], cancellationToken);
            await db.SaveChangesAsync(cancellationToken);

            await Organizations.ApplyDomainsAsync(db, cancellationToken);
            Account account = await db.Accounts.FirstAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            string directoryName = await db.Directories.Where(d => d.Id == account.DirectoryId).Select(d => d.Name).FirstAsync(cancellationToken);
            audit.Add(db, SecurityAuditTypes.AccountCreated, Target(account), new { directory = directoryName });
            await db.SaveChangesAsync(cancellationToken);
            return (AccountDto.From(account, directoryName), events);
        }, requiresNew: true, cancellationToken, isTransactional: true);

        await PublishAsync(events);
        await merges.FoldPlaceholdersAsync(MergeReasons.AccountCreated, cancellationToken); // a placeholder with this address joins them (ADR 0044)
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
            if (account.LockedLocally != locked)
            {
                audit.Add(db, locked ? SecurityAuditTypes.AccountLocked : SecurityAuditTypes.AccountUnlocked, Target(account));
            }

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

    // ---- Addresses (ADR 0044): an admin's are verified at once ----

    [HttpGet("{id:guid}/emails")]
    public async Task<AccountEmailsDto> Emails(Guid id, CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "read", await AccountAsync(id, cancellationToken));
        return await emails.ListAsync(id, cancellationToken);
    }

    /// <summary>Adds an address, verified; a placeholder with it is merged into this account.</summary>
    [HttpPost("{id:guid}/emails")]
    public async Task<AccountEmailsDto> AddEmail(Guid id, [FromBody] AddEmailInput input, CancellationToken cancellationToken)
    {
        Account account = await AccountAsync(id, cancellationToken);
        Ensure(await AbilityAsync(cancellationToken), "update", account);
        AccountEmailsDto result = await emails.AddVerifiedAsync(id, input.Email, CurrentAccountId, cancellationToken);
        // A verified address receives password resets and matches mail and sign-ups (ADR 0044).
        await audit.WriteAsync(SecurityAuditTypes.AddressAdded, Target(account), new { email = input.Email.Trim() }, cancellationToken);
        return result;
    }

    [HttpDelete("{id:guid}/emails/{emailId:guid}")]
    public async Task<AccountEmailsDto> RemoveEmail(Guid id, Guid emailId, CancellationToken cancellationToken)
    {
        Account account = await AccountAsync(id, cancellationToken);
        Ensure(await AbilityAsync(cancellationToken), "update", account);
        string? email = (await emails.ListAsync(id, cancellationToken)).Addresses.FirstOrDefault(a => a.Id == emailId)?.Email;
        AccountEmailsDto result = await emails.RemoveAsync(id, emailId, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.AddressRemoved, Target(account), new { email }, cancellationToken);
        return result;
    }

    /// <summary>Where mail goes: one of the account's verified addresses, or null for its directory's.</summary>
    [HttpPut("{id:guid}/mail-to")]
    public async Task<AccountEmailsDto> MailTo(Guid id, [FromBody] MailToInput input, CancellationToken cancellationToken)
    {
        Account account = await AccountAsync(id, cancellationToken);
        Ensure(await AbilityAsync(cancellationToken), "update", account);
        AccountEmailsDto result = await emails.SetMailToAsync(id, input.Email, cancellationToken);
        await audit.WriteAsync(SecurityAuditTypes.MailToChanged, Target(account), new { email = result.MailTo }, cancellationToken);
        return result;
    }

    // ---- Merging (ADR 0044) ----

    /// <summary>Addresses more than one account has: candidates to merge.</summary>
    [HttpGet("duplicates")]
    public async Task<List<DuplicateDto>> Duplicates(CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "merge", "Account");
        return await merges.DuplicatesAsync(cancellationToken);
    }

    /// <summary>What merging this account into another would move, without moving anything.</summary>
    [HttpPost("{id:guid}/merge/preview")]
    public async Task<MergePreviewDto> PreviewMerge(Guid id, [FromBody] MergeInput input, CancellationToken cancellationToken)
    {
        await EnsureMergeAsync(id, input.SurvivorId, cancellationToken);
        return await merges.PreviewAsync(id, input.SurvivorId, CurrentAccountId, cancellationToken);
    }

    /// <summary>
    /// Merges this account into another: everything it did, owns or is named in moves there, and it stays inactive. An
    /// account that can sign in needs Confirm to be its username.
    /// </summary>
    [HttpPost("{id:guid}/merge")]
    public async Task<AccountMergeDto> Merge(Guid id, [FromBody] MergeInput input, CancellationToken cancellationToken)
    {
        await EnsureMergeAsync(id, input.SurvivorId, cancellationToken);
        return await merges.MergeAsync(id, input.SurvivorId, CurrentAccountId, MergeReasons.Admin, input.Confirm, cancellationToken);
    }

    private async Task EnsureMergeAsync(Guid sourceId, Guid survivorId, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Ensure(ability, "merge", await AccountAsync(sourceId, cancellationToken));
        Ensure(ability, "merge", await AccountAsync(survivorId, cancellationToken));
    }

    private static AuditTarget Target(Account account) => new("Account", account.Id, account.Username);

    private Task<Account> AccountAsync(Guid id, CancellationToken cancellationToken) => guardDb.RunAsync(async db =>
        await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, cancellationToken) ?? throw new EntityNotFoundException(typeof(Account), id),
        cancellationToken: cancellationToken);
}

/// <summary>Merges as recorded (ADR 0044): every one, or an account's; and resuming one a plugin didn't finish.</summary>
[Route("api/guard/merges")]
[Authorize]
public class MergesController(AccountMergeService merges) : GuardControllerBase
{
    [HttpGet]
    public async Task<List<AccountMergeDto>> List([FromQuery] Guid? accountId, [FromQuery] int take = 100, CancellationToken cancellationToken = default)
    {
        Ensure(await AbilityAsync(cancellationToken), "merge", "Account");
        return await merges.ListAsync(accountId, take, cancellationToken);
    }

    [HttpGet("{id:guid}")]
    public async Task<AccountMergeDto> Get(Guid id, CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "merge", "Account");
        return await merges.GetAsync(id, cancellationToken);
    }

    /// <summary>Asks the plugins that haven't finished the merge (they failed, or were off) to move their rows now.</summary>
    [HttpPost("{id:guid}/resume")]
    public async Task<AccountMergeDto> Resume(Guid id, CancellationToken cancellationToken)
    {
        Ensure(await AbilityAsync(cancellationToken), "merge", "Account");
        return await merges.ResumeAsync(id, cancellationToken);
    }
}

/// <summary>
/// A person's own addresses (ADR 0044): added with a link mailed to the address, removed, and the one mail goes to.
/// Confirming takes only the link, signed in or not.
/// </summary>
[Route("api/guard")]
public class MyEmailsController(AccountEmailService emails, SelfServiceLimiter limiter) : GuardControllerBase
{
    [HttpGet("me/emails")]
    [Authorize]
    public Task<AccountEmailsDto> List(CancellationToken cancellationToken) => emails.ListAsync(CurrentAccountId, cancellationToken);

    /// <summary>Adds an address and mails a link to it; it counts once the link is followed.</summary>
    [HttpPost("me/emails")]
    [Authorize]
    public Task<AccountEmailsDto> Add([FromBody] AddEmailInput input, CancellationToken cancellationToken)
    {
        Limit("email-add", input.Email);
        return emails.AddForSelfAsync(CurrentAccountId, input.Email, cancellationToken);
    }

    [HttpDelete("me/emails/{emailId:guid}")]
    [Authorize]
    public Task<AccountEmailsDto> Remove(Guid emailId, CancellationToken cancellationToken) => emails.RemoveAsync(CurrentAccountId, emailId, cancellationToken);

    [HttpPut("me/mail-to")]
    [Authorize]
    public Task<AccountEmailsDto> MailTo([FromBody] MailToInput input, CancellationToken cancellationToken) =>
        emails.SetMailToAsync(CurrentAccountId, input.Email, cancellationToken);

    /// <summary>Confirms an address from the link mailed to it.</summary>
    [AllowAnonymous]
    [HttpPost("emails/verify")]
    public async Task<object> Verify([FromBody] TokenInput input, CancellationToken cancellationToken)
    {
        Limit("email-verify", null);
        (string email, string username) = await emails.VerifyAsync(input.Token, cancellationToken);
        return new { email, username };
    }

    private void Limit(string action, string? email)
    {
        if (!limiter.Allow(action, HttpContext.Connection.RemoteIpAddress?.ToString(), email))
        {
            throw new UserFriendlyException("Too many tries. Wait a while and try again.", Toda.Platform.TodaErrorCodes.TooManyRequests);
        }
    }
}
