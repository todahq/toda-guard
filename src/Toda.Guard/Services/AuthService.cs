using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Data;
using Toda.Guard.Directories;
using Toda.Guard.Domain;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>
/// Brute-force limit per username and per IP: 5 failures in 15 minutes blocks for 15 minutes (20 per IP). Counted for
/// the whole site (<see cref="IGuardRateLimits"/>), so several servers allow no more than one.
/// </summary>
public class LoginRateLimiter(IGuardRateLimits limits) : ISingletonDependency
{
    private const int MaxFailures = 5;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    public async Task<bool> IsBlockedAsync(string username, string? ip, CancellationToken cancellationToken = default) =>
        await limits.CountAsync($"sign-in|u:{username}", Window, cancellationToken) >= MaxFailures
        || (ip is not null && await limits.CountAsync($"sign-in|ip:{ip}", Window, cancellationToken) >= MaxFailures * 4);

    public async Task RecordFailureAsync(string username, string? ip, CancellationToken cancellationToken = default)
    {
        await limits.AddAsync($"sign-in|u:{username}", cancellationToken);
        if (ip is not null)
        {
            await limits.AddAsync($"sign-in|ip:{ip}", cancellationToken);
        }
    }

    public Task ResetAsync(string username, CancellationToken cancellationToken = default) => limits.ResetAsync($"sign-in|u:{username}", cancellationToken);
}

/// <summary>Credential check only. Tokens are issued by the OpenIddict token endpoint (ADR 0007).</summary>
/// <summary>MergedInto: the username to sign in with instead, when the account was merged (ADR 0044) and the password was right.</summary>
public sealed record LoginResult(bool Succeeded, Account? Account, string? ErrorCode, string? MergedInto = null);

/// <summary>A step-up's outcome: whether the password was right, and whether the session must end (too many failures).</summary>
public sealed record StepUpResult(bool Succeeded, bool EndSession);

public class AuthService(
    GuardDb guardDb,
    ConnectorCatalog connectors,
    LoginRateLimiter limiter) : ITransientDependency
{
    private static readonly PasswordHasher<DirectoryUser> Hasher = new();

    public static string HashPassword(DirectoryUser user, string password) => Hasher.HashPassword(user, password);

    public async Task<LoginResult> LoginAsync(string username, string password, string? ip, CancellationToken cancellationToken = default)
    {
        string normalized = GuardConstants.Normalize(username);
        if (await limiter.IsBlockedAsync(normalized, ip, cancellationToken))
        {
            await AuditAsync("auth.login.blocked", normalized, null, "Too many failed attempts", ip, cancellationToken);
            return new LoginResult(false, null, "too_many_attempts");
        }

        (bool ok, Account? account, string reason) = await guardDb.RunAsync<(bool, Account?, string)>(async db =>
        {
            Account? account = await db.Accounts.FirstOrDefaultAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            if (account is null)
            {
                return (false, null, "user_not_found");
            }

            if (account.MergedIntoId is { } survivorId)
            {
                // Merged (ADR 0044). Only someone who knows its password learns which account it became.
                return (false, account, await MergedAsync(db, account, survivorId, password, cancellationToken));
            }

            if (account.Status != AccountStatus.Active)
            {
                return (false, account, $"account_{account.Status.ToString().ToLowerInvariant()}");
            }

            // A service account acts only through its tokens.
            if (account.IsService)
            {
                return (false, account, "service_account");
            }

            if (await CheckPasswordAsync(db, account, password, cancellationToken) is { } refused)
            {
                return (false, account, refused);
            }

            account.LastLoginAt = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            return (true, account, "ok");
        }, cancellationToken: cancellationToken);

        if (!ok)
        {
            // Account-state failures don't count toward the brute-force limit; wrong passwords do.
            if (reason is "wrong_password" or "user_not_found" or "invalid_credentials")
            {
                await limiter.RecordFailureAsync(normalized, ip, cancellationToken);
            }

            await AuditAsync("auth.login.failed", normalized, account?.Id, reason, ip, cancellationToken);
            return reason.StartsWith("account_merged:", StringComparison.Ordinal)
                ? new LoginResult(false, null, "account_merged", reason["account_merged:".Length..])
                : new LoginResult(false, null, "invalid_credentials");
        }

        await limiter.ResetAsync(normalized, cancellationToken);
        await AuditAsync("auth.login.succeeded", normalized, account!.Id, null, ip, cancellationToken);
        return new LoginResult(true, account, null);
    }

    /// <summary>"account_merged:{survivor}" when the password is the merged account's own; otherwise "account_inactive".</summary>
    private async Task<string> MergedAsync(GuardDbContext db, Account account, Guid survivorId, string password, CancellationToken cancellationToken)
    {
        UserDirectory? directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == account.DirectoryId, cancellationToken);
        DirectoryUser? record = await db.DirectoryUsers.FirstOrDefaultAsync(u => u.DirectoryId == account.DirectoryId && u.NormalizedUsername == account.NormalizedUsername,
            cancellationToken);
        if (directory is not { IsActive: true, AuthenticationEnabled: true } || record is null || !(await AuthenticateAsync(directory, record, password)).Succeeded)
        {
            return "account_inactive";
        }

        string? survivor = await db.Accounts.Where(a => a.Id == survivorId).Select(a => a.Username).FirstOrDefaultAsync(cancellationToken);
        return survivor is null ? "account_inactive" : $"account_merged:{survivor}";
    }

    /// <summary>
    /// Step-up (ADR 0042): the account's own directory checks the password again, as at sign-in (a hash, or a bind for
    /// LDAP). Failures count toward the sign-in limit; once it's reached, the session ends.
    /// </summary>
    public async Task<StepUpResult> StepUpAsync(Guid accountId, string password, string? ip, CancellationToken cancellationToken = default)
    {
        (Account? account, string? refused) = await guardDb.RunAsync(async db =>
        {
            Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken);
            if (account is null || account.Status != AccountStatus.Active)
            {
                return (account, "account_inactive");
            }

            return (account, await limiter.IsBlockedAsync(account.NormalizedUsername, ip, cancellationToken)
                ? "too_many_attempts"
                : await CheckPasswordAsync(db, account, password, cancellationToken));
        }, cancellationToken: cancellationToken);

        string? username = account?.NormalizedUsername;
        if (refused is null)
        {
            await limiter.ResetAsync(username!, cancellationToken);
            await AuditAsync(SecurityAuditTypes.StepUpSucceeded, username, accountId, null, ip, cancellationToken);
            return new StepUpResult(true, false);
        }

        if (username is not null && refused is "wrong_password" or "invalid_credentials")
        {
            await limiter.RecordFailureAsync(username, ip, cancellationToken);
        }

        bool end = refused is "account_inactive" or "directory_inactive" or "directory_signin_disabled"
            || (username is not null && await limiter.IsBlockedAsync(username, ip, cancellationToken));
        await AuditAsync(end ? SecurityAuditTypes.StepUpEndedSession : SecurityAuditTypes.StepUpFailed, username, accountId, refused, ip, cancellationToken);
        return new StepUpResult(false, end);
    }

    /// <summary>
    /// The password checked by the directory that owns the account, and only that one: a same-named user in a
    /// lower-priority directory can never sign in as this account. Null when it's right; otherwise why not.
    /// </summary>
    private async Task<string?> CheckPasswordAsync(GuardDbContext db, Account account, string password, CancellationToken cancellationToken)
    {
        UserDirectory? directory = await db.Directories.AsNoTracking().FirstOrDefaultAsync(d => d.Id == account.DirectoryId, cancellationToken);
        DirectoryUser? record = account.DirectoryUserId is { } id ? await db.DirectoryUsers.FindAsync([id], cancellationToken) : null;
        if (directory is null || record is null || !directory.IsActive)
        {
            return "directory_inactive";
        }

        if (!directory.AuthenticationEnabled)
        {
            return "directory_signin_disabled";
        }

        (bool authenticated, string? error) = await AuthenticateAsync(directory, record, password);
        return authenticated ? null : error ?? "wrong_password";
    }

    public async Task<(bool Succeeded, string? Error)> AuthenticateAsync(UserDirectory directory, DirectoryUser record, string password)
    {
        if (directory.IsInternal)
        {
            bool valid = record.PasswordHash is not null
                && Hasher.VerifyHashedPassword(record, record.PasswordHash, password) != PasswordVerificationResult.Failed;
            return (valid, valid ? null : "wrong_password");
        }

        return await connectors.WithConnectorAsync(directory.Type, async (connector, _) =>
        {
            if (connector is null)
            {
                return (false, "connector_unavailable");
            }

            ConnectorAuthResult result = await connector.AuthenticateAsync(connectors.BuildContext(directory), record.Username, password, CancellationToken.None);
            return (result.Succeeded, result.Succeeded ? null : result.Error ?? "wrong_password");
        });
    }

    public Task AuditAsync(string type, string? username, Guid? accountId, string? detail, string? ip, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            db.SecurityEvents.Add(new SecurityEvent(Guid.NewGuid(), type, username, accountId, detail, ip));
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);
}
