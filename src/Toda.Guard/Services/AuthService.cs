using System.Collections.Concurrent;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Data;
using Toda.Guard.Directories;
using Toda.Guard.Domain;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>Brute-force limit per username and per IP: 5 failures in 15 minutes blocks for 15 minutes.</summary>
public class LoginRateLimiter : ISingletonDependency
{
    private const int MaxFailures = 5;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    private readonly ConcurrentDictionary<string, List<DateTime>> _failures = new();

    public bool IsBlocked(string username, string? ip) => Count($"u:{username}") >= MaxFailures || (ip is not null && Count($"ip:{ip}") >= MaxFailures * 4);

    public void RecordFailure(string username, string? ip)
    {
        Add($"u:{username}");
        if (ip is not null)
        {
            Add($"ip:{ip}");
        }
    }

    public void Reset(string username) => _failures.TryRemove($"u:{username}", out _);

    private int Count(string key)
    {
        if (!_failures.TryGetValue(key, out List<DateTime>? list))
        {
            return 0;
        }

        lock (list)
        {
            list.RemoveAll(t => t < DateTime.UtcNow - Window);
            return list.Count;
        }
    }

    private void Add(string key)
    {
        List<DateTime> list = _failures.GetOrAdd(key, _ => []);
        lock (list)
        {
            list.Add(DateTime.UtcNow);
        }
    }
}

/// <summary>Credential check only. Tokens are issued by the OpenIddict token endpoint (ADR 0007).</summary>
public sealed record LoginResult(bool Succeeded, Account? Account, string? ErrorCode);

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
        if (limiter.IsBlocked(normalized, ip))
        {
            await AuditAsync("auth.login.blocked", normalized, null, "Too many failed attempts", ip, cancellationToken);
            return new LoginResult(false, null, "too_many_attempts");
        }

        (bool ok, Account? account, string reason) = await guardDb.RunAsync(async db =>
        {
            Account? account = await db.Accounts.FirstOrDefaultAsync(a => a.NormalizedUsername == normalized, cancellationToken);
            if (account is null)
            {
                return (false, null, "user_not_found");
            }

            if (account.Status != AccountStatus.Active)
            {
                return (false, account, $"account_{account.Status.ToString().ToLowerInvariant()}");
            }

            UserDirectory? directory = await db.Directories.FirstOrDefaultAsync(d => d.Id == account.DirectoryId, cancellationToken);
            DirectoryUser? record = account.DirectoryUserId is { } id ? await db.DirectoryUsers.FindAsync([id], cancellationToken) : null;
            if (directory is null || record is null || !directory.IsActive)
            {
                return (false, account, "directory_inactive");
            }

            if (!directory.AuthenticationEnabled)
            {
                return (false, account, "directory_signin_disabled");
            }

            // The directory that owns the username is the only one asked. A same-named user in a
            // lower-priority directory can never sign in as this account.
            (bool authenticated, string? error) = await AuthenticateAsync(directory, record, password);
            if (!authenticated)
            {
                return (false, account, error ?? "wrong_password");
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
                limiter.RecordFailure(normalized, ip);
            }

            await AuditAsync("auth.login.failed", normalized, account?.Id, reason, ip, cancellationToken);
            return new LoginResult(false, null, "invalid_credentials");
        }

        limiter.Reset(normalized);
        await AuditAsync("auth.login.succeeded", normalized, account!.Id, null, ip, cancellationToken);
        return new LoginResult(true, account, null);
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
