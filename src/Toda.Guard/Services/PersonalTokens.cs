using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Casl;
using Toda.Guard.Domain;
using Toda.Platform.Acting;
using Volo.Abp;
using Volo.Abp.DependencyInjection;
using Volo.Abp.Domain.Entities;

namespace Toda.Guard.Services;

/// <summary>A personal access token as lists show it: never its secret.</summary>
public sealed record PersonalTokenDto(
    Guid Id, Guid AccountId, string Username, string Name, string Prefix, string Access, List<TokenProjectDto>? Projects,
    DateTime ExpiresAt, DateTime CreatedAt, DateTime? LastUsedAt, string? LastUsedIp, DateTime? RevokedAt, bool Active);

public sealed record TokenProjectDto(Guid Id, string Label, string? Href);

/// <summary>A token just made: the only time its secret is shown.</summary>
public sealed record NewPersonalTokenDto(PersonalTokenDto Token, string Secret);

/// <summary>A token to make: a name, read or write, the projects it's limited to (none for all), and how many days it lives.</summary>
public sealed record CreatePersonalTokenInput(string Name, string Access, List<Guid>? ProjectIds, int Days);

/// <summary>
/// Personal access tokens (M7): made, listed, revoked, and found by their secret. A token is <c>toda_pat_</c> and 43
/// random characters; only its SHA-256 is kept.
/// </summary>
public class PersonalTokens(GuardDb guardDb, SecurityLog audit, IEnumerable<IGrantScopeDescriber> describers) : ITransientDependency
{
    public const string SecretPrefix = "toda_pat_";

    public static string Hash(string secret) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret))).ToLowerInvariant();

    public async Task<NewPersonalTokenDto> CreateAsync(Guid accountId, CreatePersonalTokenInput input, Guid createdBy, CancellationToken cancellationToken = default)
    {
        string name = (input.Name ?? "").Trim();
        if (name.Length is < 1 or > 100)
        {
            throw new UserFriendlyException("Name the token: 1–100 characters, so you know later what uses it.");
        }

        if (input.Access is not (TokenAccess.Read or TokenAccess.Write))
        {
            throw new UserFriendlyException("A token reads, or reads and writes: access is read or write.");
        }

        List<Guid>? projects = input.ProjectIds is { Count: > 0 } ids ? ids.Distinct().ToList() : null;
        if (projects is not null)
        {
            Dictionary<string, GrantScopeLabel> known = await DescribeAsync(projects, cancellationToken);
            List<Guid> missing = projects.Where(p => !known.ContainsKey(ScopeKey(p))).ToList();
            if (missing.Count > 0)
            {
                throw new UserFriendlyException($"There's no project with id {missing[0]}.");
            }
        }

        byte[] random = RandomNumberGenerator.GetBytes(32);
        string secret = SecretPrefix + Base64UrlEncoder(random);
        (PersonalAccessToken token, Account account) = await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == accountId, cancellationToken)
                ?? throw new EntityNotFoundException(typeof(Account), accountId);
            if (account.Status != AccountStatus.Active)
            {
                throw new UserFriendlyException($"{account.Username} isn't active, so it can't have tokens.");
            }

            int maxDays = (await db.SecuritySettings.AsNoTracking().Where(s => s.Id == SecuritySettings.SingletonId).Select(s => (int?)s.TokenMaxDays)
                .FirstOrDefaultAsync(cancellationToken)) ?? SecuritySettings.DefaultTokenMaxDays;
            if (input.Days < 1 || input.Days > maxDays)
            {
                throw new UserFriendlyException($"Tokens on this site live 1 to {maxDays} days.");
            }

            PersonalAccessToken token = new(Guid.NewGuid(), accountId, name, secret[..(SecretPrefix.Length + 4)], Hash(secret), input.Access, projects,
                DateTime.UtcNow.AddDays(input.Days), createdBy);
            db.PersonalAccessTokens.Add(token);
            audit.Add(db, SecurityAuditTypes.TokenCreated, new AuditTarget("Account", account.Id, account.Username),
                new { token = token.Id, name, prefix = token.Prefix, access = token.Access, projects, expiresAt = token.ExpiresAt });
            await db.SaveChangesAsync(cancellationToken);
            return (token, account);
        }, requiresNew: true, cancellationToken);

        return new NewPersonalTokenDto((await ToDtosAsync([token], new Dictionary<Guid, string> { [account.Id] = account.Username }, cancellationToken))[0], secret);
    }

    /// <summary>Tokens, newest first: one account's, or every account's for site admins.</summary>
    public Task<List<PersonalTokenDto>> ListAsync(Guid? accountId, bool activeOnly, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            DateTime now = DateTime.UtcNow;
            IQueryable<PersonalAccessToken> query = db.PersonalAccessTokens.AsNoTracking();
            if (accountId is { } id)
            {
                query = query.Where(t => t.AccountId == id);
            }

            if (activeOnly)
            {
                query = query.Where(t => t.RevokedAt == null && t.ExpiresAt > now);
            }

            List<PersonalAccessToken> tokens = await query.OrderByDescending(t => t.CreatedAt).Take(500).ToListAsync(cancellationToken);
            List<Guid> accountIds = tokens.Select(t => t.AccountId).Distinct().ToList();
            Dictionary<Guid, string> names = await db.Accounts.AsNoTracking().Where(a => accountIds.Contains(a.Id)).ToDictionaryAsync(a => a.Id, a => a.Username, cancellationToken);
            return await ToDtosAsync(tokens, names, cancellationToken);
        }, cancellationToken: cancellationToken);

    /// <summary>Revokes a token (of this account, when one is given); it stops working at once.</summary>
    public Task RevokeAsync(Guid tokenId, Guid? accountId, Guid revokedBy, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            PersonalAccessToken token = await db.PersonalAccessTokens.FirstOrDefaultAsync(t => t.Id == tokenId && (accountId == null || t.AccountId == accountId), cancellationToken)
                ?? throw new EntityNotFoundException(typeof(PersonalAccessToken), tokenId);
            if (token.RevokedAt is not null)
            {
                return;
            }

            token.RevokedAt = DateTime.UtcNow;
            token.RevokedBy = revokedBy;
            string? username = await db.Accounts.Where(a => a.Id == token.AccountId).Select(a => a.Username).FirstOrDefaultAsync(cancellationToken);
            audit.Add(db, SecurityAuditTypes.TokenRevoked, new AuditTarget("Account", token.AccountId, username), new { token = token.Id, name = token.Name, prefix = token.Prefix });
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);

    /// <summary>The live token with this secret and its active account, noting when it was last used (at most once a minute).</summary>
    public Task<(PersonalAccessToken Token, Account Account)?> FindAsync(string secret, string? ip, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync<(PersonalAccessToken, Account)?>(async db =>
        {
            string hash = Hash(secret);
            DateTime now = DateTime.UtcNow;
            PersonalAccessToken? token = await db.PersonalAccessTokens.FirstOrDefaultAsync(t => t.SecretHash == hash, cancellationToken);
            if (token is null || !token.IsActive(now))
            {
                return null;
            }

            Account? account = await db.Accounts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == token.AccountId, cancellationToken);
            if (account is null || account.Status != AccountStatus.Active)
            {
                return null;
            }

            if (token.LastUsedAt is null || now - token.LastUsedAt > TimeSpan.FromMinutes(1))
            {
                (token.LastUsedAt, token.LastUsedIp) = (now, ip);
                await db.SaveChangesAsync(cancellationToken);
            }

            return (token, account);
        }, requiresNew: true, cancellationToken);

    private async Task<List<PersonalTokenDto>> ToDtosAsync(List<PersonalAccessToken> tokens, Dictionary<Guid, string> usernames, CancellationToken cancellationToken)
    {
        Dictionary<string, GrantScopeLabel> labels = await DescribeAsync(tokens.SelectMany(t => t.ProjectIds ?? []).Distinct().ToList(), cancellationToken);
        DateTime now = DateTime.UtcNow;
        return tokens.Select(t => new PersonalTokenDto(
                t.Id, t.AccountId, usernames.GetValueOrDefault(t.AccountId, "(removed)"), t.Name, t.Prefix, t.Access,
                t.ProjectIds?.Select(p => labels.TryGetValue(ScopeKey(p), out GrantScopeLabel? l) ? new TokenProjectDto(p, l.Label, l.Href) : new TokenProjectDto(p, p.ToString(), null)).ToList(),
                t.ExpiresAt, t.CreatedAt, t.LastUsedAt, t.LastUsedIp, t.RevokedAt, t.IsActive(now)))
            .ToList();
    }

    /// <summary>Projects as the projects module names them: a grant's scope key for a project is "project:{id}".</summary>
    private static string ScopeKey(Guid projectId) => $"project:{projectId}";

    private async Task<Dictionary<string, GrantScopeLabel>> DescribeAsync(List<Guid> projectIds, CancellationToken cancellationToken)
    {
        Dictionary<string, GrantScopeLabel> labels = [];
        if (projectIds.Count == 0)
        {
            return labels;
        }

        List<string> keys = projectIds.Select(ScopeKey).ToList();
        foreach (IGrantScopeDescriber describer in describers)
        {
            foreach ((string key, GrantScopeLabel label) in await describer.DescribeAsync(keys, cancellationToken))
            {
                labels[key] = label;
            }
        }

        return labels;
    }

    private static string Base64UrlEncoder(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>
/// Signs in a request that carries a personal access token as its bearer token: the token's account, with the token's
/// id, access and projects as claims for the acting context. There's no <c>auth_time</c>, so it never passes a step-up.
/// </summary>
public sealed class PersonalTokenHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, PersonalTokens tokens)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string Scheme = "TodaToken";

    /// <summary>Whether a request's bearer token is a personal access token (it goes to this handler, not to OpenIddict).</summary>
    public static bool Carries(Microsoft.AspNetCore.Http.HttpRequest request) =>
        request.Headers.Authorization.ToString() is { } header && header.StartsWith("Bearer " + PersonalTokens.SecretPrefix, StringComparison.Ordinal);

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Carries(Request))
        {
            return AuthenticateResult.NoResult();
        }

        string secret = Request.Headers.Authorization.ToString()["Bearer ".Length..].Trim();
        if (await tokens.FindAsync(secret, Context.Connection.RemoteIpAddress?.ToString(), Context.RequestAborted) is not { } found)
        {
            return AuthenticateResult.Fail("The token is unknown, revoked or expired, or its account isn't active.");
        }

        ClaimsIdentity identity = new(Scheme, "name", "role");
        identity.AddClaim(new Claim("sub", found.Account.Id.ToString()));
        identity.AddClaim(new Claim("name", found.Account.Username));
        identity.AddClaim(new Claim("display_name", found.Account.DisplayName));
        identity.AddClaim(new Claim(ActingContext.TokenClaim, found.Token.Id.ToString()));
        identity.AddClaim(new Claim(ActingContext.TokenAccessClaim, found.Token.Access));
        foreach (Guid project in found.Token.ProjectIds ?? [])
        {
            identity.AddClaim(new Claim(ActingContext.TokenProjectClaim, project.ToString()));
        }

        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme));
    }
}

/// <summary>
/// A read-only token's ability (ADR 0042): the account's own, keeping only what reads. Every allow rule keeps its read
/// actions; "manage" becomes them; deny rules stay as they are.
/// </summary>
[ExposeServices(typeof(IAbilityLimit))]
public sealed class TokenAccessLimit : IAbilityLimit, ITransientDependency
{
    /// <summary>The actions that only read.</summary>
    public static readonly IReadOnlyList<string> ReadActions = ["read", "browse", "portal"];

    public Ability Apply(Ability ability, ActingContext acting) =>
        acting.ReadOnly ? AbilityRules.Rebuild(ability, rule => rule.Inverted ? [rule] : [AbilityRules.WithActions(rule, ReadActions)]) : ability;
}

/// <summary>Rebuilding an ability from its own rules, narrowed: what the request limits (ADR 0042) are made of.</summary>
public static class AbilityRules
{
    /// <summary>Each rule of the ability, as <paramref name="rewrite"/> turns it into rules (none drops it), plus <paramref name="extra"/>.</summary>
    public static Ability Rebuild(Ability ability, Func<RawRule, IEnumerable<RawRule?>> rewrite, IEnumerable<RawRule>? extra = null) =>
        new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options)
            .AddRange(ability.Rules.SelectMany(rewrite).OfType<RawRule>().Concat(extra ?? []), null)
            .Build();

    /// <summary>The rule with only these of its actions ("manage" counting as all of them); null when none is left.</summary>
    public static RawRule? WithActions(RawRule rule, IReadOnlyList<string> allowed)
    {
        List<string> actions = rule.Action.Contains("manage") ? [.. allowed] : rule.Action.Where(allowed.Contains).ToList();
        return actions.Count == 0 ? null : Copy(rule, actions, rule.Subject);
    }

    public static RawRule Copy(RawRule rule, IReadOnlyList<string> actions, IReadOnlyList<string> subjects) => new()
    {
        Action = actions,
        Subject = subjects,
        Conditions = rule.Conditions?.DeepClone().AsObject(),
        Fields = rule.Fields,
        Inverted = rule.Inverted,
        Reason = rule.Reason,
    };
}
