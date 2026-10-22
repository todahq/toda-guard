using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Toda.Guard.Domain;
using Toda.Platform.Acting;
using OpenIddict.Abstractions;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Services;

/// <summary>A live session as requests see it, with its account's names.</summary>
public sealed record WebSessionInfo(Guid Id, Guid AccountId, string Username, string DisplayName, DateTime AuthTime, string TokenHash);

/// <summary>
/// The web's sessions (ADR 0075): started by signing in, found by the cookie's secret, slid on as they're used, marked by
/// a step-up, and ended. A found session is kept in memory for a few seconds, so most requests don't read the table; an
/// ended one stops working at once on this server, and within those seconds on the others.
/// </summary>
public class WebSessions(GuardDb guardDb, IMemoryCache cache, IOpenIddictAuthorizationManager authorizations) : ITransientDependency
{
    /// <summary>How long a session lives unused; each use pushes its end on (as the web's refresh tokens did, ADR 0007).</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(14);

    /// <summary>How long ended and expired sessions are kept before they're removed.</summary>
    public static readonly TimeSpan KeptAfterEnd = TimeSpan.FromDays(30);

    /// <summary>How long the phone app's handoff code is good for: long enough to open a web view, no longer.</summary>
    public static readonly TimeSpan HandoffLifetime = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan Remembered = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan SeenEvery = TimeSpan.FromMinutes(1);
    private const int Batch = 5000;

    public static string Hash(string secret) => PersonalTokens.Hash(secret);

    /// <summary>
    /// The anti-forgery value for a session: derived from its secret, so a page can only know it by reading the cookie
    /// the server set beside the session's, which another site can't.
    /// </summary>
    public static string CsrfFor(string secret) => Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes("toda-csrf:" + secret)));

    public static bool CsrfMatches(string secret, string? header) =>
        header is { Length: > 0 } && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(CsrfFor(secret)), Encoding.UTF8.GetBytes(header));

    /// <summary>
    /// A new session for an account that just proved who it is; the secret is the cookie's, never kept. A web view's
    /// session names the phone app's sign-in it came from, and when that proved who the person is.
    /// </summary>
    public async Task<(WebSession Session, string Secret)> StartAsync(Guid accountId, string? userAgent, string? ip, string? parentAuthorizationId = null,
        DateTime? authTime = null, CancellationToken cancellationToken = default)
    {
        string secret = Base64Url(RandomNumberGenerator.GetBytes(32));
        WebSession session = new(Guid.NewGuid(), accountId, Hash(secret), DateTime.UtcNow.Add(Lifetime), userAgent is { Length: > 256 } ? userAgent[..256] : userAgent, ip,
            parentAuthorizationId, authTime);
        await guardDb.RunAsync(async db =>
        {
            db.WebSessions.Add(session);
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);
        return (session, secret);
    }

    /// <summary>
    /// The live session with this secret, its account active, and for a web view the phone app's sign-in still standing.
    /// Slid is true when its end just moved on (at most once a minute), so the cookies are set again to last as long.
    /// </summary>
    public async Task<(WebSessionInfo Info, bool Slid)?> FindAsync(string secret, CancellationToken cancellationToken = default)
    {
        string hash = Hash(secret);
        if (cache.TryGetValue(Key(hash), out WebSessionInfo? remembered) && remembered is not null)
        {
            return (remembered, false);
        }

        return await guardDb.RunAsync<(WebSessionInfo, bool)?>(async db =>
        {
            DateTime now = DateTime.UtcNow;
            var found = await db.WebSessions.AsNoTracking()
                .Where(s => s.TokenHash == hash && s.RevokedAt == null && s.ExpiresAt > now)
                .Join(db.Accounts.Where(a => a.Status == AccountStatus.Active), s => s.AccountId, a => a.Id,
                    (s, a) => new { s.Id, s.AccountId, a.Username, a.DisplayName, s.AuthTime, s.LastSeenAt, s.ParentAuthorizationId })
                .FirstOrDefaultAsync(cancellationToken);
            if (found is null)
            {
                return null;
            }

            // A web view's session ends with the app's sign-in, however that ended (the app signed out, the token was revoked).
            if (found.ParentAuthorizationId is { } parent
                && (await authorizations.FindByIdAsync(parent, cancellationToken) is not { } authorization
                    || await authorizations.GetStatusAsync(authorization, cancellationToken) != OpenIddictConstants.Statuses.Valid))
            {
                await db.WebSessions.Where(s => s.Id == found.Id)
                    .ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, now).SetProperty(s => s.RevokedReason, "app-ended"), cancellationToken);
                return null;
            }

            bool slid = found.LastSeenAt < now - SeenEvery;
            if (slid)
            {
                DateTime expiresAt = now.Add(Lifetime);
                await db.WebSessions.Where(s => s.Id == found.Id)
                    .ExecuteUpdateAsync(set => set.SetProperty(s => s.LastSeenAt, now).SetProperty(s => s.ExpiresAt, expiresAt), cancellationToken);
            }

            WebSessionInfo info = new(found.Id, found.AccountId, found.Username, found.DisplayName, found.AuthTime, hash);
            cache.Set(Key(hash), info, Remembered);
            return (info, slid);
        }, requiresNew: true, cancellationToken);
    }

    /// <summary>Ends a session, if it's still live; it stops working at once.</summary>
    public Task EndAsync(Guid sessionId, string reason, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            WebSession? session = await db.WebSessions.FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken);
            if (session is null || session.RevokedAt is not null)
            {
                return;
            }

            session.RevokedAt = DateTime.UtcNow;
            session.RevokedReason = reason;
            await db.SaveChangesAsync(cancellationToken);
            cache.Remove(Key(session.TokenHash));
        }, requiresNew: true, cancellationToken);

    /// <summary>
    /// Ends every live session of an account but the one kept, and the web views of the phone app's sign-in kept; they
    /// stop working at once.
    /// </summary>
    public Task<int> EndAllAsync(Guid accountId, string reason, Guid? except = null, string? exceptOpenedBy = null, CancellationToken cancellationToken = default) =>
        EndWhereAsync(s => s.AccountId == accountId && s.Id != except && (exceptOpenedBy == null || s.ParentAuthorizationId != exceptOpenedBy), reason, cancellationToken);

    /// <summary>Ends the web views' sessions the phone app's sign-in opened (it ended).</summary>
    public Task<int> EndOpenedByAsync(string authorizationId, CancellationToken cancellationToken = default) =>
        EndWhereAsync(s => s.ParentAuthorizationId == authorizationId, "app-ended", cancellationToken);

    private async Task<int> EndWhereAsync(System.Linq.Expressions.Expression<Func<WebSession, bool>> which, string reason, CancellationToken cancellationToken)
    {
        List<string> ended = await guardDb.RunAsync(async db =>
        {
            DateTime now = DateTime.UtcNow;
            List<WebSession> live = await db.WebSessions.Where(which).Where(s => s.RevokedAt == null && s.ExpiresAt > now).ToListAsync(cancellationToken);
            foreach (WebSession session in live)
            {
                session.RevokedAt = now;
                session.RevokedReason = reason;
            }

            await db.SaveChangesAsync(cancellationToken);
            return live.Select(s => s.TokenHash).ToList();
        }, requiresNew: true, cancellationToken);
        foreach (string hash in ended)
        {
            cache.Remove(Key(hash));
        }

        return ended.Count;
    }

    /// <summary>A step-up passed (ADR 0042): the session says the person proved who they are just now. Null when it has ended.</summary>
    public Task<DateTime?> MarkSteppedUpAsync(Guid sessionId, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync<DateTime?>(async db =>
        {
            WebSession? session = await db.WebSessions.FirstOrDefaultAsync(s => s.Id == sessionId, cancellationToken);
            if (session is null || !session.IsActive(DateTime.UtcNow))
            {
                return null;
            }

            session.AuthTime = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            cache.Remove(Key(session.TokenHash));
            return session.AuthTime;
        }, requiresNew: true, cancellationToken);

    /// <summary>
    /// A code the phone app opens a web view with (ADR 0075): good once, for seconds, for a session that belongs to the
    /// app's sign-in. Only its hash is kept.
    /// </summary>
    public async Task<(string Code, DateTime ExpiresAt)> HandOffAsync(Guid accountId, string authorizationId, DateTime authTime, CancellationToken cancellationToken = default)
    {
        string code = Base64Url(RandomNumberGenerator.GetBytes(32));
        SessionHandoff handoff = new(Guid.NewGuid(), Hash(code), accountId, authorizationId, authTime, DateTime.UtcNow.Add(HandoffLifetime));
        await guardDb.RunAsync(async db =>
        {
            db.SessionHandoffs.Add(handoff);
            await db.SaveChangesAsync(cancellationToken);
        }, requiresNew: true, cancellationToken);
        return (code, handoff.ExpiresAt);
    }

    /// <summary>
    /// Takes a handoff code, once: the account (still active), the app's sign-in and its proof time; null when the code is
    /// unknown, used or too old. Two web views opening the same code can't both have it.
    /// </summary>
    public Task<SessionHandoff?> TakeHandoffAsync(string code, CancellationToken cancellationToken = default) =>
        guardDb.RunAsync(async db =>
        {
            string hash = Hash(code);
            DateTime now = DateTime.UtcNow;
            if (await db.SessionHandoffs.Where(h => h.CodeHash == hash && h.UsedAt == null && h.ExpiresAt > now)
                    .ExecuteUpdateAsync(set => set.SetProperty(h => h.UsedAt, now), cancellationToken) == 0)
            {
                return null;
            }

            SessionHandoff handoff = await db.SessionHandoffs.AsNoTracking().FirstAsync(h => h.CodeHash == hash, cancellationToken);
            return await db.Accounts.AnyAsync(a => a.Id == handoff.AccountId && a.Status == AccountStatus.Active, cancellationToken) ? handoff : null;
        }, requiresNew: true, cancellationToken);

    /// <summary>Removes sessions that ended or expired over a month ago, and handoff codes over a day old.</summary>
    public async Task PruneAsync(CancellationToken cancellationToken = default)
    {
        DateTime before = DateTime.UtcNow - KeptAfterEnd;
        while (await guardDb.RunAsync(db => db.WebSessions.Where(s => s.ExpiresAt < before || s.RevokedAt < before).OrderBy(s => s.ExpiresAt).Take(Batch)
                   .ExecuteDeleteAsync(cancellationToken), requiresNew: true, cancellationToken: cancellationToken) == Batch)
        {
        }

        DateTime dayAgo = DateTime.UtcNow.AddDays(-1);
        await guardDb.RunAsync(db => db.SessionHandoffs.Where(h => h.ExpiresAt < dayAgo).ExecuteDeleteAsync(cancellationToken), requiresNew: true, cancellationToken: cancellationToken);
    }

    private static string Key(string hash) => "toda:web-session:" + hash;

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>
/// Signs in a browser by its session cookie (ADR 0075), when the request carries no bearer token. A request that changes
/// something must also carry the session's anti-forgery header, which the page reads from <c>toda_csrf</c>: without it
/// the request counts as no one's, and an endpoint that needs someone answers 403 <c>csrf_failed</c>.
/// </summary>
public sealed class WebSessionHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, WebSessions sessions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "TodaSession";
    public const string CookieName = "toda_session";
    public const string CsrfCookieName = "toda_csrf";
    public const string CsrfHeader = "X-Toda-Csrf";

    /// <summary>Set by the phone app's handoff: the shell shows only the page, and talks to the app (ADR 0073, 0075).</summary>
    public const string EmbeddedCookieName = "toda_embedded";

    /// <summary>The session's id (OpenID Connect's claim), so the person's list can say which session is this one.</summary>
    public const string SessionIdClaim = "sid";

    private const string CsrfFailedItem = "toda.csrf-failed";

    /// <summary>Whether a request comes with a session cookie (and so goes to this handler, when it has no bearer token).</summary>
    public static bool Carries(HttpRequest request) => request.Cookies.ContainsKey(CookieName);

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Request.Cookies[CookieName] is not { Length: > 0 } secret)
        {
            return AuthenticateResult.NoResult();
        }

        if (!IsSafe(Request.Method) && !WebSessions.CsrfMatches(secret, await CsrfValueAsync()))
        {
            Context.Items[CsrfFailedItem] = true;
            return AuthenticateResult.Fail("The request changes something but has no anti-forgery header, or a wrong one.");
        }

        if (await sessions.FindAsync(secret, Context.RequestAborted) is not { } found)
        {
            return AuthenticateResult.Fail("The session has ended, or its account isn't active.");
        }

        if (found.Slid)
        {
            Issue(Context, secret);
        }

        ClaimsIdentity identity = new(SchemeName, "name", "role");
        identity.AddClaim(new Claim("sub", found.Info.AccountId.ToString()));
        identity.AddClaim(new Claim("name", found.Info.Username));
        identity.AddClaim(new Claim("display_name", found.Info.DisplayName));
        identity.AddClaim(new Claim(SessionIdClaim, found.Info.Id.ToString()));
        // Every sign-in so far is a password checked by the account's directory (OpenID Connect's "pwd").
        identity.AddClaim(new Claim(ActingContext.AuthTimeClaim, new DateTimeOffset(found.Info.AuthTime, TimeSpan.Zero).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)));
        identity.AddClaim(new Claim("amr", "pwd"));
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    /// <summary>
    /// The anti-forgery value a request came with: the header, or for a plain HTML form (the OAuth consent page's, which
    /// can't set headers) a field of the same name as the cookie.
    /// </summary>
    private async Task<string?> CsrfValueAsync()
    {
        if (Request.Headers[CsrfHeader].ToString() is { Length: > 0 } header)
        {
            return header;
        }

        return Request.HasFormContentType ? (await Request.ReadFormAsync(Context.RequestAborted))[CsrfCookieName].ToString() : null;
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (!Context.Items.ContainsKey(CsrfFailedItem))
        {
            await base.HandleChallengeAsync(properties);
            return;
        }

        Response.StatusCode = StatusCodes.Status403Forbidden;
        await Response.WriteAsJsonAsync(new { error = new { code = "csrf_failed", message = "This request came without the page's anti-forgery header and was refused. Reload the page." } });
    }

    /// <summary>Sets the session's cookies: its secret (only the server reads it) and the anti-forgery value (the page reads it).</summary>
    /// <param name="embedded">
    /// Whether the shell shows itself embedded, in the phone app's web view (<c>toda_embedded</c>, read by the web): true
    /// for a handoff, false for a sign-in, null to keep what the browser has.
    /// </param>
    public static void Issue(HttpContext http, string secret, bool? embedded = null)
    {
        bool secure = IsHttps(http.Request);
        CookieOptions Cookie(bool httpOnly) => new()
        {
            HttpOnly = httpOnly, Secure = secure, SameSite = SameSiteMode.Lax, Path = "/", MaxAge = WebSessions.Lifetime, IsEssential = true,
        };
        http.Response.Cookies.Append(CookieName, secret, Cookie(httpOnly: true));
        http.Response.Cookies.Append(CsrfCookieName, WebSessions.CsrfFor(secret), Cookie(httpOnly: false));
        if (embedded ?? http.Request.Cookies.ContainsKey(EmbeddedCookieName))
        {
            http.Response.Cookies.Append(EmbeddedCookieName, "1", Cookie(httpOnly: false));
        }
        else if (embedded is false)
        {
            http.Response.Cookies.Delete(EmbeddedCookieName, new CookieOptions { Secure = secure, SameSite = SameSiteMode.Lax, Path = "/" });
        }
    }

    public static void Clear(HttpContext http)
    {
        bool secure = IsHttps(http.Request);
        foreach (string name in new[] { CookieName, CsrfCookieName, EmbeddedCookieName })
        {
            http.Response.Cookies.Delete(name, new CookieOptions { Secure = secure, SameSite = SameSiteMode.Lax, Path = "/" });
        }
    }

    /// <summary>
    /// Whether a sign-in or sign-out came from another site (a page there can't read our cookies, but it can post a form
    /// here). Browsers say where a request came from in Sec-Fetch-Site or Origin; a client that sends neither isn't a
    /// browser, so it can't be made to send someone's cookies. The site's public address counts as this site too, since
    /// a proxy in front may change the host.
    /// </summary>
    public static bool IsCrossSite(HttpRequest request, string? publicUrl)
    {
        if (IsSafe(request.Method))
        {
            return false;
        }

        if (request.Headers["Sec-Fetch-Site"].ToString() is { Length: > 0 } site)
        {
            return site != "same-origin";
        }

        if (request.Headers.Origin.ToString() is not { Length: > 0 } origin)
        {
            return false;
        }

        string scheme = IsHttps(request) ? "https" : "http";
        string forwardedHost = request.Headers["X-Forwarded-Host"].ToString().Split(',')[0].Trim();
        HashSet<string> allowed = new(StringComparer.OrdinalIgnoreCase) { $"{scheme}://{request.Host}" };
        if (forwardedHost.Length > 0)
        {
            allowed.Add($"{scheme}://{forwardedHost}");
        }

        if (publicUrl is { Length: > 0 } && Uri.TryCreate(publicUrl, UriKind.Absolute, out Uri? publicSite))
        {
            allowed.Add(publicSite.GetLeftPart(UriPartial.Authority));
        }

        return !allowed.Contains(origin);
    }

    private static bool IsSafe(string method) => HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method) || HttpMethods.IsTrace(method);

    /// <summary>Whether the browser used https: directly, or to a proxy that says so.</summary>
    private static bool IsHttps(HttpRequest request) =>
        request.IsHttps || string.Equals(request.Headers["X-Forwarded-Proto"].ToString().Split(',')[0].Trim(), "https", StringComparison.OrdinalIgnoreCase);
}
