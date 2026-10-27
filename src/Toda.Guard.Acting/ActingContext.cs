using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Volo.Abp.DependencyInjection;

namespace Toda.Platform.Acting;

/// <summary>How someone acts for another person (ADR 0042).</summary>
public static class ActingModes
{
    /// <summary>Support sees Toda as someone else sees it (M9).</summary>
    public const string Impersonation = "impersonation";

    /// <summary>A person acts on someone's approvals and assignments while they're away (M8).</summary>
    public const string Delegation = "delegation";
}

/// <summary>
/// Whose rights a request uses and who is acting (ADR 0042). The <em>subject</em> is the account whose rights apply;
/// the <em>actor</em> is the person acting, when that's someone else, and the <em>mode</em> says how. Usually there's
/// only a subject. Worked out once per request from the access token, and the only place that reads who the token is
/// for: everything else asks this, so a token's limits can't be skipped.
/// </summary>
public sealed class ActingContext(IHttpContextAccessor http) : IScopedDependency
{
    /// <summary>The claim that names the actor (RFC 8693): a JSON object whose <c>sub</c> is the actor's account id.</summary>
    public const string ActClaim = "act";

    /// <summary>The claim with the impersonation session a token belongs to.</summary>
    public const string SessionClaim = "toda_session";

    /// <summary>The claim with the mode an actor acts in.</summary>
    public const string ModeClaim = "toda_mode";

    /// <summary>When the person last proved who they are, in seconds since 1970 (OpenID Connect's claim).</summary>
    public const string AuthTimeClaim = "auth_time";

    /// <summary>The personal access token a request came with (its id), set only by the token's own sign-in.</summary>
    public const string TokenClaim = "toda_token";

    /// <summary>A personal access token's access: <c>read</c> or <c>write</c>.</summary>
    public const string TokenAccessClaim = "toda_token_access";

    /// <summary>A project a personal access token is limited to; one claim each, none for every project.</summary>
    public const string TokenProjectClaim = "toda_token_project";

    /// <summary>A tool a personal access token is limited to (M7, ADR 0025); one claim each, none for every tool.</summary>
    public const string TokenToolClaim = "toda_token_tool";

    private bool _read;
    private Guid? _subjectId;
    private string? _subjectName;
    private Guid? _actorId;
    private string? _mode;
    private Guid? _sessionId;
    private DateTimeOffset? _authTime;
    private Guid? _tokenId;
    private bool _tokenReadOnly;
    private IReadOnlyList<Guid>? _tokenProjects;
    private IReadOnlyList<string>? _tokenTools;

    /// <summary>The account whose rights apply; none for a visitor who isn't signed in, or work outside a request.</summary>
    public Guid? SubjectId => Read()._subjectId;

    /// <summary>The subject's username, as the token says it.</summary>
    public string? SubjectName => Read()._subjectName;

    /// <summary>The person acting for the subject, when that's someone else.</summary>
    public Guid? ActorId => Read()._actorId;

    /// <summary>How the actor acts: <see cref="ActingModes"/>.</summary>
    public string? Mode => Read()._mode;

    /// <summary>The impersonation session the token belongs to.</summary>
    public Guid? SessionId => Read()._sessionId;

    public bool SignedIn => SubjectId is not null;

    /// <summary>When the person last proved who they are: signing in, or a step-up since (ADR 0042, the token's <c>auth_time</c>).</summary>
    public DateTimeOffset? AuthTime => Read()._authTime;

    /// <summary>The personal access token the request came with, if any: it can't step up, and it may only read or only some projects.</summary>
    public Guid? TokenId => Read()._tokenId;

    /// <summary>The request may only read: a read-only token.</summary>
    public bool ReadOnly => Read()._tokenReadOnly;

    /// <summary>The projects the request is limited to, by its token; null for every project the person may use.</summary>
    public IReadOnlyList<Guid>? TokenProjects => Read()._tokenProjects;

    /// <summary>The tools the request may use, by its token (their names); null for every tool.</summary>
    public IReadOnlyList<string>? TokenTools => Read()._tokenTools;

    /// <summary>The request's address, for the security audit.</summary>
    public string? Ip => http.HttpContext?.Connection.RemoteIpAddress?.ToString();

    private ActingContext Read()
    {
        if (_read)
        {
            return this;
        }

        _read = true;
        ClaimsPrincipal? user = http.HttpContext?.User;
        if (user?.Identity?.IsAuthenticated != true)
        {
            return this;
        }

        if (Guid.TryParse(user.FindFirstValue("sub") ?? user.FindFirstValue(ClaimTypes.NameIdentifier), out Guid subject))
        {
            _subjectId = subject;
            _subjectName = user.FindFirstValue("name") ?? user.FindFirstValue(ClaimTypes.Name);
        }

        if (user.FindFirstValue(ActClaim) is { Length: > 0 } act)
        {
            try
            {
                using JsonDocument doc = JsonDocument.Parse(act);
                if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("sub", out JsonElement sub)
                    && Guid.TryParse(sub.GetString(), out Guid actor))
                {
                    _actorId = actor;
                    _mode = user.FindFirstValue(ModeClaim) ?? ActingModes.Impersonation;
                }
            }
            catch (JsonException)
            {
                // A token that names its actor wrongly acts for no one: the subject alone.
            }
        }

        if (Guid.TryParse(user.FindFirstValue(SessionClaim), out Guid session))
        {
            _sessionId = session;
        }

        if (long.TryParse(user.FindFirstValue(AuthTimeClaim), out long seconds))
        {
            _authTime = DateTimeOffset.FromUnixTimeSeconds(seconds);
        }

        if (Guid.TryParse(user.FindFirstValue(TokenClaim), out Guid token))
        {
            _tokenId = token;
            _tokenReadOnly = user.FindFirstValue(TokenAccessClaim) != "write";
            List<Guid> projects = user.FindAll(TokenProjectClaim).Select(c => Guid.TryParse(c.Value, out Guid id) ? id : Guid.Empty).ToList();
            _tokenProjects = projects.Count == 0 ? null : projects;
            List<string> tools = user.FindAll(TokenToolClaim).Select(c => c.Value).ToList();
            _tokenTools = tools.Count == 0 ? null : tools;
        }

        return this;
    }
}

/// <summary>
/// A row that says who did something, and so also who acted for them when that was someone else (ADR 0042). The row's
/// own column keeps the account the action counts as; these two keep the actor and the mode.
/// </summary>
public interface IActed
{
    Guid? ActingAccountId { get; set; }

    string? ActingMode { get; set; }

    /// <summary>Whether a change to the row is the act it records (a held request's decision), not only its creation.</summary>
    bool ActedOnChange => false;
}

public static class ActedRows
{
    /// <summary>
    /// Fills the actor on every row about to be saved that records an act, unless the code set it already: the rows a
    /// request adds, and the rows whose change is the act. Nothing to fill when no one acts for someone else.
    /// </summary>
    public static void Stamp(ChangeTracker changes, ActingContext? acting)
    {
        if (acting?.ActorId is not Guid actor)
        {
            return;
        }

        foreach (EntityEntry entry in changes.Entries())
        {
            if (entry.Entity is IActed acted && acted.ActingAccountId is null
                && (entry.State == EntityState.Added || (entry.State == EntityState.Modified && acted.ActedOnChange)))
            {
                acted.ActingAccountId = actor;
                acted.ActingMode = acting.Mode;
            }
        }
    }
}

/// <summary>What a change in the security audit was made to: an account, a group, a role, a directory, a plugin.</summary>
public sealed record AuditTarget(string Type, Guid? Id, string? Name);

/// <summary>
/// The security audit (ADR 0042): every change to who may do what. Guard keeps it; other modules write to it through
/// this, as whoever the request acts as.
/// </summary>
public interface ISecurityAudit
{
    Task WriteAsync(string type, AuditTarget? target, object? detail, CancellationToken cancellationToken = default);
}
