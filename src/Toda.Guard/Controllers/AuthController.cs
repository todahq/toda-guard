using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Domain;
using Toda.Guard.Services;

namespace Toda.Guard.Controllers;

/// <summary>
/// The person's language and time zone; null follows the site's (ADR 0039). Weeks start on the site's first day for
/// everyone (ADR 0013): sunday, monday…
/// </summary>
public sealed record PreferencesDto(string? Language, string? TimeZone, string SiteTimeZone, string FirstDayOfWeek);

public sealed record PreferencesInput(string? Language, string? TimeZone);

[Route("api/guard")]
public class AuthController(GuardDb guardDb, MembershipGraph graph, Toda.Platform.Localization.LocalizationCache localization,
    Toda.Platform.SiteCalendar calendar) : GuardControllerBase
{
    /// <summary>Sets the person's language and time zone; null (or empty) goes back to the site's.</summary>
    [HttpPut("me/preferences")]
    [Authorize]
    public async Task<PreferencesDto> SavePreferences([FromBody] PreferencesInput input, CancellationToken cancellationToken)
    {
        string? language = string.IsNullOrWhiteSpace(input.Language) ? null : input.Language.Trim();
        string? zone = string.IsNullOrWhiteSpace(input.TimeZone) ? null : input.TimeZone.Trim();
        if (language is not null)
        {
            Toda.Platform.Localization.LanguageInfo? known = (await localization.SnapshotAsync(cancellationToken)).Find(language);
            language = known is { Enabled: true } ? known.Code : throw new Volo.Abp.UserFriendlyException($"'{language}' isn't one of the site's languages.");
        }

        if (zone is not null && !TimeZoneInfo.TryFindSystemTimeZoneById(zone, out _))
        {
            throw new Volo.Abp.UserFriendlyException($"'{zone}' isn't a time zone.");
        }

        return await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.FirstAsync(a => a.Id == CurrentAccountId, cancellationToken);
            account.Language = language;
            account.TimeZone = zone;
            await db.SaveChangesAsync(cancellationToken);
            return Preferences(account);
        }, requiresNew: true, cancellationToken: cancellationToken);
    }

    private PreferencesDto Preferences(Account account) =>
        new(account.Language, account.TimeZone, calendar.TimeZone, calendar.FirstDayOfWeek.ToString().ToLowerInvariant());

    [HttpGet("me")]
    [Authorize]
    public async Task<object> Me(CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        return await guardDb.RunAsync<object>(async db =>
    {
        Account account = await db.Accounts.FirstAsync(a => a.Id == CurrentAccountId, cancellationToken);
        Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
        List<EffectiveGroup> groups = await graph.GetEffectiveGroupsAsync(db, account, cancellationToken);
        return new
        {
            account = AccountDto.From(account, directories.GetValueOrDefault(account.DirectoryId, "?")),
            groups = groups.Select(g => new EffectiveGroupDto(g.Group.Id, g.Group.Name, g.Group.DirectoryId, directories.GetValueOrDefault(g.Group.DirectoryId, "?"), g.Direct, g.Path)),
            isAdmin = ability.Can("manage", "all"),
            // Whose rights the session uses and who is acting (ADR 0042): only a subject unless someone acts for them.
            acting = new { accountId = Acting.SubjectId, actingAccountId = Acting.ActorId, mode = Acting.Mode, sessionId = Acting.SessionId },
            preferences = Preferences(account),
            // CASL raw rules for the browser (casl-net): the UI hides what the server would refuse.
            rules = ability.ToCaslRules(),
        };
    }, cancellationToken: cancellationToken);
    }

    private static object Error(string code, string message) => new { error = new { code, message } };
}
