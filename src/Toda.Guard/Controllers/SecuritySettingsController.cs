using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Toda.Guard.Data;
using Toda.Guard.Domain;
using Toda.Guard.Services;
using Toda.Platform.Acting;
using Toda.Platform.Controllers;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace Toda.Guard.Controllers;

/// <summary>
/// The site's security settings (ADR 0042), with their limits: how long the security audit keeps events, and how
/// recently a person must have signed in or stepped up to do something sensitive.
/// </summary>
public sealed record SecuritySettingsDto(int RetentionDays, int MinRetentionDays, int MaxRetentionDays, int StepUpMinutes, int MinStepUpMinutes, int MaxStepUpMinutes);

public sealed record SecuritySettingsInput(int RetentionDays, int StepUpMinutes);

/// <summary>
/// Security settings, for site admins. Changing them is sensitive (a shorter retention removes older events, a longer
/// window weakens step-up), so it needs a step-up itself and goes in the audit.
/// </summary>
[Route("api/guard/security/settings")]
[Authorize(Policy = TodaPolicies.Admin)]
public class SecuritySettingsController(GuardDb guardDb, SecurityLog audit) : GuardControllerBase
{
    [HttpGet]
    public Task<SecuritySettingsDto> Get(CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db => ToDto(await LoadAsync(db, cancellationToken)), cancellationToken: cancellationToken);

    [HttpPut]
    [StepUp]
    public Task<SecuritySettingsDto> Save([FromBody] SecuritySettingsInput input, CancellationToken cancellationToken)
    {
        if (input.RetentionDays is < SecuritySettings.MinRetentionDays or > SecuritySettings.MaxRetentionDays)
        {
            throw new UserFriendlyException($"Keep security events between {SecuritySettings.MinRetentionDays} and {SecuritySettings.MaxRetentionDays} days.");
        }

        if (input.StepUpMinutes is < SecuritySettings.MinStepUpMinutes or > SecuritySettings.MaxStepUpMinutes)
        {
            throw new UserFriendlyException($"Ask for the password again after {SecuritySettings.MinStepUpMinutes} to {SecuritySettings.MaxStepUpMinutes} minutes.");
        }

        return guardDb.RunAsync(async db =>
        {
            SecuritySettings settings = await LoadAsync(db, cancellationToken);
            if (settings.RetentionDays != input.RetentionDays)
            {
                audit.Add(db, SecurityAuditTypes.RetentionChanged, null, new { retentionDays = new { before = settings.RetentionDays, after = input.RetentionDays } });
                settings.RetentionDays = input.RetentionDays;
            }

            if (settings.StepUpMinutes != input.StepUpMinutes)
            {
                audit.Add(db, SecurityAuditTypes.StepUpChanged, null, new { stepUpMinutes = new { before = settings.StepUpMinutes, after = input.StepUpMinutes } });
                settings.StepUpMinutes = input.StepUpMinutes;
            }

            await db.SaveChangesAsync(cancellationToken);
            return ToDto(settings);
        }, requiresNew: true, cancellationToken);
    }

    /// <summary>The site's security settings, made with the defaults the first time they're asked for.</summary>
    public static async Task<SecuritySettings> LoadAsync(GuardDbContext db, CancellationToken cancellationToken)
    {
        SecuritySettings? settings = await db.SecuritySettings.FirstOrDefaultAsync(s => s.Id == SecuritySettings.SingletonId, cancellationToken);
        if (settings is null)
        {
            settings = new SecuritySettings(SecuritySettings.SingletonId);
            db.SecuritySettings.Add(settings);
            await db.SaveChangesAsync(cancellationToken);
        }

        return settings;
    }

    private static SecuritySettingsDto ToDto(SecuritySettings s) => new(
        s.RetentionDays, SecuritySettings.MinRetentionDays, SecuritySettings.MaxRetentionDays,
        s.StepUpMinutes, SecuritySettings.MinStepUpMinutes, SecuritySettings.MaxStepUpMinutes);
}

/// <summary>The step-up window as the site sets it (ADR 0042): ten minutes unless changed, never more than thirty.</summary>
[ExposeServices(typeof(IStepUpPolicy))]
public class GuardStepUpPolicy(GuardDb guardDb) : IStepUpPolicy, ITransientDependency
{
    public async Task<TimeSpan> WindowAsync(CancellationToken cancellationToken = default)
    {
        int minutes = await guardDb.RunAsync(db => db.SecuritySettings.AsNoTracking().Where(s => s.Id == SecuritySettings.SingletonId)
            .Select(s => (int?)s.StepUpMinutes).FirstOrDefaultAsync(cancellationToken), cancellationToken: cancellationToken) ?? SecuritySettings.DefaultStepUpMinutes;
        return TimeSpan.FromMinutes(Math.Clamp(minutes, SecuritySettings.MinStepUpMinutes, SecuritySettings.MaxStepUpMinutes));
    }
}
