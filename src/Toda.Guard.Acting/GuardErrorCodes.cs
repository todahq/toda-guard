using Microsoft.Extensions.DependencyInjection;
using Volo.Abp.AspNetCore.ExceptionHandling;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Modularity;

namespace Toda.Guard;

/// <summary>
/// The error codes Guard answers with (ADR 0087), the same strings Toda has always used, so clients see no change: a
/// refusal, a step-up needed (with <c>maxAgeSeconds</c> in the error's data), and too many tries.
/// </summary>
public static class GuardErrorCodes
{
    /// <summary>The person may not do this (a rule refused it). 403.</summary>
    public const string Forbidden = "Toda:Forbidden";

    /// <summary>
    /// A sensitive action needs the person to have proved who they are recently (ADR 0042). 403, not 401, which would end
    /// the session; the error's data says how recent (<c>maxAgeSeconds</c>).
    /// </summary>
    public const string StepUpRequired = "step_up_required";

    /// <summary>Too many requests from one place in a while (sign-up, password reset). 429.</summary>
    public const string TooManyRequests = "Toda:TooManyRequests";
}

/// <summary>The acting context's module (ADR 0087): its services, and Guard's error codes answered with their own statuses.</summary>
[DependsOn(typeof(AbpAspNetCoreMvcModule))]
public class TodaGuardActingModule : AbpModule
{
    public override void ConfigureServices(ServiceConfigurationContext context) =>
        Configure<AbpExceptionHttpStatusCodeOptions>(options =>
        {
            options.Map(GuardErrorCodes.Forbidden, System.Net.HttpStatusCode.Forbidden);
            options.Map(GuardErrorCodes.StepUpRequired, System.Net.HttpStatusCode.Forbidden);
            options.Map(GuardErrorCodes.TooManyRequests, System.Net.HttpStatusCode.TooManyRequests);
        });

    /// <summary>After every module has registered its services: Guard's status finder, unless the host has its own.</summary>
    public override void PostConfigureServices(ServiceConfigurationContext context) =>
        GuardHttpExceptionStatusCodeFinder.UseUnlessTheHostHasItsOwn(context.Services);
}
