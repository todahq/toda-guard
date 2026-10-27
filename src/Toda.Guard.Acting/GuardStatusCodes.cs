using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Volo.Abp;
using Volo.Abp.AspNetCore.ExceptionHandling;
using Volo.Abp.DependencyInjection;
using Volo.Abp.ExceptionHandling;

namespace Toda.Guard;

/// <summary>
/// The statuses Guard's errors answer with (ADR 0087), for a host that hasn't chosen its own: a refusal or a step-up
/// needed is 403, too many tries 429, and a business rule that says no to the input (a taken username, a short password,
/// a bad link) 400, where ABP's default would answer 403 and make it look like a permission problem. Toda has its own
/// finder that does the same, and keeps it.
/// </summary>
[DisableConventionalRegistration]
public class GuardHttpExceptionStatusCodeFinder(IOptions<AbpExceptionHttpStatusCodeOptions> options) : DefaultHttpExceptionStatusCodeFinder(options)
{
    public override HttpStatusCode GetStatusCode(HttpContext httpContext, Exception exception)
    {
        if (exception is IHasErrorCode { Code: { } code })
        {
            switch (code)
            {
                case GuardErrorCodes.Forbidden:
                case GuardErrorCodes.StepUpRequired:
                    return HttpStatusCode.Forbidden;
                case GuardErrorCodes.TooManyRequests:
                    return HttpStatusCode.TooManyRequests;
            }
        }

        if (exception is UserFriendlyException or BusinessException && exception is not Volo.Abp.Authorization.AbpAuthorizationException)
        {
            HttpStatusCode mapped = base.GetStatusCode(httpContext, exception);
            return mapped == HttpStatusCode.Forbidden ? HttpStatusCode.BadRequest : mapped;
        }

        return base.GetStatusCode(httpContext, exception);
    }

    /// <summary>Uses Guard's finder when the host still has ABP's default one; a host's own finder stays.</summary>
    public static void UseUnlessTheHostHasItsOwn(IServiceCollection services)
    {
        ServiceDescriptor? current = services.LastOrDefault(d => d.ServiceType == typeof(IHttpExceptionStatusCodeFinder));
        if (current is null || current.ImplementationType == typeof(DefaultHttpExceptionStatusCodeFinder))
        {
            services.Replace(ServiceDescriptor.Transient<IHttpExceptionStatusCodeFinder, GuardHttpExceptionStatusCodeFinder>());
        }
    }
}
