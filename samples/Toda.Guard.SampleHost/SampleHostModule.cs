using Volo.Abp;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Autofac;
using Volo.Abp.Modularity;

namespace Toda.Guard.SampleHost;

/// <summary>Guard's module and ABP's, and Guard's controllers: all a host needs (ADR 0087).</summary>
[DependsOn(typeof(AbpAutofacModule), typeof(TodaGuardModule))]
public class SampleHostModule : AbpModule
{
    public override void ConfigureServices(ServiceConfigurationContext context) =>
        Configure<AbpAspNetCoreMvcOptions>(options => options.ConventionalControllers.Create(typeof(TodaGuardModule).Assembly));

    public override void OnApplicationInitialization(ApplicationInitializationContext context)
    {
        IApplicationBuilder app = context.GetApplicationBuilder();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        // A read-only token reads only (ADR 0042).
        app.UseMiddleware<Toda.Platform.Acting.ReadOnlyRequests>();
        app.UseConfiguredEndpoints();
    }
}
