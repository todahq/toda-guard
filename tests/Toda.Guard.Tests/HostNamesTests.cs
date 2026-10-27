using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Toda.Guard.Controllers;
using Toda.Guard.Services;

namespace Toda.Guard.Tests;

/// <summary>The host's names for cookies, pages and clients (ADR 0087): Toda's by default, the host's when it says.</summary>
public class HostNamesTests
{
    [Fact]
    public void Todas_names_are_the_defaults()
    {
        GuardOptions options = new();

        Assert.Equal(("toda_session", "toda_csrf", "toda_embedded", "NEXT_LOCALE"),
            (options.Cookies.Session, options.Cookies.Csrf, options.Cookies.Embedded, options.Cookies.Language));
        Assert.Equal(("/signup/verify", "/reset-password", "/emails/verify", "/oauth/consent"),
            (options.Pages.SignUpVerify, options.Pages.PasswordReset, options.Pages.AddressVerify, options.Pages.Consent));
        Assert.Equal((GuardOidc.WebClientId, GuardOidc.MobileClientId), (options.Clients.Web, options.Clients.Mobile));
        Assert.Equal("toda.api", options.ApiScope);
        Assert.Equal(["toda.api", "offline_access"], Services.OAuthAgents.GrantedScopes(options.ApiScope).ToArray());
    }

    [Fact]
    public void A_session_is_read_and_issued_under_the_hosts_cookie_names()
    {
        ServiceProvider services = new ServiceCollection().Configure<GuardOptions>(o => { o.Cookies.Session = "shop_session"; o.Cookies.Csrf = "shop_csrf"; })
            .BuildServiceProvider();
        DefaultHttpContext http = new() { RequestServices = services };
        http.Request.Headers.Cookie = "shop_session=abc";

        Assert.True(WebSessionHandler.Carries(http.Request));
        WebSessionHandler.Issue(http, "secret", embedded: false);
        string[] set = [.. http.Response.Headers.SetCookie.Select(c => c!)];
        Assert.Contains(set, c => c.StartsWith("shop_session=", StringComparison.Ordinal));
        Assert.Contains(set, c => c.StartsWith("shop_csrf=", StringComparison.Ordinal));
        Assert.DoesNotContain(set, c => c.StartsWith("toda_session=", StringComparison.Ordinal));
    }
}
