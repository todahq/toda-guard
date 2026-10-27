using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Npgsql;

namespace Toda.Guard.Host.Tests;

/// <summary>
/// Guard hosted alone (ADR 0087), as another product (the marketplace) hosts it: the sample host on a database of its own
/// (ConnectionStrings:Guard), with Guard's defaults only. An admin opens sign-up, a person signs up, confirms the mailed
/// link from the pickup folder, signs in and reads /api/guard/me; a refused input is 400 and a switched-off feature 404;
/// a refusal is JSON whatever the client accepts.
/// Needs Postgres on localhost:55432 (toda/toda), as CI's.
/// </summary>
public sealed partial class GuardAloneTests : IAsyncLifetime
{
    private const string Server = "Host=localhost;Port=55432;Username=toda;Password=toda";
    private const string AdminPassword = "Host-Admin-Pass-1";

    private readonly string _database = "guard_host_" + Guid.NewGuid().ToString("N")[..12];
    private readonly string _mail = Path.Combine(Path.GetTempPath(), "guard-host-mail-" + Guid.NewGuid().ToString("N"));
    private WebApplicationFactory<Program>? _factory;

    public Task InitializeAsync()
    {
        // The host reads its settings as it builds, so they're the process's environment for this test.
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        Environment.SetEnvironmentVariable("ConnectionStrings__Guard", $"{Server};Database={_database}");
        Environment.SetEnvironmentVariable("Guard__Seed__AdminPassword", AdminPassword);
        Environment.SetEnvironmentVariable("Guard__Messenger__PickupFolder", _mail);
        Environment.SetEnvironmentVariable("Guard__Features__Handoff", "true");
        _factory = new WebApplicationFactory<Program>();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }

        NpgsqlConnection.ClearAllPools();
        await using NpgsqlConnection connection = new($"{Server};Database=postgres");
        await connection.OpenAsync();
        await using NpgsqlCommand drop = new($"DROP DATABASE IF EXISTS \"{_database}\" WITH (FORCE)", connection);
        await drop.ExecuteNonQueryAsync();
        if (Directory.Exists(_mail))
        {
            Directory.Delete(_mail, recursive: true);
        }
    }

    [Fact]
    public async Task Someone_signs_up_confirms_signs_in_and_is_known()
    {
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);

        // Sign-up is a site setting, off at first: an admin opens it for the internal directory.
        using HttpRequestMessage open = new(HttpMethod.Put, "/api/guard/signup/settings")
        {
            Content = JsonContent.Create(new { enabled = true, directoryId = "00000000-0000-0000-0000-00000000d001", emailDomains = Array.Empty<string>() }),
        };
        open.Headers.Add("X-Toda-Csrf", csrf);
        Assert.Equal(HttpStatusCode.OK, (await admin.SendAsync(open)).StatusCode);

        // A switched-off feature (the sample has no directories to sync) has no endpoints.
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync("/api/guard/directories")).StatusCode);

        HttpClient visitor = Client();
        HttpResponseMessage refused = await visitor.PostAsJsonAsync("/api/guard/signup", new { email = "dana@example.test", displayName = "Dana", password = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

        HttpResponseMessage signedUp = await visitor.PostAsJsonAsync("/api/guard/signup", new { email = "dana@example.test", displayName = "Dana", password = "Dana-Pass-12345" });
        Assert.Equal(HttpStatusCode.NoContent, signedUp.StatusCode);
        string mail = await File.ReadAllTextAsync(Assert.Single(Directory.GetFiles(_mail, "*.eml")));
        Assert.Contains("To: \"Dana\" <dana@example.test>", mail);
        string token = Token().Match(mail).Groups[1].Value;

        HttpResponseMessage confirmed = await visitor.PostAsJsonAsync("/api/guard/signup/verify", new { token });
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);

        HttpClient dana = Client();
        await SignInAsync(dana, "dana@example.test", "Dana-Pass-12345");
        using JsonDocument me = JsonDocument.Parse(await dana.GetStringAsync("/api/guard/me"));
        Assert.Equal("dana@example.test", me.RootElement.GetProperty("account").GetProperty("username").GetString());
    }

    [Fact]
    public async Task A_refusal_is_json_whatever_the_client_accepts()
    {
        // The web's downloads fetch with Accept: */*; a refusal still answers with its JSON error and status.
        HttpClient admin = Client();
        string csrf = await SignInAsync(admin, "admin", AdminPassword);
        using HttpRequestMessage record = new(HttpMethod.Get, "/api/guard/privacy/record?format=pdf");
        record.Headers.Add("Accept", "*/*");
        await AssertErrorAsync(await admin.SendAsync(record), HttpStatusCode.BadRequest, "bad_format");

        // A personal access token can't step up: the export's refusal (an action with no object result) is 403 JSON.
        using HttpRequestMessage create = new(HttpMethod.Post, "/api/guard/me/tokens")
        {
            Content = JsonContent.Create(new { name = "download", access = "write", projectIds = (Guid[]?)null, days = 7 }),
        };
        create.Headers.Add("X-Toda-Csrf", csrf);
        HttpResponseMessage made = await admin.SendAsync(create);
        Assert.Equal(HttpStatusCode.OK, made.StatusCode);
        using JsonDocument token = JsonDocument.Parse(await made.Content.ReadAsStringAsync());
        HttpClient bearer = Client();
        using HttpRequestMessage export = new(HttpMethod.Post, "/api/guard/me/data-export") { Content = JsonContent.Create(new { }) };
        export.Headers.Add("Accept", "*/*");
        export.Headers.Authorization = new("Bearer", token.RootElement.GetProperty("secret").GetString());
        await AssertErrorAsync(await bearer.SendAsync(export), HttpStatusCode.Forbidden, "Toda:Forbidden");

        // The phone's web view follows redirects: a refused handoff still goes to sign-in, not to a JSON error.
        using HttpRequestMessage handoff = new(HttpMethod.Get, "/api/guard/session/handoff?code=not-a-code&next=/projects");
        handoff.Headers.Add("Accept", "*/*");
        HttpResponseMessage redirected = await Client().SendAsync(handoff);
        Assert.Equal(HttpStatusCode.Redirect, redirected.StatusCode);
        Assert.Equal("/login?next=%2Fprojects", redirected.Headers.Location?.OriginalString);
    }

    private static async Task AssertErrorAsync(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(code, body.RootElement.GetProperty("error").GetProperty("code").GetString());
    }

    private HttpClient Client() => _factory!.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });

    /// <summary>Signs in with the web's session cookie; the anti-forgery value the page would read from toda_csrf.</summary>
    private static async Task<string> SignInAsync(HttpClient client, string username, string password)
    {
        HttpResponseMessage signedIn = await client.PostAsJsonAsync("/api/guard/session", new { username, password });
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        string csrf = signedIn.Headers.GetValues("Set-Cookie").Select(c => Csrf().Match(c)).First(m => m.Success).Groups[1].Value;
        return Uri.UnescapeDataString(csrf);
    }

    [GeneratedRegex(@"token=([A-Za-z0-9_\-%.]+)", RegexOptions.None, 1000)]
    private static partial Regex Token();

    [GeneratedRegex(@"^toda_csrf=([^;]+)", RegexOptions.None, 1000)]
    private static partial Regex Csrf();
}
