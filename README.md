# Toda Guard

Accounts, sign-in and authorization for ABP applications on .NET 10 and PostgreSQL. Guard is the identity module of
Toda, an open-source work management platform, packaged so other products can use the same code instead of writing
their own security.

> **Preview.** 0.x versions may change their API in any minor version (SemVer). Pin an exact version.

## What it does

- **Directories and accounts:** user directories in order of precedence (an internal one with passwords, and a
  connector interface for others such as LDAP), service accounts, account merges, preferences and added email addresses.
- **Groups:** nested groups, organizations and email-domain groups, imports.
- **Sign-in:** web sessions with CSRF protection, rate limits, an OpenIddict server (password, refresh and code grants)
  with its token endpoint, OAuth apps with consent, dynamic client registration, and personal access tokens.
- **Step-up:** sensitive actions ask for the password again within a window; a personal access token never passes.
- **Two-factor sign-in:** authenticator apps (TOTP), recovery codes and codes sent by email or a host's own channels,
  with Off, Optional or Required per group.
- **Self-service:** sign-up with a confirmed email, and password reset.
- **Authorization with [CASL .NET](https://www.nuget.org/packages/Casl.Net):** roles hold rules in CASL's format; grants
  give a role to an account or a group with a scope; the same rules filter queries in SQL and go to the browser.
- **The security log**, kept for a set number of days.

Guard keeps its tables in the `guard` schema of the host's database, or in a database of its own.

## Packages

On [nuget.org](https://www.nuget.org/packages?q=Toda.Guard):

| Package | What it holds |
|---|---|
| `Toda.Guard.Contracts` | The public contracts: lookups, the directory connector interface, account and group events. No ABP, EF Core or OpenIddict. |
| `Toda.Guard.Acting` | The acting context (whose rights a request uses and who acts), step-up, read-only requests, error codes, the names Guard writes. |
| `Toda.Guard` | The ABP module: domain, services, controllers, the EF Core contexts and their migrations. |

## Use it in a host

`samples/Toda.Guard.SampleHost` is a complete host with Guard's defaults only. In short:

```csharp
builder.Host.UseAutofac();
// Guard protects secrets with the Data Protection key ring: keep it in Guard's database so every server reads the same keys.
builder.Services.AddDataProtection().SetApplicationName("my-product").AddGuardKeyRing();
await builder.AddApplicationAsync<MyHostModule>();   // [DependsOn(typeof(TodaGuardModule))]

WebApplication app = builder.Build();
await GuardDatabase.MigrateAsync(app.Services);
await GuardDatabase.SeedAsync(app.Services);
await app.InitializeApplicationAsync();
await app.RunAsync();
```

Configure it in the `Guard` section (`GuardOptions`):

- **Connection:** `ConnectionStrings:Guard` names Guard's database, falling back to `ConnectionStrings:Default`.
- **Addresses:** `PublicUrl` is where people reach the host. `Pages` holds the paths of the pages Guard's mails link to.
  A path may contain `{lang}`, such as `/{lang}/reset-password`. A mailed link puts the recipient's language there, or
  the site's first language when the recipient has none.
- **Names:** `Cookies` holds the cookie names (`toda_session`, `toda_csrf`, `toda_embedded`), `Clients` the OAuth
  clients, and `ApiScope` the scope of your own API (`toda.api`).
- **Stored and wire names:** `Guard:Names` (`GuardNames`) holds what Guard writes into tokens, headers, stored rows and
  protected data: the claims, the anti-forgery header (`X-Toda-Csrf`), the token prefix (`toda_pat_`), the app id and
  secret prefixes, the read scope, the second step's grant type and the Data Protection purposes' prefix. Choose them
  before your first release: changing one later breaks whatever already holds the old one.
- **Features:** `Features` switches whole features off, and their endpoints go with them. These are `Directories`,
  `PersonalTokens`, `OAuthApps`, `ClientRegistration`, `Merges`, `Handoff`, `SignUp`, `TwoFactor` and `DataExport`.
- **Mail:** `Messenger:PickupFolder` gives the default messenger a folder to write mail to. For real delivery, replace
  `IGuardMessenger`.
- **Texts:** `Texts` holds your product's name in Guard's messages (`Texts:ProductName`), or templates of your own.
- **First start:** `SignUp:Open` opens sign-up into the internal directory; it is closed by default, and an admin's
  later choice stays. `Seed` names what the first start makes: the admin's display name and email, the internal
  directory, and the admins and users groups with their descriptions. The admin's password is `Seed:AdminPassword`.
- **Two-factor:** `TwoFactor:Issuer` is the name authenticator apps show. By default it is your product's English name
  and the site's host. Set `TwoFactor:ListsRecovery` to list "recovery" among the second step's methods when the person
  has recovery codes left.
- **Data folder:** `DataRoot` is where Guard looks once for sign-in key files kept on disk, and keeps them when there's
  no database for them. A host can give its own setting instead (`GuardStartupOptions`, through ABP's PreConfigure).

Guard needs ABP's clock in UTC. It sets `AbpClockOptions.Kind` to UTC itself and refuses to start if a host sets
another kind.

`IServiceAccounts` lets your own code make service accounts, and give them tokens, list and revoke them. Your code
decides who may ask. Guard refuses tokens for an agent's account and audits each change as the admin pages do.

`AddGuardKeyRing(certificate)` keeps the Data Protection key ring in Guard's database encrypted by a certificate. Every
server needs the same certificate with its private key.

A host can replace each of Guard's seams with its own service: `IGuardMessenger`, `IGuardLocks`, `IGuardRateLimits`,
`IGuardEventSink`, `IGuardBroadcast`, `IGuardSiteDefaults`, `ISignUpChallenges` and `ITokenRestrictions`. Otherwise
Guard uses its defaults.

Comments in the code cite design records by number, such as "ADR 0087". These are Toda's architecture decision records.
`docs/adr/0087-guard-as-a-package.md` is the one that made Guard a package.

## Build and test

You need the .NET 10 SDK. The integration tests also need PostgreSQL: `localhost:5432` with user and password
`postgres` (the official image's defaults), or the server `GUARD_TEST_POSTGRES` names.

```bash
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17
dotnet build Toda.Guard.slnx -c Release
dotnet test Toda.Guard.slnx -c Release
dotnet pack Toda.Guard.slnx -c Release -o artifacts
```

## Releasing

The version is `VersionPrefix` and `VersionSuffix` in `Directory.Build.props`, and `CHANGELOG.md` needs an entry for
it. Pushing the tag `v<version>`, such as `v0.1.0-preview.1`, runs the checks. GitHub Actions then pushes the packages
to nuget.org and makes a GitHub release.

Publishing uses nuget.org's Trusted Publishing, so no API key is stored anywhere: nuget.org gives the release job a key
that lasts an hour. It needs a Trusted Publishing policy on nuget.org for this repository, the workflow file `ci.yml`
and the environment `release`, and the repository variable `NUGET_USER` set to the nuget.org account that owns the
packages.

## Contributing

Issues and pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md) for
vulnerabilities. CI runs on GitHub Actions for every pull request.

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE).
