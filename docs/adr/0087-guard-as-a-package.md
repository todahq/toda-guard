# 0087. Guard as a versioned package

- **Status:** Accepted (the user approved the plan on 26 Oct 2026; amends ADR 0001)
- **Date:** 2026-10-26
- **Revisit at:** Guard 1.0, or a second host besides Toda and Toda Marketplace

## Context

ADR 0001 keeps every module in this repository until the SDK 1.0 freeze. It plans to split per module after that.
Guard is the first module another product needs before then. Toda Marketplace needs the same accounts, sign-in,
sessions and second factor, and building them a second time would mean two security codebases to keep right. The rule
is to "go shopping at toda": find what's there, abstract it, package it, reuse it.

Guard is close to that already. Since ADR 0047 step 5, Projects reaches it only through `Toda.Guard.Contracts`, and
an architecture test holds the line. What stands in the way:

- **The contracts lean on Toda.** The events derive from `Toda.Sdk.CatalogEvent`. `RoleKeys` takes its regex timeout
  from `Toda.Sdk.TextPatterns`. `IQueryClocks` returns `Toda.Query.QueryClock`.
- **Guard depends on Toda's platform module.** It uses the acting context, ModuleDb, key storage, cluster locks,
  change notices, site limits, the site calendar, CAPTCHAs, channels and templates, plugin leases, the tool catalog,
  the entity query engine, and the error codes and admin policy.
- **Some of Guard is Toda's, not Guard's.** That covers the RQL lists of accounts and groups, what plugins are offered,
  MCP tool access, people for channels, the platform's rows in a merge, and Toda's own OIDC clients.

## Decision

**Guard owns who someone is and what they may do. The host owns what things are, how people are reached, and its own
runtime.** Guard becomes a set of versioned packages that Toda and Toda Marketplace both consume.

### What is in the package

- **Directories:** the connector SPI, sync, the account projector and internal passwords.
- **Accounts:** service accounts, merges and preferences. Account emails. Merges are the mechanism plus
  `IAccountMergeParticipant`, which each host and module implements for its own tables.
- **Groups:** nesting, group kinds (organizations and email domains included), group and organization imports, and
  customer accounts.
- **Sign-in:** rate limits, test accounts, web sessions with CSRF and the phone handoff, the OpenIddict server, the
  token endpoint and its keys.
- **Apps and tokens:** OAuth apps, consent, dynamic client registration (behind a feature switch), personal access
  tokens and the step-up window.
- **The security log** and its retention.
- **Two-factor:** TOTP, recovery codes, sent codes, group modes.
- **Self-service:** sign-up, verification and password reset.
- **Authorization:** roles, rules, grants, the ability factory and cache with the permission stamp, rule merging, the
  role catalog, Anonymous, the admin policy and the subject registry.

### What stays in Toda

A new `src/Toda.Guard.Integration` holds Toda's side: the RQL controllers for accounts and groups, `QueryClocks`, the
export audit, the platform's merge participant and the plugin bridge (leases, what plugins are offered, directory
connections for connector plugins, `PluginViewers`, the "Plugin" subject, the event catalog). It also holds MCP tool
access, people for channels, message templates and channels, the `toda-web` and `toda-mobile` clients and mobile
discovery, and adapters for site limits, cluster locks, change notices, localization, the site calendar, CAPTCHAs and
key storage.

### Seams

`Toda.Guard.Contracts` stays pure: no ABP, EF Core, OpenIddict, Toda.Sdk or Toda.Query. An architecture test holds
that.

- `GuardEvent` (`EventId`, `OccurredAt`) is the base of Guard's `*Eto` events. Toda's event catalog still finds them
  by the suffix.
- `IQueryClocks` and `IExportAudit` move to Toda's platform. The export audit then takes the person's username rather
  than Guard's `AccountInfo`, since the platform can't see Guard.
- `RoleKeys` keeps its own regex timeout.
- The acting-context contracts move into Guard's contracts: `IActingContext`, `IAbilityLimit`, `AuditTarget`,
  `ISecurityAudit` and `IStepUpPolicy`.

The module gets one seam per host service, each with a `TryAdd` default. Toda replaces them in
`TodaGuardIntegrationModule`:

| Seam | Default | Toda's |
|---|---|---|
| `IGuardEventSink` | ABP's distributed bus, with Guard's outbox | `Toda.Sdk.IEventPublisher` |
| `IGuardMessenger` (kinds `guard.signup-verify`, `guard.password-reset`, `guard.address-verify`, `guard.second-factor-code`) | a pickup folder, in Development | templates and channels |
| `IGuardRateLimits` | table `guard.rate_limits` | site limits |
| `IGuardLocks` | Postgres advisory locks | cluster locks |
| `IGuardBroadcast` | in process | change notices (`web-session`) |
| `IGuardExtensions` | DI | plugin leases |
| `ISignUpChallenges` | none | CAPTCHAs |
| `IGuardSiteDefaults` | `GuardOptions` | the site calendar and languages |
| `ITokenRestrictions` | no tools or resources | the tool catalog and `project:{id}` |

Some host pieces are folded in rather than given a seam:

- ModuleDb becomes `GuardDb`, and key storage is inlined.
- `SqlLike` is copied in, internal.
- The error codes and admin policy kept **the same strings** at first (`Toda:Forbidden`, `step_up_required`,
  `TodaAdmin`); since the Toda rename they are Guard's own (see the amendment below).
- `PersonalAccessToken.ProjectIds` becomes `ResourceIds`, on the same column, so no migration is needed.
- Claim names don't change.

### Packages, schema and configuration

- **Three NuGet packages, one version:**
  - `Toda.Guard.Contracts`
  - `Toda.Guard.Acting`: the acting context, Guard's claims, step-up, and read-only requests
  - `Toda.Guard`: the ABP module, domain, services, controllers, and both DbContexts with their migrations

  The names keep `Toda.` because plugins bind to the host's contract assemblies by name (ADR 0078). There is also an
  npm package, `@todahq/guard-client`, a small framework-free client from the same repository and tag. It covers
  sign-in with its second step, sending a code, setting up the app with a ticket, and recovery codes.
- **The module depends on ABP's MVC and Postgres modules, not on Toda's platform.** It registers its own controllers.
  A switched-off feature's controllers are removed.
- **Schema `guard`.** History tables are `guard.__EFMigrationsHistory` and `guard.__EFMigrationsHistory_oidc`.
  Migrations ship in the package, and the host calls `GuardDatabase.MigrateAsync` and `SeedAsync`. Toda keeps its
  order (Platform, Guard, OIDC, Projects, Assets) under the `startup-migrate` cluster lock. Hosts never add migrations
  to Guard's contexts. Released migrations are never edited. `guard.permission_stamp` and its trigger are a published
  contract. Guard uses the connection string "Guard", and falls back to "Default".
- **Configuration: `GuardOptions`, from the "Guard" section.**
  - `PublicUrl`, `Pages`, `Cookies` (each host names its own), `ApiScope`, `AdminsGroupName` and `Clients`.
  - `Features`: Directories, PersonalTokens, OAuthApps, ClientRegistration, Merges, Handoff, SignUp and TwoFactor.
  - Today's `Guard:*` keys keep working.
  - A host must keep the Data Protection key ring. `AddGuardKeyRing()` keeps it in the database, as Toda does since
    ADR 0050, not on disk.

### Repository, history and publishing

- **One repository:** `todahq/toda-guard` on GitHub (its first release was on GitLab). It keeps the
  app's paths and the house style of the app's packages: a Keep a Changelog CHANGELOG, a release check, Apache-2.0 with
  NOTICE, CONTRIBUTING and SECURITY.
- **CI:** GitHub Actions builds, then runs the unit tests and Postgres integration tests against a sample host that
  uses only the defaults. On a `v*` tag it pushes to nuget.org and makes a GitHub release.
- **Versions:** SemVer, starting at 0.1.0-preview.1. A pre-1.0 minor may break.
- **Restoring in Toda:** package source mapping (`Toda.Guard*` and everything else from nuget.org), with no
  credentials in the repository.
- **History:** Guard's history since its first commit is copied with `git filter-repo` from a fresh clone, never from
  the shared checkout. It is audited for secrets, private hosts and names before anything is pushed.
- **Going public:** the repository becomes public at the cut-over, with a pinned version tagged at the same time. Only
  this project is made public; every other project in the groups stays private.

### Steps in Toda

Each step lands on main with `scripts/ci.sh` green, and Guard's e2e suites pass every time: e2e_accounts,
e2e_sessions, e2e_two_factor, e2e_security, e2e_security_levels and e2e_oauth. Code moves verbatim first; behaviour
changes only in separate commits.

| Step | What |
|---|---|
| S0 | this record |
| S1 | Contracts stripped: `GuardEvent`, `IQueryClocks` and `IExportAudit` to the platform, no Sdk or Query references, an architecture test; plugins that hear Guard's events rebuilt |
| S2 | `Toda.Guard.Integration` made, Toda's pieces moved into it, the server references it |
| S3 | the seams and `GuardOptions`, with Toda's adapters; only after PDPL step 1 has closed |
| S4 | `Toda.Guard.Acting` from the platform's acting folder; architecture tests: Guard references no Toda platform, SDK or query |
| S5 | the sample host and Postgres integration tests |
| S6 | a short freeze on `src/Toda.Guard*`; the history copied, audited, published as 0.1.0-preview.1 and made public |
| S7 | Toda switches to the packages and deletes `src/Toda.Guard*`; the freeze lifts |

After the split, an `TODA_GUARD_CHECKOUT` variable swaps the package references for project references. No props file
is committed or left in the shared checkout for it.

### Personal data (ADR 0082)

- **Step 1 (two-factor) closes with its next green full CI, before S3.** Its code is in `src/Toda.Guard`, and S3
  changes it through the seams:
  - Codes go through `IGuardMessenger` (kind `guard.second-factor-code`). The messenger also says which ways reach a
    person: the methods allowed are the app plus what the messenger reaches.
  - The code's templates get package defaults per language, which Toda overrides.
  - The limits go through `IGuardRateLimits`: five sends a person in 15 minutes, three a sign-in, and ten wrong codes
    in 15 minutes, shared with step-up.
  - `toda-admins` is seeded keyed on `GuardOptions.AdminsGroupName`.
  - TOTP secrets are encrypted with the key ring, so a key ring that isn't kept is a startup check in the package.
  - `scripts/e2e_two_factor.py` stays green at every step.
- **For steps 2 to 11, Guard owns the mechanism and the participant interface.** Each host and module implements a
  participant for its own tables:
  - Personal data: `IPersonalData`, in Guard's contracts beside `IAccountMergeParticipant`.
  - Export: a zip of the participants' parts. Toda runs it as a job, audited through `ISecurityAudit`.
  - Renames: a published `AccountRenamed` event.
  - Anonymising: in Guard, as a two-step admin action with step-up. Holds on a person are Guard's; holds on a project
    are Toda's.
  - Retention: Guard's own sweeps ship in the package.
  - Notice acceptance: a table in `guard`. The host supplies the text and link.
  - Client registration is off by default. The outbound allow-list is Toda's.
  - Security events are Guard events, which Toda turns into notices and its feed.
  - `AddGuardKeyRing` can take a certificate.

  Whoever starts a step says which files first, so it lands before the S6 freeze or in the new repository.

### Amendment, 29 Oct 2026: Toda Guard

The app is now called Toda, and Guard goes public first as Toda Guard (github.com/todahq/toda-guard, NuGet
`Toda.Guard*`). Guard's defaults become Toda's; Toda keeps every name its sites already hold until its own rename:

- **Names in one place:** `GuardNames` (`Guard:Names`) holds what Guard writes into tokens, headers, stored rows and
  protected data: the acting claims, the anti-forgery header and salt, the token, app id and secret prefixes, the app
  properties, the read scope, the second step's grant type, the Data Protection purposes' prefix and the imported
  directories' salt. With `GuardOptions` (cookies, clients, API scope, seeded names, product name) it defaults to
  Toda's.
- **Toda pins its own:** `Toda.Guard.Integration`'s `TodaGuardNames` sets them before Guard reads its settings, and a
  test writes each value out. Toda's rename moves each one with whatever already holds it. The Data Protection
  purposes stay as they are for good, since they guard stored secrets.
- **Changed now, as nothing outside a server holds them:** Guard's error codes (`Toda:Forbidden`,
  `Toda:TooManyRequests`; `step_up_required` is unchanged), the admin policy (`TodaAdmin`) and the authentication
  schemes, and the personal-data schema's id (`urn:toda:guard.personal-data@1`). Toda's own refusals keep
  `Toda:Forbidden` and `Toda:TooManyRequests`, which its status finder maps beside Guard's.
- **Texts name the host:** Guard's messages and status reasons name the product from `Texts.ProductName`, so Toda's
  read as before.

## Consequences

- **ADR 0001 is amended for Guard alone.** Guard leaves this repository before the SDK freeze. The other modules stay
  until then.
- **A plugin that hears Guard's events must be rebuilt after S1.**
  - The cause: an event's `EventId` used to be read through `CatalogEvent`. A plugin built before reads it the old
    way, and the plugin compatibility check can't see that.
  - In Toda's repository, only the LDAP connector hears them. It's a system plugin, and is refreshed when its package
    changes.
  - Guard's events no longer carry `Cause`, which only automation's events use.
- **Plugins keep binding to the host's contracts.** The assembly and namespace stay `Toda.Guard`. A type plugins use,
  such as `IMembershipResolver` or `GuardWellKnown`, doesn't move between assemblies without a plugin version bump.
- **A change to sign-in becomes a release.** Guard's code changes in its own repository and Toda takes a version. The
  dev loop above keeps that to a variable while working. Guard's database rules (migrations, the stamp) are a
  contract for every host.
- **A public security codebase.** Anyone can read how sign-in works, as they can read OpenIddict's. Reports go to
  SECURITY.md's address. The history is audited before it goes public.
- **To watch:**
  - Guard's ABP version against each host's.
  - The static subject registry when two hosts add subjects.
  - Package-registry friction for contributors.
  - The account-columns check once Guard's model snapshots leave `src/` (S7): it must still see `guard.*`.
