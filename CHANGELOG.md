# Changelog

All notable changes to Toda Guard are written here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the packages follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html): before 1.0, a minor version may
change the API.

## [Unreleased]

### Security

- Setting up an authenticator app with a sign-in ticket is refused when the ticket's second step is a code the site
  sends (email or a channel). Before, a password alone could put in an app of one's own there and pass the step without
  the code.
- A password reset ends what the old password signed in: browser sessions, the phone app's and scripts' sign-ins, and
  personal access tokens (apps a person allowed stay, as when they sign out everywhere). It is in the security log
  as `auth.password.reset`.
- A sign-up's confirmation link works only for the password that sign-up set: signing up again for the same address
  before confirming makes the links mailed before stop working.
- Sign-in, step-up and second-step limits take a try before the password or code is checked, and sending codes takes
  from its limits before a code is made, so requests sent at once can't go past a limit. A wrong password for a merged
  account counts toward the limit as any other.
- A security event keeps at most 256 characters of the username it was given.
- A recovery code, an emailed code, an authenticator's step and a sign-in ticket each pass once, however many requests
  use them together.
- The default messenger writes each header on one line: a name, address or subject with a line break no longer starts
  a header of its own.
- An access token is checked against its entry and its sign-in on every request: revoking it, revoking the app's
  permission, signing out everywhere, a lock or a merge stops it at once, not when its 15 minutes run out.
- With `Features:PersonalTokens` off, no personal access token signs in, those issued before included.
- A merge right short of an admin's lists, reads and resumes only the merges of accounts it may merge; resuming takes a
  step-up.
- CI pins each action by commit SHA, and Dependabot keeps the pins current.

### Changed

- Adding, removing or choosing an account's addresses (`POST /api/guard/accounts/{id}/emails`,
  `DELETE …/emails/{emailId}`, `PUT …/mail-to`) needs the Admin policy; an `update` right on accounts no longer
  reaches them. A person adds their own at `/api/guard/me/emails`, through a mailed link. **Breaking** for a host whose
  roles relied on `update`.
- Merging an account with a right short of an admin's is refused when the merger would be the survivor, or the account
  merged away holds grants or memberships added in Guard.
- Locking, unlocking or resetting the second factors of an account with an administrator's rights needs an
  administrator, whatever the actor's role says (the seeded Directory helpdesk's included).
- Allowing an app at `/connect/authorize` takes the browser's session: any bearer token is refused, the phone's and
  scripts' from the token endpoint too.
- Display names with a line break or another control character are refused at sign-up, and when an admin creates an
  account or a service account.

## [0.1.0-preview.1] - 2026-10-29

Extracted from Toda at 19563f7d, with its history for these paths. The first version as packages on nuget.org:
`Toda.Guard.Contracts`, `Toda.Guard.Acting` and `Toda.Guard`.

### Added

- Directories, accounts (people, service accounts and agents), groups, sign-in with web sessions and OpenIddict,
  OAuth apps, personal access tokens, step-up, two-factor sign-in, self-service sign-up and password reset,
  authorization with CASL .NET, and the security log.
- `GuardOptions` for everything a host sets: addresses and pages (with `{lang}`), cookies, clients, the API scope,
  features, the messenger's folder, the texts and product name, sign-up's default, the seeded names and two-factor.
- `GuardNames` (`Guard:Names`): the names Guard writes into tokens, headers, stored rows and protected data.
- `IServiceAccounts`: service accounts, and their tokens, made from a host's own code.
- Seams with defaults a host may replace: `IGuardMessenger`, `IGuardLocks`, `IGuardRateLimits`, `IGuardEventSink`,
  `IGuardBroadcast`, `IGuardSiteDefaults`, `ISignUpChallenges` and `ITokenRestrictions`.
- `AddGuardKeyRing`, with an optional certificate to encrypt the key ring at rest.
- `samples/Toda.Guard.SampleHost`, a host with the defaults only, and integration tests against PostgreSQL.
