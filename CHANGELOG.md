# Changelog

All notable changes to Toda Guard are written here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the packages follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html): before 1.0, a minor version may
change the API.

## [Unreleased]

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
- A sign-up's confirmation link confirms that sign-up only: another sign-up for the same address makes earlier links
  stop working. Links mailed before this version don't work; sign up again for a new one.
- Display names with a line break or another control character are refused at sign-up, and when an admin creates an
  account or a service account.

### Fixed

- A sign-in ticket sets up an authenticator app only when the person has no way through the second step; when the site
  sends them codes, the step asks for one.
- A password reset ends the account's sessions everywhere: browsers', the phone's and scripts'.
- Sign-in, step-up and second-step tries are taken before they're checked, so tries sent at once can't exceed the limits;
  a recovery code, an emailed code and an authenticator's step each pass once, however many requests use them together.
- The default messenger writes each header on one line: a name, address or subject with a line break no longer starts
  a header of its own.

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
