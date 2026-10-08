# Delegated authentication (MSC3861): running Spindle behind MAS

Spindle can hand identity to an OAuth 2.0 provider — in practice the
[Matrix Authentication Service](https://github.com/element-hq/matrix-authentication-service)
(MAS), the same provider matrix.org runs in front of Synapse. Delegation
is all-or-nothing by design: when it is on, the provider owns accounts,
sessions and devices, and Spindle's own password login and registration
turn off. One identity provider is the point; two is how accounts drift
apart.

This page is the operator's view. The protocol view — what each side
does and the evidence it works against an unmodified MAS v1.9.0 release
binary — is [evidence/m4-delegated-auth.md](evidence/m4-delegated-auth.md).

If what you want is modern (OIDC-native) login for Element X without
deploying a second service at all, that is not this page: see
[the built-in provider](#the-built-in-provider-modern-login-without-mas)
below.

## What turns on, what turns off

With `[auth.delegated]` configured:

- `GET /_matrix/client/v1/auth_metadata` relays the provider's OIDC
  discovery document, and `/.well-known/matrix/client` names the issuer
  (MSC2965) — this is how Element Web/X find the provider's login page.
- Every bearer token that is not a local session or an appservice
  `as_token` is resolved by **token introspection** against the
  provider, with the verdict cached for 120 seconds. The account and
  device are provisioned on first sight, bound to what the provider's
  scopes say (MSC2967), never to anything the client claims.
- Tokens with `urn:synapse:admin:*` can use the admin API without a
  device scope. Element Admin needs this access. This permission
  stays on the token and does not set the account's permanent `admin`
  flag. A token without a device cannot use device-dependent client
  endpoints. It can still call `/whoami`, read profiles, and read
  media, which is what Element Admin needs to show users and avatars.
  Spindle accepts stable `urn:matrix:client:*` scopes and scope names
  from MSC2967. The `urn:mas:admin` scope alone does not grant access
  to Spindle's admin API.
- Element Admin 0.1.12 sends these requests to the homeserver: the
  room list, room details, members, room deletion (v2) with its
  `scheduled_tasks` status, federation destinations, and the server
  version. It sends all user, session, email, and registration-token
  requests to MAS. `crates/spindle-server/tests/element_admin.rs`
  replays the homeserver requests and checks each response against
  the schema that the console uses.
- The `/_synapse/mas/*` provisioning surface opens (only with
  `homeserver_secret` set, and only to its holder): MAS uses it to
  create users, manage devices, set display names, and deactivate
  accounts. It is the same dialect MAS speaks to Synapse, so an
  unmodified MAS runs Spindle.
- Legacy `GET|POST /login`, `/register` and `/register/available`
  answer 404 `M_UNRECOGNIZED`. The one exception is appservice
  registration (`m.login.application_service`): ghosts are the
  bridge's to mint, delegation or not.

Two consequences worth knowing before you flip it on:

- **Revocation lags by at most 120 seconds.** A token the provider
  revokes keeps working here until its cached introspection verdict
  expires. That window is the price of not putting the provider in
  every request's latency; Synapse ships the same order of magnitude.
- **Deactivation reserves the name forever.** `delete_user` kills every
  session and device but keeps the account row, because a released
  localpart would hand the old user's identity to whoever registers it
  next.

## Spindle's side

```toml
[auth.delegated]
# Where the provider lives; /auth_metadata relays its discovery document.
issuer = "https://auth.example.org/"
# MAS serves introspection at {issuer}/oauth2/introspect.
introspection_endpoint = "https://auth.example.org/oauth2/introspect"
# The client credentials Spindle presents when introspecting — must
# match a client in MAS's `clients:` section.
client_id = "0000000000000000000SP1ND1E"
client_secret = "<introspection-secret>"
# The token MAS presents when calling us (MAS's `matrix.secret`).
# Omit it and the /_synapse/mas/* surface does not exist — but then
# MAS cannot register users or manage devices here, so in practice
# a MAS deployment always sets it.
homeserver_secret = "<matrix-secret>"
```

## MAS's side

The corresponding fragment of MAS's `config.yaml`. MAS needs the
`client_id` to be a ULID (26 characters, Crockford base32) — zero-pad
your way there.

```yaml
matrix:
  kind: synapse            # the homeserver dialect Spindle implements
  homeserver: example.org  # your server_name
  secret: "<matrix-secret>"
  endpoint: "https://matrix.example.org/"   # where Spindle listens

clients:
  - client_id: 0000000000000000000SP1ND1E
    client_auth_method: client_secret_basic
    client_secret: "<introspection-secret>"
```

### In place of Synapse's `matrix_authentication_service`

Element Server Suite sets up Synapse with the stable
`matrix_authentication_service:` section. In that setup, Synapse has no
client of its own at MAS. To introspect, Synapse sends `matrix.secret` as
a bearer token. Spindle does the same when you leave out `client_id` and
`client_secret`. Thus MAS needs no change when Spindle replaces Synapse:

```toml
[auth.delegated]
issuer = "https://auth.example.org/"
introspection_endpoint = "http://mas.internal:8080/oauth2/introspect"
homeserver_secret = "<matrix-secret>"   # MAS's matrix.secret
```

The MAS `matrix.kind` stays `synapse_modern`, and `matrix.endpoint`
changes to Spindle. For a rehearsal of this setup with MAS 1.23 and a
restore of a production MAS database, see
[evidence/mas-cutover-rehearsal.md](evidence/mas-cutover-rehearsal.md).

Then the usual MAS lifecycle applies: `mas-cli config check`,
`mas-cli database migrate`, `mas-cli config sync`, run the server.
`mas-cli manage register-user` will check the localpart with Spindle
before accepting it, and the account appears in Spindle through the
provisioning surface — no token of the user's ever needs to be seen
first.

## What is deliberately not implemented

- **Suspension.** MAS's locked-but-not-deactivated state has no Spindle
  counterpart; `query_user` always answers `is_suspended: false`, and a
  suspended user's tokens stop introspecting as active.
- **Email addresses.** `provision_user` accepts `set_emails` and
  ignores it — there is nowhere to put them, and refusing would fail
  every provision.
- **A UIA gate on cross-signing uploads.** `allow_cross_signing_reset`
  is an acknowledged no-op: the window it asks to open is always open
  here.

## Verifying a deployment

```console
$ curl https://matrix.example.org/_matrix/client/v1/auth_metadata | jq .issuer
"https://auth.example.org/"
$ mas-cli manage issue-compatibility-token alice DEVICE1
$ curl -H "Authorization: Bearer mct_…" \
    https://matrix.example.org/_matrix/client/v3/account/whoami
{"device_id":"DEVICE1","user_id":"@alice:example.org"}
```

If `auth_metadata` answers 404 `M_UNRECOGNIZED`, delegation is not
configured. If `whoami` answers `M_UNKNOWN_TOKEN` for a token that MAS
issued, check the introspection client credentials first — from the
caller's side, "provider unreachable", "wrong client secret" and
"revoked token" are deliberately the same answer.

## The built-in provider: modern login without MAS

MSC3861-native clients — Element X natively, Element Web behind
`feature_oidc_native_flow` — log in through an OAuth 2.0 provider or
not at all. Running MAS buys the full identity stack, but it also
costs a second service and the PostgreSQL it needs, which is a lot
of ceremony for a single-node server whose accounts already live in
Spindle. The other answer:

```toml
[server]
# The issuer; omit it and https://<server.name> is used.
public_base_url = "https://matrix.example.org"

[auth]
builtin_oidc = true
# Optional (#609): an issuer on a host of its own. Omitted, the issuer is
# the client base URL above.
# oidc_issuer = "https://auth.example.org/"
```

`oidc_issuer` exists for replacing a MAS in place. Clients remember the
issuer they logged in against, and MAS lives on its own host; setting
`oidc_issuer` to that host's origin (and pointing the host's reverse proxy
at Spindle) keeps every advertised URL — the discovery document,
`/_matrix/client/v1/auth_metadata` and its MSC2965 unstable alias, the
`/.well-known/matrix/client` authentication block, and each endpoint —
on the issuer the clients already know. It must be an origin: the
provider's routes are served at the root of whichever host reaches
Spindle, so a path would advertise URLs nothing serves, and the server
refuses to start with one.

With that, Spindle itself serves the small provider surface those
clients need — discovery (`/.well-known/openid-configuration`, relayed
by `auth_metadata`), dynamic client registration (RFC 7591), an
authorization page over Spindle's own accounts and passwords, PKCE
`S256` (mandatory — `plain` is refused), token exchange, refresh and
revocation (RFC 7009). Both MSC2967 scope spellings are accepted, the
current `urn:matrix:client:*` and the legacy
`urn:matrix:org.matrix.msc2967.client:*`.

The decisive simplification is that **the tokens it mints are Spindle's
native sessions** — the token endpoint calls the same session machinery
as a password login, so there is no introspection hop, no JWT
machinery, no signing keys to rotate, and nothing new to back up.
Password login and registration stay on: the provider is a second door
into the same accounts, not a second set of accounts.

### Account management (#607)

An OIDC-native client has no account settings of its own, so the provider
serves them, the way MAS does: server-rendered pages (plain HTML forms, no
script) at `{issuer}/account/`, advertised as MSC4191's
`account_management_uri` in the discovery document and `auth_metadata`,
and as `account` in the `/.well-known/matrix/client` authentication block.

| Page | Deep link (`?action=`) | What it does |
|---|---|---|
| Profile | `org.matrix.profile` (and any unknown action) | Display name and avatar (`mxc://`), propagated into every joined room's member event, as `PUT /profile` does. |
| Password | `password` | Change it: current password required; by default also signs out every device and every other browser. |
| Devices | `org.matrix.sessions_list` / `org.matrix.devices_list` | List devices; `org.matrix.session_view` / `org.matrix.device_view` and `org.matrix.session_end` / `org.matrix.device_delete` with `device_id=` show one, with a sign-out button. Signing out removes the device, its tokens and E2EE material and announces the device-list change, as `DELETE /devices/{id}` does. |
| Deactivate | `org.matrix.account_deactivate` | Password plus an explicit confirmation; optionally erases the profile. Leaves every room, then the same deactivation the admin API performs. |
| Cross-signing reset | `org.matrix.cross_signing_reset` | Spindle demands no approval for replacing cross-signing keys, and the page says so rather than inventing a step. |
| Email | `emails` | With `[email]`: confirmed addresses, add (password required, confirmed by a mailed link) and remove. |

The pages sit behind a **browser session**: signing in on the
authorization page or at `/account/login` sets an `HttpOnly`,
`SameSite=Lax` cookie (`Secure` whenever the issuer is https) that lasts a
week. Only its BLAKE3 digest is stored. With it, a second client's
authorization shows "Continue as @you" instead of the password form;
`prompt=login` forces the password.

Security properties, all tested in `tests/account_management.rs`:

- every POST carries a CSRF token compared in constant time — the
  session's own secret once signed in, a double-submit cookie before;
- changing the password, adding an address and deactivating re-check the
  current password; every password check, on every page, spends the same
  per-account (5/min) and per-source (30/min) budget as the client API's
  `/login`, so switching doors gains a guesser nothing;
- pages send `Content-Security-Policy` with `frame-ancestors 'none'`,
  `X-Frame-Options: DENY`, `Cache-Control: no-store` and
  `Referrer-Policy: no-referrer`;
- the post-sign-in redirect (`next`) is only ever a `/account` path on
  this server; the OAuth redirect is only ever a URI the client
  registered, as before.

### Email and password reset (#608)

Configure an SMTP relay with `[email]` (see `spindle.example.toml`:
`from`, `smtp_host`, `tls` = `starttls`|`tls`|`none`, `smtp_port`,
`username`, `password` or `password_file`). Then:

- **Addresses.** On the Email page a user adds an address (with their
  password); a link is mailed to it and the address is bound only when the
  link's confirmation button is pressed — opening the link (as mail
  scanners do) binds nothing. An address belongs to at most one account;
  claiming one that is taken looks exactly like claiming a free one and
  mails nobody. Deactivation releases the account's addresses.
- **Forgotten password.** The sign-in pages link to
  `/account/password/forgot`. Its answer is the same page, status and
  work for every input: the lookup, the token and the mail happen after
  the response, in their own task, so neither the page nor its timing
  says whether an address has an account. The link works once, for an
  hour; only the newest one works; following it and setting a new
  password signs out every device and browser.
- Links carry 256 random bits; only their digests are stored. Requests are
  rate-limited per source (5 per 15 min) and per address (3 per hour,
  whether or not the address is anyone's); confirmation mails per account
  (5 per hour).
- `GET /_matrix/client/v3/account/3pid` lists the confirmed addresses.
  Adding and removing them through the client API (`requestToken` and
  friends) is not served; the account pages are the way. Under
  `[auth.delegated]` the endpoint stays absent, as before.
- Nothing logs an address, a token or a link; delivery failures are
  logged by class (permanent, transient, connection) only.

Metrics for all of this — sign-ins by door and result, token grants,
resets requested and completed, mail sent and failed, account actions —
are in [metrics.md](metrics.md).

### Password recovery without email

`[email]` is optional, and a server without it is not stuck when a user
forgets their password. Two ways back need no mail at all:

- **Recovery codes.** The account pages' *Recovery codes* section
  (`?action=recovery`) generates ten one-time codes behind the current
  password. They are shown once; generating a new set retires the old one.
  The sign-in pages link to *Use a recovery code* (`/account/recover`):
  username, one code and a new password. The code is used up, the password
  set, and every device and browser signed out. Each code is 80 random
  bits, stored as a per-code salt and `BLAKE3(salt ‖ code)` — not Argon2,
  because a slow hash protects guessable human secrets, and an 80-bit random
  code is beyond guessing with any hash, while ten Argon2 runs per attempt
  would hand anyone who can post the form a way to burn CPU and memory.
  Attempts spend the same per-account and per-source budget as a password
  (5 and 30 a minute), and an unknown user and a wrong code get the same
  answer.
- **An administrator's reset link.** `spindle issue-reset-link <config>
  <localpart> [--ttl 24h]` (offline, like `set-password-hash`) or
  `POST /_spindle/admin/v1/users/{user_id}/reset_link` with an optional
  `{"ttl": "2h"}` (the running server's way) returns a URL on the issuer,
  once. Hand it to the user by any channel you trust. It is the same link a
  mailed reset sends: single-use, a day by default and a week at most,
  stored only as a digest, superseded by any newer link, and it opens the
  same *choose a new password* page, which signs every device out. The
  admin API records the issuance and its lifetime in the audit log, never
  the token.

Without `[email]` the sign-in pages show only *Use a recovery code*, and
there is no Email page or forgotten-password form; with it, both ways
appear. Metrics: `spindle_password_recoveries_total{method,result}` and
`spindle_reset_links_issued_total` ([metrics.md](metrics.md)).

### Moving from MAS to the built-in provider

What carries over, and how:

1. **The issuer.** Set `oidc_issuer` to MAS's public origin and point that
   host's reverse proxy at Spindle, so clients' stored issuer and endpoints
   keep resolving (above).
2. **Passwords.** MAS stores Argon2id PHC hashes (`user_passwords`); import
   them with `POST /_spindle/admin/v1/users/{user_id}/password_hash` or the
   offline `spindle set-password-hash` (see [lifecycle.md](lifecycle.md)).
   Both validate the hash and work while authentication is still
   delegated, so hashes can land before the switch. A MAS scheme
   configured with a `secret` (pepper) produces hashes that look ordinary
   and never verify here.
3. **Sessions do not carry over.** MAS's access and refresh tokens are
   MAS's; after the switch, clients sign in again (once — the browser
   session then covers the rest).
4. **Email addresses** are not imported yet: users re-add them on the
   Email page.
5. **Upstream identity providers** (MAS `upstream_oauth2`) are not
   supported; users who only ever signed in through one have no password
   here and need one set: an administrator's reset link (above) is the way,
   with or without mail.

### Upstream identity providers (#610): not yet

Signing in through another OIDC provider is the next step and is not in
this release. The design hook is the authorization page: `authorize` in
`oidc.rs` resolves *who* is signing in (today: a password, or a browser
session) and then mints a code; an upstream provider becomes a third way
to resolve the localpart — a redirect to the upstream with its own PKCE
and state, a callback that validates the ID token and maps the subject to
a localpart (a link table keyed by issuer and subject, beside the
`BrowserSession` and `EmailOwner` keyspaces), and then the same browser
session and code issuance as a password sign-in. Nothing downstream of
the localpart changes.

The proof it works — Element Web completing the whole OIDC-native flow
against a lone Spindle process, with nothing else running — is
[evidence/builtin-oidc.md](evidence/builtin-oidc.md).
