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
  provider, with the verdict cached for 120 seconds by default. The account and
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

Three consequences worth knowing before you flip it on:

- **Revocation is immediate when Spindle knows of it.** A logout that
  Spindle serves ends the token at once. So does an admin or client
  call that ends the device or the account. So do the MAS calls
  `delete_device`, `sync_devices` and `delete_user`. Spindle keeps a
  record of a device that it ends. Thus a later introspection does not
  make the device again, until MAS provisions it with `upsert_device`.
- **Other revocations lag by at most 120 seconds.** MAS can revoke a
  token and not tell Spindle. Then the token works until the cached
  result of its introspection expires. Set the window with
  `introspection_cache_ttl_secs`; 0 asks MAS on each request. Spindle
  never trusts a result after the `expires_in` time that MAS gives
  the token. Synapse has the same behavior, with a fixed window of two
  minutes.
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
# Optional: how long a cached introspection result counts, in seconds.
# This bounds only a revocation that MAS does not tell Spindle about.
# introspection_cache_ttl_secs = 120
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
# Optional (#609): an issuer on a host of its own, or under a path.
# Omitted, the issuer is the client base URL above.
# oidc_issuer = "https://auth.example.org/"
```

`oidc_issuer` lets Spindle replace a MAS in place. Clients remember the
issuer they logged in against, and MAS lives on its own host.

Set
`oidc_issuer` to the origin of that host, and point the reverse proxy of
that host at Spindle. Then each advertised URL stays on the issuer that
the clients already know. This covers the discovery document,
`/_matrix/client/v1/auth_metadata` and its MSC2965 unstable alias, the
`/.well-known/matrix/client` authentication block, and each endpoint.

The value can have a path, for example `https://example.org/auth/`. Use
this when a reverse proxy publishes the provider under that path. The
proxy can keep the path or remove it: Spindle answers on both. The links,
forms and redirects of the pages keep the path. The first segment of the
path cannot be a route of the server (`account`, `oauth2`, `upstream`,
or a segment that starts with `_` or `.`). A query, a fragment or
credentials stop the server at startup.

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
serves them, as MAS does. They are server-rendered pages (plain HTML
forms, no script) at `{issuer}/account/`. The discovery document and
`auth_metadata` advertise them as MSC4191's `account_management_uri`. They also
appear as `account` in the `/.well-known/matrix/client` authentication block.

| Page | Deep link (`?action=`) | What it does |
|---|---|---|
| Profile | `org.matrix.profile` (and any unknown action) | Display name and avatar (`mxc://`), propagated into every joined room's member event, as `PUT /profile` does. |
| Password | `password` | Change it: current password required; by default also signs out every device and every other browser. |
| Devices | `org.matrix.sessions_list` / `org.matrix.devices_list` | List devices; `org.matrix.session_view` / `org.matrix.device_view` and `org.matrix.session_end` / `org.matrix.device_delete` with `device_id=` show one, with a sign-out button. Signing out removes the device, its tokens and E2EE material and announces the device-list change, as `DELETE /devices/{id}` does. |
| Deactivate | `org.matrix.account_deactivate` | Password plus an explicit confirmation; optionally erases the profile. Leaves every room, then the same deactivation the admin API performs. |
| Cross-signing reset | `org.matrix.cross_signing_reset` | Spindle demands no approval for replacing cross-signing keys, and the page says so rather than inventing a step. |
| Email | `emails` | With `[email]`: confirmed addresses, add (password required, confirmed by a mailed link) and remove. |

The pages sit behind a **browser session**. A sign-in on the
authorization page or at `/account/login` sets an `HttpOnly`,
`SameSite=Lax` cookie that lasts a week (`Secure` when the issuer is
https). The server keeps only its BLAKE3 digest. With it, a second client's
authorization shows "Continue as @you" instead of the password form;
`prompt=login` forces the password.

Security properties, all tested in `tests/account_management.rs`:

- each POST carries a CSRF token, compared in constant time. After
  sign-in it is the session's own secret; before, a double-submit cookie;
- a password change, a new address and a deactivation each check the
  current password again. Each password check, on each page, spends the
  budget of the client API's `/login`. That is 5/min per account and
  30/min per source. A guesser gets nothing from a change of door;
- pages send `Content-Security-Policy` with `frame-ancestors 'none'`,
  `X-Frame-Options: DENY`, `Cache-Control: no-store` and
  `Referrer-Policy: no-referrer`;
- the redirect after sign-in (`next`) is always a `/account` path on
  this server. The OAuth redirect is always a URI that the client
  registered, as before.

### Email and password reset (#608)

Configure an SMTP relay with `[email]` (see `spindle.example.toml`:
`from`, `smtp_host`, `tls` = `starttls`|`tls`|`none`, `smtp_port`,
`username`, `password` or `password_file`). Then:

- **Addresses.** On the Email page a user adds an address (with their
  password). The server mails a link to it. The address binds only when
  the user pushes the confirmation button of the link. A visit to the link
  (as mail scanners do) binds nothing. An address belongs to one account
  at most. A claim on a taken address looks the same as a claim on a free
  one, and mails nobody. Deactivation releases the account's addresses.
- **Forgotten password.** The sign-in pages link to
  `/account/password/forgot`. Its answer is the same page, status and
  work for each input. The lookup, the token and the mail happen after
  the response, in their own task. Thus the page and its timing do not
  show if an address has an account. The link works once, for an hour.
  Only the newest link works. A user who follows it and sets a new
  password signs out each device and browser.
- Links carry 256 random bits; the server keeps only their digests. The
  server limits requests per source (5 per 15 min). It also limits them
  per address (3 per hour), for an address with no account too. It limits confirmation
  mails per account (5 per hour).
- `GET /_matrix/client/v3/account/3pid` lists the confirmed addresses.
  Under `[auth.delegated]` the endpoint stays absent, as before.
- **The client API flows.** Clients that log in with a password use the
  spec calls, and these work too:
  - `POST /account/password/email/requestToken`, then
    `POST /account/password` with the `m.login.email.identity` stage.
    The client does not need an access token. This is "Forgot password?"
    in Element. All devices and browsers sign out.
  - `POST /account/3pid/email/requestToken`, then `POST /account/3pid/add`
    (with the password). `POST /account/3pid/delete` removes an address.
  - `POST /register/email/requestToken`, then `POST /register` with the
    `m.login.email.identity` stage. Registration shows this stage beside
    `m.login.dummy`, so an address is optional. With
    `require_token`, the server does not show it and refuses the request.

  Each mail has a link to `/account/3pid/validate`, which opens a
  confirmation button. The client continues after the user pushes it.
  A `requestToken` gives a `sid` for each address, but an unknown address
  or an address of another account gets no mail. The limits of the
  forgotten-password page apply. The validation sessions are in memory
  and work once.
- Nothing logs an address, a token or a link. The log records a delivery
  failure only by class (permanent, transient, connection).

[metrics.md](metrics.md) has the metrics for all of this. They count
sign-ins by door and result, token grants, resets requested and completed,
mail sent and failed, and account actions.

### Password recovery without email

`[email]` is optional, and a server without it is not stuck when a user
forgets their password. Two ways back need no mail at all:

- **Recovery codes.** The account pages' *Recovery codes* section
  (`?action=recovery`) makes a set of ten codes, behind the current
  password. Each code works one time. The page shows them once; a new set
  retires the old one. The sign-in pages link to *Use a recovery code*
  (`/account/recover`): username, one code and a new password. This uses up
  the code. The password changes, and each device and browser signs out.
  Each code is 80 random bits. The server keeps a per-code salt and
  `BLAKE3(salt ‖ code)`, not Argon2. A slow hash is for secrets that a
  person can guess. With any hash, a person cannot guess 80 random bits.
  And ten Argon2 runs per try would let anyone who can post the form burn
  CPU and memory. Tries spend the same per-account and per-source budget
  as a password (5 and 30 a minute). An unknown user and a wrong code get
  the same answer.
- **An administrator's reset link.** Two commands return a URL on the
  issuer, once. `spindle issue-reset-link <config> <localpart> [--ttl 24h]`
  works offline, like `set-password-hash`. For a live server, use
  `POST /_spindle/admin/v1/users/{user_id}/reset_link` with an optional
  `{"ttl": "2h"}`. Give the URL to the user by a channel you trust. It is the same link
  that a mailed reset sends. It works one time, for a day by default and
  a week at most. The server keeps only its digest, and a newer link
  replaces it. It opens the same *choose a new password* page, which signs
  each device out. The
  admin API records the issuance and its lifetime in the audit log, never
  the token.

Without `[email]` the sign-in pages show only *Use a recovery code*, and
there is no Email page or forgotten-password form; with it, both ways
appear. Metrics: `spindle_password_recoveries_total{method,result}` and
`spindle_reset_links_issued_total` ([metrics.md](metrics.md)).

### Moving from MAS to the built-in provider (#797)

Spindle can replace MAS. The accounts are already in Spindle, because
MAS provisions them. The command `spindle import-mas` copies the rest
from the MAS database:

| From MAS | Into Spindle |
|---|---|
| `users` | An account for each user that Spindle does not have. |
| `user_passwords`, the newest row of each user | The password hash, with the MAS scheme that made it. |
| `user_emails` | The addresses, as confirmed addresses. |
| `upstream_oauth_links` | The account links of `[[auth.upstream_oidc]]`. |
| `can_request_admin` | The `admin` flag. |
| `locked_at` | The `locked` flag. |
| `deactivated_at` | A new account that is deactivated. |

Sessions do not move. The access and refresh tokens of MAS stay in MAS.

#### Password schemes

MAS hashes a password with a scheme from `passwords.schemes` in its
`config.yaml`. Give that file to the importer with `--mas-config`. Then
each password works in Spindle as it did in MAS:

- Argon2id hashes, the MAS default.
- bcrypt hashes. MAS keeps them for the users that syn2mas moved from
  Synapse.
- A scheme with a `secret` (pepper). The importer reads the secret from
  `secret` or `secret_file`. Spindle keeps a copy with each account, because
  the hash cannot verify without it. The copy stays until the user sets a new
  password.
- A scheme with `unicode_normalization`. Spindle normalizes the password
  (NFKC) before it checks it.

Without `--mas-config`, the importer uses the default of MAS: version 1,
Argon2id, no secret. It refuses a hash of a version that it does not know.
It also refuses PBKDF2 hashes. Give those users a reset link.

#### The cutover

1. Stop Spindle. The importer opens the store, and the store has a lock.
2. Write the new configuration. Remove `[auth.delegated]`. Set
   `builtin_oidc = true`. Set `oidc_issuer` to the public origin of MAS,
   and point the reverse proxy of that host at Spindle. Then each client
   finds its issuer and its endpoints at the same URLs. Add each MAS
   upstream provider as `[[auth.upstream_oidc]]` (below). Use the ULID of
   the provider in MAS as `id`. Then the callback URL at the provider and
   the links stay the same.
3. Do a dry run. It reads everything and writes nothing:

   ```console
   $ SPINDLE_MAS_DB_PASSWORD=… spindle import-mas spindle.toml \
       --mas-database "host=mas-db user=mas dbname=mas" \
       --mas-config mas-config.yaml --dry-run
   ```

   The report is JSON on stdout. It has counts for users, passwords,
   addresses and links. `refused` lists what the import cannot take,
   with the reason. `kept` lists each account that keeps its state in
   Spindle.
4. Run the same command without `--dry-run`. Then start Spindle.
5. Clients sign in again, one time. After that, the browser session
   signs in the next clients.

You can run the import again. It changes only what changed in MAS. It
does not replace a password that the user changed in Spindle after the
last import. It does not unlock or reactivate an account, and it does not
remove an admin flag.

The command exits non-zero when `refused` is not empty. These are the
usual reasons:

- The username is not a valid localpart in Spindle.
- An address or an upstream identity belongs to another account in
  Spindle.
- No `[[auth.upstream_oidc]]` has the ULID of the provider.
- MAS deactivated a user that is active in Spindle. The importer locks
  the account. When Spindle runs again, deactivate the account with
  `POST /_spindle/admin/v1/users/{user_id}/deactivate`. Only the server
  can do a full deactivation: it removes the devices and tells other
  servers.

**Rollback.** The import does not change MAS. To go back, put back the
old configuration with `[auth.delegated]` and start Spindle. MAS then
signs users in as before. The accounts, addresses and links that the
import wrote stay in the store, and delegation does not use them.

The importer is only in builds with the `mas-import` feature, as
`synapse-import` is for Synapse. The release binary and image do not have
it. Use `cargo build --features mas-import`, or
`docker build --build-arg FEATURES=mas-import .` for an image. The
importer connects to PostgreSQL without TLS. Use a private network or a
port forward.

For one account, `spindle set-password-hash` and
`POST /_spindle/admin/v1/users/{user_id}/password_hash` store a hash
without a scheme (see [lifecycle.md](lifecycle.md)).

### Upstream identity providers (#610)

Sign-in can go to another OIDC provider (Authelia, Keycloak, Kanidm).
The issuer that clients know stays the issuer of Spindle.
`spindle.example.toml` shows each key of `[[auth.upstream_oidc]]`.
Register `{issuer}/upstream/callback/{id}` as the redirect URI at the
provider. The server does not start if `[auth.delegated]` is also set.
The issuer must use https, but Spindle accepts plain http on loopback, or
with `insecure_http = true` for a test rig.

- The sign-in pages show a "Sign in with …" button for each provider.
  `GET /login` shows `m.login.sso` with the providers, and
  `/login/sso/redirect` and `/login/sso/redirect/{idpId}` start the flow.
- The flow is the authorization code flow with PKCE `S256`, a `state`
  and a `nonce`. The server keeps no flow. It seals each flow into the
  cookie that binds it to the browser (ChaCha20-Poly1305, with a key per
  process). Thus open flows use no memory on the server. A flow works
  once and stops after ten minutes.
- A failed callback spends the login budget of its source (30 a minute).
  A successful callback resets it.
- Spindle reads the discovery document and the JWKS at first use and
  keeps them for an hour. Spindle checks the signature of the ID token
  (RS256, PS256, ES256, ES384 or EdDSA). It also checks the issuer, the
  audience, the expiry time and the nonce of the flow.
- The link table (keyspace `0x49`) maps the provider `id` and the `sub`
  to an account. A second sign-in uses the link, not the name.
- A first sign-in makes an account from `localpart_claim`. It sets the
  display name. It also binds the `email` claim if `email_verified` is
  true, because that flag applies to that claim only. Spindle refuses
  addresses with characters that are not ASCII: in Unicode, two different
  addresses can become equal in lowercase. If an account has that
  name, the sign-in fails: Spindle does not give an existing account to a
  new identity. With `link_existing_by_email`, a verified address that an
  account here holds links to that account. This is off by default.
- For the client API, the callback shows a page with a link back to the
  client. The link has a single-use login token for `m.login.token`.

The metric `spindle_auth_logins_total{method="upstream"}` counts each
callback by result.

The proof it works — Element Web completing the whole OIDC-native flow
against a lone Spindle process, with nothing else running — is
[evidence/builtin-oidc.md](evidence/builtin-oidc.md).
