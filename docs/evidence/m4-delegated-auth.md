# M4 evidence: an unmodified Matrix Authentication Service runs Spindle

MSC3861's exit criterion is not "the introspection code exists" — it is
that the actual provider people deploy can own identity for this server.
This transcript is a real **MAS v1.9.0 release binary** (PostgreSQL 16
behind it), configured exactly as its own documentation says a Synapse
deployment is configured, driving a debug-build Spindle over TCP — both
directions of the contract at once:

- **outbound** (Spindle → MAS): OAuth 2.0 token introspection with
  client credentials, plus relaying the provider's discovery document
  through `/_matrix/client/v1/auth_metadata`;
- **inbound** (MAS → Spindle): the `/_synapse/mas/*` provisioning
  surface MAS uses to manage accounts and devices on the homeserver it
  owns, guarded by `matrix.secret` / `auth.delegated.homeserver_secret`.

## Setup

MAS's side (`mas-config.yaml`), verbatim where it matters:

```yaml
matrix:
  kind: synapse                    # MAS speaks one homeserver dialect
  homeserver: 127.0.0.1:8008
  secret: <matrix-secret>          # bearer for /_synapse/mas/* calls
  endpoint: http://127.0.0.1:8008/
clients:
  - client_id: 0000000000000000000SP1ND1E
    client_auth_method: client_secret_basic
    client_secret: <introspection-secret>
```

Spindle's side:

```toml
[auth.delegated]
issuer = "http://127.0.0.1:8080/"
introspection_endpoint = "http://127.0.0.1:8080/oauth2/introspect"
client_id = "0000000000000000000SP1ND1E"
client_secret = "<introspection-secret>"
homeserver_secret = "<matrix-secret>"
```

## Transcript (2026-08-27, mas-cli v1.9.0)

**MAS registers a user, through Spindle.** `mas-cli manage
register-user` checks the localpart with Spindle
(`GET /_synapse/mas/is_localpart_available`) before accepting it — the
same command aborted with a connection error when nothing listened on
8008 — then its job queue provisions the account:

```
$ mas-cli manage register-user --display-name "Bob Bridgebuilder" bob …
INFO mas_cli::commands::manage:924 User registered user.id=01M1253NE7H0CYWCD4T40AEFGD

$ curl -H "Authorization: Bearer <matrix-secret>" \
    "http://127.0.0.1:8008/_synapse/mas/query_user?localpart=bob"
{"avatar_url":null,"display_name":"Bob Bridgebuilder","is_deactivated":false,
 "is_suspended":false,"user_id":"@bob:127.0.0.1:8008"}
```

No token of bob's was ever presented to Spindle — the display name can
only have arrived through MAS's `POST /_synapse/mas/provision_user`.

**A MAS-issued token is a Spindle identity.** A compatibility token
minted by MAS, never seen by Spindle before, resolves by introspection
— account and device bound to what the provider says, not to anything
the client claims:

```
$ mas-cli manage issue-compatibility-token alice MASEVIDENCE1
INFO … Compatibility token issued: mct_… compat_session.device=MASEVIDENCE1

$ curl -H "Authorization: Bearer mct_…" \
    http://127.0.0.1:8008/_matrix/client/v3/account/whoami
{"device_id":"MASEVIDENCE1","user_id":"@alice:127.0.0.1:8008"}

$ curl -H "Authorization: Bearer mct_…" \
    http://127.0.0.1:8008/_matrix/client/v3/devices/MASEVIDENCE1
{"device_id":"MASEVIDENCE1","display_name":null}
```

**Discovery is the provider's own document.**
`/_matrix/client/v1/auth_metadata` relays MAS's real metadata —
`authorization_endpoint`, `account_management_uri` and all — which is
what Element Web/X reads to send the user to the provider's login.

**The legacy surface is closed, and garbage buys nothing:**

```
$ curl http://127.0.0.1:8008/_matrix/client/v3/login
{"errcode":"M_UNRECOGNIZED","error":"authentication is delegated to the OIDC provider"}
$ curl -H "Authorization: Bearer mct_forged" …/account/whoami
{"errcode":"M_UNKNOWN_TOKEN","error":"the access token is not valid"}
```

**Revocation propagates, with exactly the documented lag.** A token in
active use keeps working for at most `INTROSPECTION_TTL` (120 s) after
MAS ends the session — the cached verdict — and is then refused:

```
$ curl -H "Authorization: Bearer mct_…3" …/account/whoami
{"device_id":"MASEVIDENCE3","user_id":"@alice:127.0.0.1:8008"}
$ mas-cli manage kill-sessions alice
INFO … Ended 1 active compatibility session
$ curl -H "Authorization: Bearer mct_…3" …/account/whoami   # immediately
{"device_id":"MASEVIDENCE3","user_id":"@alice:127.0.0.1:8008"}
$ sleep 125; curl -H "Authorization: Bearer mct_…3" …/account/whoami
{"errcode":"M_UNKNOWN_TOKEN","error":"the access token is not valid"}
```

## Element Web, through the front door

The milestone's headline exit criterion, run for real: **Element Web
v1.12.26** (release tarball, `feature_oidc_native_flow` enabled) served
at one origin, Spindle at another, MAS at a third, driven by a scripted
browser (Chromium via Playwright) with no test double anywhere:

1. Element discovers the provider through Spindle's MSC2965
   advertisement, registers itself with MAS by dynamic client
   registration, and hands the user to `{issuer}/login` — MAS's own
   page, not Element's.
2. alice signs in with her MAS password, passes MAS's consent screen
   for the newly registered client, and is redirected back.
3. Element lands on `#/home` — *"Welcome @alice:127.0.0.1:8008"* — and
   proceeds to make 41 client-API calls to Spindle with the
   provider-issued token, including E2EE device-key bootstrap (the
   backup prompt appears, meaning key upload against Spindle worked).

Two Spindle bugs and one MAS deployment fact fell out of doing it for
real, which is the argument for doing it for real:

- **Spindle sent no CORS headers.** Every native client and Complement's
  Go client worked; a browser blocked every response. The spec's
  Web Browser Clients section is now implemented (`routes::cors`) and
  pinned by `tests/browser_cors.rs` — Complement can never catch this
  class, since its client sends no `Origin`.
- **Element asks the unstable MSC2965 path first**
  (`/_matrix/client/unstable/org.matrix.msc2965/auth_metadata`); a
  server answering only the stable `/v1/auth_metadata` looks
  undelegated to it. Spindle now serves both.
- MAS's registration policy refuses `http://` client URIs by default;
  the sandbox run needed `policy.data.client_registration.
  allow_insecure_uris: true`. A production deployment on https never
  hits this.

## What this does not show

- **A full cross-signing reset driven from MAS's account UI** —
  `allow_cross_signing_reset` is an acknowledged no-op because Spindle
  imposes no UIA on that upload; the reset flow end-to-end has no test.
