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

## What this does not show

- **A browser login through Element.** The OAuth authorization-code
  flow (MAS's login pages → redirect back to the client) runs entirely
  between the client and MAS; Spindle only ever sees the resulting
  access token, which is exactly what the introspection path above
  exercises. A human-run pass with Element Web against this pair is
  still worth doing before calling the milestone's UX proven.
- **E2EE through a delegated session** — device key upload works (the
  device row exists), but a full cross-signing reset driven from MAS's
  account UI has no test yet; `allow_cross_signing_reset` is an
  acknowledged no-op because Spindle imposes no UIA there.
