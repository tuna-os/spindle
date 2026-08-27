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

The corresponding fragment of MAS's `config.yaml`. MAS requires the
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

Then the usual MAS lifecycle applies: `mas-cli config check`,
`mas-cli database migrate`, `mas-cli config sync`, run the server.
`mas-cli manage register-user` will check the localpart with Spindle
before accepting it, and the account appears in Spindle through the
provisioning surface — no token of the user's ever needs to be seen
first.

## What is deliberately not implemented

- **Suspension.** MAS's locked-but-not-deactivated state has no Spindle
  counterpart; `query_user` always answers `is_suspended: false`, and a
  suspended user's tokens simply stop introspecting as active.
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
configured. If `whoami` answers `M_UNKNOWN_TOKEN` for a token MAS just
issued, check the introspection client credentials first — from the
caller's side, "provider unreachable", "wrong client secret" and
"revoked token" are deliberately the same answer.
