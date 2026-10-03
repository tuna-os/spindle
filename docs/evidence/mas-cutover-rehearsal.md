# MAS cutover rehearsal: production MAS data in front of a dark Spindle

This page is the evidence for the delegated-auth gate of #563. In that
migration, reilly.asia moves from Synapse to Spindle, and its Matrix
Authentication Service (MAS) stays in place. To pass, sessions that MAS
issued before the cutover must still work. MAS must also still reach the
homeserver to provision accounts and devices.

## What production runs (2026-10-03, read-only inventory)

- MAS **1.23.0**, with `matrix.kind: synapse_modern`. It has **no
  `clients:` entry for the homeserver**.
- Synapse v1.156.0 uses the stable `matrix_authentication_service:`
  section. It sends `matrix.secret` as a bearer token to introspect, and
  has no client credentials.
- MAS has no upstream OIDC providers.
- The ingress sends the legacy `/login`, `/logout` and `/refresh` paths
  to the MAS compat layer, not to Synapse.
- The 2026-10-03 `mas.dump` holds 5 users and 21 active user OAuth 2.0
  sessions, plus 3 admin client-credential sessions:
  - The clients are Element Web, Element X, Fractal, SchildiChat Next
    and Element Admin.
  - 19 sessions have the unstable MSC2967 scopes. 1 session has the
    stable `urn:matrix:client:*` scopes.
  - The Element Admin session has `urn:synapse:admin:*` and no device.
  - 2 compat sessions are active.
  - Some device IDs contain `+` and `/` (Fractal).

## The rig

The rig is in the `spindle-rehearsal` namespace. It has the same
isolation layers as the #558 rig.

- **Dark MAS**: MAS 1.23.0 on `mas_dark`, a restore of the production
  `mas.dump`.
  - It has new secrets. No production key or encryption secret is in it.
  - The email transport is `blackhole`. It has no upstream providers.
  - It has one admin client of its own. The rig drives the admin API
    with it.
  - `dnsPolicy: None`, peers through `hostAliases`, a ClusterIP Service
    only, and a netwatch sidecar.
- **Dark Spindle**: `[federation] enabled = false`, with the #558 rig
  rooms and users from `synapse_dark`. The isolation is the same as for
  the dark MAS.
  - `[auth.delegated]` has **only `homeserver_secret`**, as Synapse does.
    It has no client ID or client secret.
- **Netwatch** recorded **0** outbound sockets from the two pods for the
  full run.

The rig made test sessions only for rig users (`spindle-mig-*` and
`spindle-mas-*`). It made no session for a real user.

## Results

**All 29 checks of the MAS gate script pass.**

- **Discovery.** Spindle serves the MAS metadata on `/v1/auth_metadata`
  and on the unstable MSC2965 path. Spindle answers legacy `/login` with
  404 `M_UNRECOGNIZED`, because that path belongs to MAS.
- **MAS sessions.** The MAS admin API makes personal sessions with the
  stable scopes (`urn:matrix:client:api:*`) and with the unstable
  scopes. For each, Spindle finds the correct user and device:
  - The device shows in `/devices`.
  - The token can read the key backup from the import.
  - MAS 1.23 sends the two scope spellings in each introspection answer.
- **Compat sessions.** A password login on the MAS compat `/login` gives
  an `mct_` token, and Spindle accepts it:
  - MAS sends the device and its display name to Spindle.
  - After the compat `/logout`, Spindle refuses the token within the
    120 s cache time. The MAS device sync then deletes the device.
- **Account management** through the `/_synapse/mas/*` surface
  (`synapse_modern`):
  - To register a user, MAS first checks the localpart with Spindle.
    Then `provision_user` makes the account.
  - For a deactivation in the MAS admin API, MAS calls `delete_user`. Spindle
    then shows the user as deactivated. Reactivation calls
    `reactivate_user`.
  - `sync_devices` sets the Spindle devices to the MAS set.
- **Revocation.** After MAS revokes a session, Spindle refuses its token
  within the cache time.
- **Element Web v1.12.28 through the MAS login page, for the three rig
  users.**
  - Element finds MAS through the Spindle `auth_metadata` and registers
    itself with MAS.
  - The user signs in on the MAS page and gives consent ("Continue to
    Element? … with your reilly.asia account").
  - Element then uses the recovery key and decrypts the imported history:
    a 81/81, b 81/81, c 56/56.

## What this means for the cutover

- MAS keeps `kind: synapse_modern` and its secret. Only
  `matrix.endpoint` changes, from Synapse to Spindle.
- The Spindle `[auth.delegated]` section needs `issuer`,
  `introspection_endpoint` and `homeserver_secret`, which is the MAS
  `matrix.secret`. MAS needs no new client.
- The ingress continues to send `/login`, `/logout` and `/refresh` to
  MAS.
- Sessions that exist do not change, because MAS answers for its tokens.

## Not covered here

- **Element Admin.** Its session has no device scope, and it calls the
  Synapse admin API. Spindle refuses a token with no device, and it
  serves only part of that API.
- **MSC4108 QR-code login.** Synapse has it on. Spindle does not have it.
