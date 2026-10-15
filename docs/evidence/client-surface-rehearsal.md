# Client-surface rehearsal: what reilly.asia clients use, against a dark Spindle

This page is the evidence for the client-surface gate of #563. The rig is
`scripts/migration-mas-rig`, with the dark MAS and dark Spindle from
[mas-cutover-rehearsal.md](mas-cutover-rehearsal.md). The binary is main
at #567, which includes #565 and #566.

## What production clients use (read-only inventory, 2026-10-03)

- **Element X** (Android) is the active client in the production HAProxy
  log. It syncs with MSC4186 at
  `/_matrix/client/unstable/org.matrix.simplified_msc3575/sync`. A
  separate Synapse worker serves that path. It also calls `/context`,
  `/messages`, `/threads`, receipts, `/pushers/set`, authenticated media
  and the MSC2965 `auth_metadata`.
- **The MAS database** also shows sessions for Element Web
  (`app.element.io`, `develop.element.io`, `element.reilly.asia`),
  Fractal, SchildiChat Next and Element Admin.
- **Synapse** advertises `org.matrix.simplified_msc3575`,
  `org.matrix.msc4108` (QR login), `msc4028`, `msc4140`, `msc4143` and
  `msc4222`.
- **Element Call**: the well-known names `https://call.reilly.asia` as
  the LiveKit transport.
  - Behind it are lk-jwt-service 0.6.0 and LiveKit 1.13.5.
  - The SFU does not make rooms itself (`auto_create: false`).
  - The ingress sends three paths to lk-jwt-service: `/sfu/get`,
    `/get_token` and `/delegate_delayed_leave`.
- There are no appservices or bridges. HAProxy serves the well-known
  documents as static files.

## Results

### Element X sync stack (matrix-sdk 0.18, `ssprobe`)

`ssprobe` builds a client the same way Element X does: with
`DiscoverNative`, a session from a MAS token (stable scopes),
`SyncService`, the room list, and the event cache. It then uses the
recovery key and reads each timeline. Result for rig user b, who can read
all four rooms:

| Check | Result |
|---|---|
| `/versions` has `org.matrix.simplified_msc3575` | pass (fails before #565) |
| `DiscoverNative` accepts the server | pass (fails before #565) |
| Synapse sliding sync `pos` gets `M_UNKNOWN_POS` | pass |
| Synapse `/sync` `since` gets an initial sync | pass |
| Room list shows the 4 rig rooms | pass |
| `SyncService` stays `Running` | pass |
| Recovery with the recovery key | pass |
| Timelines: dm, group, plain, v10 | all events decrypted, 0 UTD |
| Send, then the remote echo arrives through sliding sync | pass |

For users a and c, the room list, recovery and sends pass. The only UTDs
are events that c could not read (from the manifest), and messages that
earlier probe devices sent. Those devices had no key backup.

### Element Web (v1.12.28)

Element Web signs in through the MAS pages for a, b and c, then uses the
recovery key. It decrypts 81/81, 81/81 and 56/56 events.

### Element Call and MatrixRTC (`rtc_check.py`, 12/12)

- `/versions` has MSC4140, MSC4143 and MSC4354.
- With a MAS session, `openid/request_token` returns a token for
  `reilly.asia`. lk-jwt-service exchanges this token.
- `/rtc/transports` answers.
- A delayed leave, the live `call.member`, then 4 restarts with no token
  across 16 s (the delay is 8 s): the membership stays. A send with no
  token clears the membership. A second send gets 404. This is the
  lk-jwt-service `/delegate_delayed_leave` sequence, which fails before
  #566.
- Element Call's own Playwright suite, with lk-jwt-service and LiveKit,
  passes on main every night (`element-call-e2e`).

The dark Spindle does not federate. Thus this rig cannot show
lk-jwt-service redeeming the OpenID token through
`/_matrix/federation/v1/openid/userinfo`. The nightly `element-call-e2e`
job covers that path.

## Settings for production

- `[rtc] foci = [{ type = "livekit", livekit_service_url = "https://call.reilly.asia" }]`
  replaces the Synapse `matrix_rtc.transports` setting.
- Keep lk-jwt-service. The built-in `[rtc.livekit]` service leaves room
  creation to LiveKit, and this SFU has `auto_create: false`.
- lk-jwt-service must reach the Spindle federation listener (for
  `openid/userinfo`) and the client listener (for the delayed-event
  actions).

## Open items

#568 lists the gaps that remain:

- `/messages` with `dir=f`.
- Synapse `prev_batch` tokens in client caches.
- MSC4108 QR login.
- Element Admin.
