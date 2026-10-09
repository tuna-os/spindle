# MatrixRTC: deploying calls end to end

What a call needs from a deployment, in the order a client asks for it,
and the two ways to provide the piece this server does not carry: the
media. Both are supported; ADR 0004 records why both exist.

## The pieces

A MatrixRTC call (Element Call, Element X, Element Web) touches four
things:

1. **The homeserver** — room state for the call membership, delayed
   events (MSC4140) to expire it, sticky events (MSC4354) so a
   membership can lapse without becoming permanent state, to-device
   signalling, and transport discovery (MSC4143). All served here;
   docs/dashboard.md's M7 row is the inventory.
2. **A LiveKit SFU** — carries the media. Not bundled (#4 lists media
   servers under what not to build); run
   [livekit-server](https://github.com/livekit/livekit).
3. **A JWT service** — mints the token a client presents to the SFU.
   Either the built-in one (`[rtc.livekit]`) or
   [lk-jwt-service](https://github.com/element-hq/lk-jwt-service)
   deployed beside this server.
4. **A TURN relay**, optionally, for the client-side leg that cannot
   reach the SFU directly. `[turn]` in `spindle.example.toml`; not
   MatrixRTC-specific.

The flow a client drives, once it is in a room and has decided to call:

```text
client ──GET /_matrix/client/v1/rtc/transports──▶ homeserver
       ◀── [{type: livekit, livekit_service_url: S}] ──

client ──POST /user/{me}/openid/request_token──▶ homeserver
       ◀── {access_token, matrix_server_name, expires_in} ──

client ──POST S/sfu/get {room, openid_token, device_id}──▶ JWT service
                                                      │
                          (external service only)     ├─GET /_matrix/federation/v1/openid/userinfo─▶ homeserver
                                                      │◀────────────── {sub: @me:server} ───────────
       ◀────────────────── {url: wss://sfu, jwt} ─────┘

client ──websocket, jwt──▶ SFU
```

The OpenID token is the credential in that exchange. It is short-lived
(an hour), it opens nothing on this server, and the JWT service — built
in or external — is what it is for.

## Option A: the built-in JWT service

One binary, one secret to keep in step with the SFU.

```toml
[server]
name = "example.org"
public_base_url = "https://matrix.example.org"

[rtc.livekit]
url = "wss://livekit.example.org"
key = "APIxxxxxxxx"
secret = "..."          # the SFU's matching API secret
# token_ttl_seconds = 900
```

`key` and `secret` are the pair the SFU was started with (`--keys
APIxxxxxxxx: ...`, or `keys:` in `livekit.yaml`). With the section set,
this server:

- advertises itself as a `livekit` transport, first in the list, at
  `https://matrix.example.org/_spindle/rtc/livekit` — on
  `/rtc/transports` and in `.well-known/matrix/client` alike;
- answers `POST /_spindle/rtc/livekit/sfu/get` with `{url, jwt}` in
  `lk-jwt-service`'s shape, so a client cannot tell the two apart;
- mints only for a Matrix room the user is **joined to at that moment**,
  checked against its own membership index. Never joined, only invited,
  or since left: refused with `M_FORBIDDEN`, and a room that does not
  exist is refused identically;
- mints for its own users only. A token whose `matrix_server_name` is
  another server is refused rather than verified over federation;
- rate limits minting per user (docs/rate-limits.md).

The token's grants are the least a participant needs: join this one
room, publish, subscribe. `roomCreate` is withheld because in LiveKit it
also permits deleting the room, which ends everyone's call; the SFU's
default `auto_create: true` makes the room on first join instead. If
your SFU has `auto_create` off, use option B or create rooms another
way.

**Revocation.** A minted token cannot be revoked: it is stateless, and
the SFU never asks this server again. A user who leaves the room after
minting holds their token until it expires. `token_ttl_seconds` is the
whole of that guarantee, which is why it defaults to fifteen minutes and
why the default is not an hour. `lk-jwt-service` issues an hour; a
client that needs that gets it by setting `3600` here, on purpose.

The secret is LiveKit's and is shared with nothing else. It is not this
server's signing key and is not derived from it; the two rotate apart,
and a leak of one is not a leak of the other. It is never logged.

## Option B: lk-jwt-service beside the server

The reference shape, and what Element and Tuwunel document. Run
`lk-jwt-service` with the SFU's key and secret, put it behind your
reverse proxy at some public path, and name that path here:

```toml
[server]
name = "example.org"
public_base_url = "https://matrix.example.org"

[rtc]
foci = [
    { type = "livekit", livekit_service_url = "https://matrix-rtc.example.org/livekit/jwt" },
]
```

The service redeems each OpenID token against this server's
`GET /_matrix/federation/v1/openid/userinfo`, resolved through
`.well-known/matrix/server` like any federation request, so the
federation listener has to be reachable from wherever the service runs.
Nothing else on this server is involved: the service mints for whatever
room the client names, with no membership check on this side.

Recent `lk-jwt-service` releases (0.6 and later; Element Server Suite
ships 0.6.0) also take over a client's delayed leave event when the
client asks (`/delegate_delayed_leave`, or a `delay_id` on `/get_token`):
while the participant stays connected to the SFU the service restarts the
delay, and when they drop it sends it. It does that with
`POST /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/{restart|send}`
and no access token, the delay ID being the capability, so that route has
to reach this server from wherever the service runs, like `openid/userinfo`.

**Delegation lengthens the leave, so the webhook matters.** Element Call
asks the transport (`POST {livekit_service_url}/delegate_delayed_leave`,
unauthenticated) whether it can hold the leave; any answer but a 404 is a
yes, and Element Call then schedules its leave an **hour** out instead of
eighteen seconds and stops restarting it every four. From then on the only
thing that removes a participant whose browser died is `lk-jwt-service`
noticing them leave the SFU -- which it learns from LiveKit's webhooks
(`webhook.urls` in `livekit.yaml` pointing at the service's
`/sfu_webhook`, `webhook.api_key` equal to the service's `LIVEKIT_KEY`), or,
as a fallback, from `LIVEKIT_SANITY_CHECK_INTERVAL_SECONDS`. A deployment
that serves `/delegate_delayed_leave` but whose SFU cannot reach
`/sfu_webhook` leaves crashed participants in the call for up to an hour.

Releases from 0.7 drop the token-less calls: the service runs as an
application service (option C) and calls the same endpoint authenticated
as the user. And they treat a 409 from it as final; this server answers
409 only on the stable `/_matrix/client/v1/delayed_events/{id}/{action}`
and keeps the 404 on the unstable paths, which is what older releases and
the matrix-js-sdk in shipping Element Call were built against (a 409 is a
retry loop for the first and an unrecoverable error for the second).

The two options compose. With both configured, the built-in service is
listed first and the operator's `foci` follow in the order written;
clients read the list as a priority order.

## Option C: lk-jwt-service as the homeserver's sidecar

From 0.7, `lk-jwt-service` is built to sit behind the homeserver as an
application service rather than beside it as a web service, and Element
Call's own test rig runs it that way. The homeserver answers MSC4195's
endpoints by forwarding them (MSC4512): the client's request under
`/_matrix/client/…/rtc/livekit/` is authenticated as usual and handed to
the service with the service's `hs_token` and the caller's user ID in
`X-Matrix-User-Identifier`; the federation twin, under
`/_matrix/federation/…/rtc/livekit/`, is checked against its X-Matrix
signature and handed over with `X-Matrix-Origin`. The service asks this
server whether the caller is in the room (`/rooms/{id}/is_joined`,
MSC4502) instead of trusting the client, and sends its own federation
requests through `fed_proxy`, signed as this server. And because Element
Call's delegation probe now goes to the homeserver path, this is the shape
in which the homeserver itself can hold a delayed leave.

The registration, as `lk-jwt-service`'s README writes it:

```yaml
id: "LiveKit JWT service"
as_token: "<snip>"
hs_token: "<snip>"
sender_localpart: "_lk_jwt_service"
namespaces:
  users:
    - exclusive: false
      regex: ".*"        # it checks membership and acts for every local user
url: null                # no event traffic
io.element.msc4502.scopes: [ "urn:matrix:client:io.element.msc4502:rooms:is_joined" ]
io.element.msc4512.proxy_prefix: "rtc/livekit"
io.element.msc4512.proxy_url: "http://127.0.0.1:8080"
```

```toml
[appservices]
registrations = ["/etc/spindle/lk-jwt-service.yaml"]
```

with the service started with `LIVEKIT_AS_REGISTRATION_FILE` pointing at
the same file and `LIVEKIT_HS_SERVER_NAME` set to this server's name.
`proxy_prefix` and `proxy_url` go together or not at all, and two services
may not claim overlapping prefixes; either mistake stops the server at
startup rather than half-routing calls. `is_joined` answers only services
granted the scope, and server admins. Advertise the transport as the
service's public URL in `[rtc] foci`, as in option B; the homeserver path
is what Element Call probes and what clients post to once they move to
MSC4195's homeserver endpoint.

`crates/spindle-server/tests/appservice_proxy.rs` pins the forwarding,
the authentication on both APIs, the scope, and `fed_proxy`'s confinement
to the service's prefix.

## What to check

- `curl https://matrix.example.org/.well-known/matrix/client` names
  the transport under `org.matrix.msc4143.rtc_foci`. If it does not,
  neither `[rtc.livekit]` nor `[rtc] foci` is set.
- `GET /_matrix/client/versions` lists `org.matrix.msc4140`,
  `org.matrix.msc4143` and `org.matrix.msc4354` under
  `unstable_features`; Element Call checks them before it will rely on
  the server. `GET /_matrix/client/v3/capabilities` names both delayed-
  event limits under `m.delayed_events` (and the unstable
  `org.matrix.msc4140.delayed_events`), from `[delayed_events]`.
- `curl -X POST https://matrix.example.org/_matrix/client/unstable/io.element.msc4195/rtc/livekit/delegate_delayed_leave`
  is a 404 unless option C is configured, and a 401 when it is. Element
  Call reads anything but a 404 as "this homeserver holds my leave".
- A send with `?org.matrix.msc4354.sticky_duration_ms=30000` comes back
  from `GET .../event/{id}` carrying `msc4354_sticky.duration_ms`, and a
  client that joins the room afterwards finds it under
  `rooms.join.{room}.msc4354_sticky.events` in its first `/sync`, with
  `unsigned.msc4354_sticky_duration_ttl_ms` counting down. Durations
  above an hour are capped to it.
- For option A: a joined user's `POST .../sfu/get` returns a `jwt` whose
  decoded `video.room` is the Matrix room ID and whose `exp - nbf` is
  `token_ttl_seconds`. A user who has left gets `403 M_FORBIDDEN`.
- For option B: `GET /_matrix/federation/v1/openid/userinfo?access_token=…`
  with a fresh token returns `{"sub": "@you:example.org"}`; with an
  expired or invented one, `401 M_UNKNOWN_TOKEN`.

The tests that pin each of these: `crates/spindle-server/tests/openid.rs`,
`livekit_jwt.rs`, `rtc_transports.rs`, `rtc_membership.rs`,
`delayed_events.rs`, `delayed_events_merged.rs`, `appservice_proxy.rs`
and `sticky_events.rs`.

## Running Element Call's own suite

`contrib/element-call/run.sh` stands up Element Call's two-homeserver
Playwright stack (LiveKit, lk-jwt-service, Element Web, nginx, all
upstream's and pinned) with Spindle in both of Synapse's seats, and runs
their specs against it. `docker-compose-spindle.yml` is the whole
override; `spindle.toml` and `spindle-othersite.toml` stand in for
`backend/playwright_homeserver*.yaml`. Results go through
`scripts/element-call-check.py` against `contrib/element-call/allowlist.txt`,
the same ratchet shape as Complement's. The `element-call-e2e` job in
`.github/workflows/compliance.yml` runs it nightly and on demand.

Beside upstream's specs run this server's own, in
`contrib/element-call/specs/` (copied into the checkout as
`playwright/spindle/`, driven through upstream's fixtures unchanged): a
five-party call with joins, a clean leave, a rejoin, simultaneous
arrivals and departures and a participant killed mid-call; a homeserver
restart mid-call in both membership modes, after which the call must
still be up and a crash must still expire; a ring the caller abandons;
and a call across the rig's two Spindles in both modes.

## Calls with no SFU

A room of a handful of people can call peer to peer, full mesh, with no
media server in the path; that is a different client build and its own
page, docs/p2p-calls.md, with the rig that proves it against this server.

## What is not here

- **Remote users on the built-in service.** MSC4195's current draft adds
  a federation endpoint for a remote participant's token; the built-in
  service does not serve it. A federated caller needs `lk-jwt-service`,
  external (option B) or as the sidecar (option C), which does.
- **MSC4195's homeserver token endpoint on the built-in service**
  (`/_matrix/client/unstable/io.element.msc4195/rtc/livekit/get_token`).
  Option C serves it, by forwarding it to `lk-jwt-service`; the built-in
  service still answers only `/sfu/get`.
- **Delegated leave on the built-in service.** Holding a participant's
  leave for them needs to see them drop off the SFU, which only
  `lk-jwt-service` does (from LiveKit's webhooks). With the built-in
  service, Element Call keeps its own eighteen-second leave and restarts
  it every four seconds.
- **The SFU and the relay themselves.** Their own documentation covers
  them; this server never speaks to either.
