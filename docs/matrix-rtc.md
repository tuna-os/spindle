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
          (external service; built-in for other      ├─GET /_matrix/federation/v1/openid/userinfo─▶ token's homeserver
           servers' tokens)                          │◀────────────── {sub: @me:server} ───────────
       ◀────────────────── {url: wss://sfu, jwt} ─────┘

client ──websocket, jwt──▶ SFU
```

The OpenID token is the credential in that exchange. It is short-lived
(an hour), it opens nothing on this server, and the JWT service — built
in or external — is what it is for.

In a call across servers, each participant publishes on the SFU of
their own server and subscribes on the SFUs of the others. So a user of
another server also asks this server's JWT service for a token, with an
OpenID token from their own server.

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
# secret_file = "/run/secrets/livekit-secret"   # instead of secret
# token_ttl_seconds = 900
# full_access_servers = []
```

`key` and `secret` are the pair the SFU was started with (`--keys
APIxxxxxxxx: ...`, or `keys:` in `livekit.yaml`). With the section set,
this server:

- advertises itself as a `livekit` transport, first in the list, at
  `https://matrix.example.org/_spindle/rtc/livekit` — on
  `/rtc/transports` and in `.well-known/matrix/client` alike;
- answers `POST /_spindle/rtc/livekit/sfu/get` and
  `POST /_spindle/rtc/livekit/get_token` (the Matrix 2.0 request) in the
  shape of `lk-jwt-service` 0.7, so a client cannot tell the two apart;
- mints only for a Matrix room the user is **joined to at that moment**,
  checked against its own membership index. Never joined, only invited,
  or since left: refused with `M_FORBIDDEN`, and a room that does not
  exist is refused identically;
- redeems its own users' OpenID tokens itself. It sends another server's
  token to that server (`openid/userinfo` over federation) and accepts it
  only for a user of that server;
- rate limits minting per user, and per server for other servers' tokens
  (docs/rate-limits.md).

The token's grants are the ones `lk-jwt-service` gives:

| Who | Join, subscribe | Publish | Room on the SFU |
|---|---|---|---|
| a user of this server, or of a server in `full_access_servers` | yes | yes | created through the SFU's API before the token is sent |
| a user of any other server | yes | no | not created |

So the users of another server see and hear a call on this SFU, and
their own media goes through their own server's SFU. `full_access_servers`
names each server whose users may also publish here. It has no
wildcard, because publishing uses the bandwidth of this SFU.

The LiveKit room name is a hash of the Matrix room ID and the call slot.
The Matrix 2.0 identity is a hash of user, device and member ID. Both are
the hashes of `lk-jwt-service`, so a call lands in the same LiveKit room
with either service. The legacy `sfu/get` identity is
`{user_id}:{device_id}`.

No token gets `roomCreate`, because in LiveKit it also permits deleting
the room, which ends the call for everyone. This server creates the room
itself, with the SFU's `CreateRoom` API at the `http(s)` address of
`url`. Thus the SFU can keep `auto_create: false`, which is the setting
`lk-jwt-service` recommends: a user of another server cannot open a room
on it. This server must reach the SFU at that address. If it cannot, the
token request fails with `500 M_UNKNOWN`.

A token request that asks the transport to hold the delayed leave
(`delay_id`) gets `400 M_BAD_JSON`, and clients then ask again without it.
This server holds delayed leaves on the homeserver path instead (option C
and the SFU program below).

**Revocation.** A minted token cannot be revoked: it is stateless, and
the SFU never asks this server again. A user who leaves the room after
minting holds their token until it expires. `token_ttl_seconds` is the
whole of that guarantee, which is why it defaults to fifteen minutes and
why the default is not an hour. `lk-jwt-service` issues an hour; a
client that needs that gets it by setting `3600` here, on purpose.

The secret is LiveKit's and is shared with nothing else. It is not this
server's signing key and is not derived from it; the two rotate apart,
and a leak of one is not a leak of the other. It is never logged.

To keep the secret out of `spindle.toml`, put it in a file and set
`secret_file` to its path instead of `secret`. For example, use a
Compose or Kubernetes secret. This is how `lk-jwt-service` reads
`LIVEKIT_SECRET_FROM_FILE`. Set exactly one of the two keys.

The server reads the file once, at startup, and ignores the trailing
newline. If the file is missing or empty, or if both keys or neither key
is set, the server does not start, and the error names `rtc.livekit`.
To use a new secret, restart the server. With a supervised SFU, the
generated `livekit.yaml` gets the secret from the file.

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

## The SFU program: switch, models, sidecar

The built-in service above is one half of an SFU *program* with an
operator switch. `spindle sfu on|off|status <config>` flips and reads it;
`GET/PUT /_spindle/admin/v1/rtc/sfu` does the same behind admin auth. The
switch is stored server-side and survives restarts; it never rewrites the
config file. When off, everything reads as unconfigured: `sfu/get`
answers 404 `M_UNRECOGNIZED`, the transport is unadvertised on both
discovery surfaces, and no sidecar runs — off costs zero.

Two models serve the media, and the switch plus the minter behave
identically for both:

- **Remote** (default): the SFU is separately hosted at `[rtc.livekit]
  url`. This server only mints.
- **Local**: `[rtc.livekit] binary` names the operator-supplied
  `livekit-server` binary (pinned at v1.13.5, Element Server Suite
  parity), and this server supervises it as a child — generating its
  config (keys from `[rtc.livekit]`, `auto_create: false`, webhooks
  pointing at this server), watching it, restarting it. Upgrades are
  decoupled from spindle releases: replace the binary and restart, or
  flip the switch off and on. The only file supervision writes is the
  generated sidecar config (`<storage.path>/livekit.yaml` unless
  `sidecar_config_path` says otherwise).

The minter gaps the "What is not here" section used to list are closed:
MSC4195's homeserver token endpoint (`POST
.../rtc/livekit/get_token`, stable and unstable) mints for local users
over their access token; the federation twin mints for a remote
participant whose server vouches for them by X-Matrix signature, with
the same grants as any other remote user's token; the delegation probe
(`POST .../delegate_delayed_leave`, anything but 404 meaning "held")
records the hold; and the SFU webhook (`POST
/_spindle/rtc/livekit/sfu/webhook`) releases held leaves when
participants drop off the media — fed by the supervised sidecar's
generated webhook config, or by the operator's hand on the remote model.
The webhook accepts only a request that LiveKit signed: an HS256 JWT
under the API secret in `Authorization`, with the SHA-256 of the body.

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
  decoded `video.room` is the hash of the Matrix room ID and the call
  slot (not the room ID) and whose `exp - nbf` is `token_ttl_seconds`.
  A user who has left gets `403 M_FORBIDDEN`. A joined user of another
  server gets `canPublish: false`.
- For option B: `GET /_matrix/federation/v1/openid/userinfo?access_token=…`
  with a fresh token returns `{"sub": "@you:example.org"}`; with an
  expired or invented one, `401 M_UNKNOWN_TOKEN`.

The tests that pin each of these: `crates/spindle-server/tests/openid.rs`,
`livekit_jwt.rs`, `livekit_remote.rs`, `rtc_sfu.rs`, `rtc_transports.rs`,
`rtc_membership.rs`, `delayed_events.rs`, `delayed_events_merged.rs`,
`appservice_proxy.rs` and `sticky_events.rs`.

## Moving from lk-jwt-service to the built-in minter

This moves a deployment from option B (or C) to option A. The SFU stays.
Calls in progress continue, because both services give the same LiveKit
room names.

Before you start:

1. Make sure that this server can reach the SFU at the `http(s)` form of
   its `wss` URL. The minter creates rooms there. A `curl` of
   `https://livekit.example.org/` from the homeserver host must connect.
2. Read `LIVEKIT_FULL_ACCESS_HOMESERVERS` from the lk-jwt-service
   environment. Put each name except this server's own into
   `full_access_servers`. If the value is `*`, decide which servers to
   name: the built-in minter has no wildcard.
3. Keep the SFU's `auto_create: false`. The minter does not need
   `auto_create`.

Roll out:

1. Add `[rtc.livekit]` with the SFU's `url`, `key` and `secret` (the
   values of `LIVEKIT_URL`, `LIVEKIT_KEY` and `LIVEKIT_SECRET`). Remove
   the lk-jwt-service entry from `[rtc] foci`. For option C, also remove
   its registration from `[appservices]`; otherwise this server sends
   `get_token` and `delegate_delayed_leave` to the service.
2. Point the SFU's `webhook.urls` at
   `https://<public_base_url>/_spindle/rtc/livekit/sfu/webhook`, with
   `webhook.api_key` equal to `key`. Restart the SFU.
3. Restart this server. `GET /_matrix/client/v1/rtc/transports` now names
   `https://<public_base_url>/_spindle/rtc/livekit` first.
4. Publish the new transport where clients find it. If a static
   `.well-known/matrix/client` names the lk-jwt-service URL, change it to
   the URL from step 3 or let this server serve the document.
5. Make a call to a user of another server, in both directions. Check
   that each side sees and hears the other. In the server log, look for
   `the SFU refused to create a call's room`: it means step 1 of the
   preparation is not done.
6. Stop lk-jwt-service when no client uses its URL. Clients that cached
   the old transport ask it until they refresh it.

Roll back:

1. Put the lk-jwt-service entry back in `[rtc] foci` (and the
   registration in `[appservices]` for option C), and start the service.
2. Turn the built-in minter off without editing its section:
   `spindle sfu off <config>`, or `PUT /_spindle/admin/v1/rtc/sfu` with
   `{"enabled": false}`. The built-in transport disappears from
   discovery at once, and `sfu/get` answers 404.
3. Point the SFU's `webhook.urls` back at the service's `/sfu_webhook`.
4. Restore the static `.well-known/matrix/client` if you changed it.

Tokens that either service minted stay valid until they expire, and the
room names are the same, so a call in progress continues in both
directions.

## Running Element Call's own suite

`contrib/element-call/run.sh` starts Element Call's Playwright stack with
two homeservers. LiveKit, lk-jwt-service, Element Web and nginx are
upstream's, at a pinned revision. Spindle takes the first homeserver
seat: `docker-compose-spindle.yml` puts it there, with `spindle.toml` in
place of upstream's `backend/playwright_homeserver.yaml`. The script then
runs upstream's specs against the stack. `scripts/element-call-check.py`
compares the results with `contrib/element-call/allowlist.txt`, as the
Complement check does with its allowlist. The `element-call-e2e` job in
`.github/workflows/compliance.yml` runs the suite nightly and on demand.

`SPINDLE_PEER` selects the server in the second seat:

- `spindle`, the default: a second Spindle, from
  `docker-compose-spindle-othersite.yml` and `spindle-othersite.toml`.
- `synapse`: upstream's Synapse, with no change.
  `docker-compose-dead-peers.yml` adds three more Spindles for the last
  ring test below. This variant has its own allowlist,
  `allowlist-synapse-peer.txt`. The `element-call-synapse-peer` job runs
  it nightly, on demand, and on pull requests that change federation or
  MatrixRTC code.

The rig also runs specs of this server, from `contrib/element-call/specs/`.
The script copies them into the checkout as `playwright/spindle/`. They
use upstream's fixtures with no change. With two Spindles they run:

- a five-party call with joins, a clean leave, a rejoin, and a
  participant that stops mid-call;
- a homeserver restart mid-call in both membership modes. The call must
  stay up, and a crash must still expire;
- a ring that the caller abandons;
- a call across the two Spindles in both membership modes.

With Spindle and Synapse they run:

- a call in each direction, in both membership modes.
- a DM call in each direction. The ring must get to the callee in 15
  seconds, and then the call must connect.
- the same ring from Spindle, while the DM also holds users of three
  servers that do not answer. Each request to these servers runs into
  its timeout. Before #794, the outbox sent to one destination at a time,
  and this ring did not arrive.

`SPINDLE_RTC` selects who mints the SFU tokens for each Spindle seat:

- `lk-jwt-service`, the default: upstream's service beside each
  homeserver, as in the Element Call rig.
- `builtin`: the built-in minter of the Spindle, against upstream's SFU.
  `docker-compose-builtin-rtc.yml` gives the first seat
  `spindle-builtin-rtc.toml`, and `docker-compose-builtin-rtc-othersite.yml`
  gives a second Spindle `spindle-othersite-builtin-rtc.toml`. `run.sh`
  writes copies of upstream's nginx and LiveKit configs that send
  `/_spindle/rtc/livekit` and the SFU webhooks to the Spindles. A Synapse
  in the second seat keeps its lk-jwt-service. The results go against
  `allowlist-builtin-rtc.txt`, or `allowlist-builtin-rtc-synapse-peer.txt`
  with Synapse. The `element-call-e2e` job runs both minters nightly; a
  push to main runs only the first.

## Calls with no SFU

A room of a handful of people can call peer to peer, full mesh, with no
media server in the path; that is a different client build and its own
page, docs/p2p-calls.md, with the rig that proves it against this server.

## What is not here

- **Remote users without the program on.** The built-in minter and the
  federation twin mint for a remote participant while the SFU program
  is on. While it is off, a federated caller needs `lk-jwt-service`,
  external (option B) or as the sidecar (option C), which mints on its
  own.
- **Delegation on the transport.** `lk-jwt-service` also holds a delayed
  leave when a client asks the transport
  (`{livekit_service_url}/delegate_delayed_leave`, or `delay_id` on a
  token request). The built-in minter does not: the first is a 404, and
  the second is `400 M_BAD_JSON`. Clients then restart their own short
  leave, or use the homeserver path, which this server holds.
- **Delegated leave without SFU events.** The probe records the hold.
  The release learns the drop from the SFU webhook. The supervised
  sidecar points its webhooks here on generation. A remote deployment
  must point its SFU at `/_spindle/rtc/livekit/sfu/webhook` by hand.
  Without that pointer, crashed participants keep an hour-long leave.
- **The SFU and the relay themselves.** Their docs cover them. This
  server mints for one and supervises the local deployment of the
  other. It never carries media.
