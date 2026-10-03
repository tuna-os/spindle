# MatrixRTC: deploying calls end to end

This page lists what a call needs from a deployment, in the order a
client asks for it. It also gives the two ways to provide the piece this
server does not carry: the media. Both are supported; ADR 0004 records
why both exist.

## The pieces

A MatrixRTC call (Element Call, Element X, Element Web) touches four
things:

1. **The homeserver** — room state for the call membership, and delayed
   events (MSC4140) to expire it. It also serves sticky events (MSC4354),
   so a membership can lapse and not become permanent state. It also
   carries to-device call signals and transport discovery (MSC4143). All
   served here; docs/dashboard.md's M7 row is the inventory.
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

`key` and `secret` are the pair that the SFU started with (`--keys
APIxxxxxxxx: ...`, or `keys:` in `livekit.yaml`). With the section set,
this server:

- advertises itself as a `livekit` transport, first in the list, at
  <code>https://matrix.example.org/_spindle/rtc/livekit</code> — on
  `/rtc/transports` and in `.well-known/matrix/client` alike;
- answers `POST /_spindle/rtc/livekit/sfu/get` with `{url, jwt}` in
  `lk-jwt-service`'s shape, so a client cannot tell the two apart;
- mints only for a Matrix room the user is **joined to at that moment**,
  checked against its own membership index. A user who never joined, who
  has an invite only, or who has since left gets `M_FORBIDDEN`. A room
  that does not exist gets the same refusal;
- mints for its own users only. If a token's `matrix_server_name` is
  another server, Spindle refuses it and does not verify it over
  federation;
- applies a per-user rate limit to token mints (docs/rate-limits.md).

The token's grants are the least a participant needs: join this one
room, publish, subscribe. Spindle withholds `roomCreate`, because in
LiveKit it also lets the holder delete the room, which ends everyone's
call. The SFU's default `auto_create: true` makes the room on first join
instead. If
your SFU has `auto_create` off, use option B or create rooms another
way.

**Revocation.** Spindle cannot revoke a minted token: it is stateless,
and the SFU never asks this server again. A user who leaves the room
after the mint holds their token until it expires. `token_ttl_seconds` is the
whole of that guarantee, which is why it defaults to fifteen minutes and
why the default is not an hour. `lk-jwt-service` issues an hour; a
client that needs that gets it by setting `3600` here, on purpose.

The secret is LiveKit's, and Spindle shares it with nothing else. It is
not the key that this server signs with, and Spindle does not derive it
from that key. The two rotate apart, and a leak of one is not a leak of
the other. Spindle never logs it.

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
`GET /_matrix/federation/v1/openid/userinfo`. It resolves that endpoint
through `.well-known/matrix/server` like any federation request. So the
federation listener has to be reachable from wherever the service runs.
Nothing else on this server takes part: the service mints for whatever
room the client names, with no membership check on this side.

The two options compose. With both configured, the built-in service
comes first, and the operator's `foci` follow in the order written.
Clients read the list as a priority order.

## What to check

- <code>curl https://matrix.example.org/.well-known/matrix/client</code> names
  the transport under `org.matrix.msc4143.rtc_foci`. If it does not,
  neither `[rtc.livekit]` nor `[rtc] foci` is set.
- `GET /_matrix/client/versions` lists `org.matrix.msc4140`,
  `org.matrix.msc4143` and `org.matrix.msc4354` under
  `unstable_features`. Element Call checks for them before it will rely
  on the server.
- A send with `?org.matrix.msc4354.sticky_duration_ms=30000` comes back
  from `GET .../event/{id}` with `msc4354_sticky.duration_ms`. A client
  that joins the room afterwards finds it under
  `rooms.join.{room}.msc4354_sticky.events` in its first `/sync`. There,
  `unsigned.msc4354_sticky_duration_ttl_ms` counts down. Spindle caps
  durations above an hour to one hour.
- For option A: a joined user's `POST .../sfu/get` returns a `jwt` whose
  decoded `video.room` is the Matrix room ID and whose `exp - nbf` is
  `token_ttl_seconds`. A user who has left gets `403 M_FORBIDDEN`.
- For option B: `GET /_matrix/federation/v1/openid/userinfo?access_token=…`
  with a fresh token returns `{"sub": "@you:example.org"}`; with an
  expired or invented one, `401 M_UNKNOWN_TOKEN`.

The tests that pin each of these: `crates/spindle-server/tests/openid.rs`,
`livekit_jwt.rs`, `rtc_transports.rs`, `rtc_membership.rs`,
`delayed_events.rs` and `sticky_events.rs`.

## Running Element Call's own suite

`contrib/element-call/run.sh` stands up the two-homeserver Playwright
stack of Element Call (LiveKit, lk-jwt-service, Element Web, nginx, all
upstream's and pinned). Spindle sits in both of Synapse's seats, and the
script runs their specs against it. `docker-compose-spindle.yml` is the whole
override; `spindle.toml` and `spindle-othersite.toml` stand in for
`backend/playwright_homeserver*.yaml`. Results go through
`scripts/element-call-check.py` against `contrib/element-call/allowlist.txt`,
the same ratchet shape as Complement's. The `element-call-e2e` job in
`.github/workflows/compliance.yml` runs it nightly and on demand.

## Calls with no SFU

A room of a handful of people can call peer to peer, full mesh, with no
media server in the path. That needs a different client build, and it has
its own page, docs/p2p-calls.md. That page also has the rig that proves it
against this server.

## What is not here

- **Remote users on the built-in service.** MSC4195's current draft adds
  a federation endpoint for a remote participant's token. Until clients
  speak it, a federated caller needs the external service.
- **MSC4195's homeserver token endpoint**
  (`/_matrix/client/v1/rtc/livekit/get_token`). Clients that ship today
  post to `/sfu/get`. When they move, Spindle will add the homeserver
  endpoint, and the same code will mint the tokens.
- **The SFU and the relay themselves.** Their own documentation covers
  them; this server never speaks to either.
