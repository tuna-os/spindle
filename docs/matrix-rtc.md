# MatrixRTC: deploying calls end to end

What a call needs from a deployment, in the order a client asks for it,
and the two ways to provide the piece this server does not carry: the
media. Both are supported; ADR 0004 records why both exist.

## The pieces

A MatrixRTC call (Element Call, Element X, Element Web) touches four
things:

1. **The homeserver** — room state for the call membership, delayed
   events (MSC4140) to expire it, to-device signalling, and transport
   discovery (MSC4143). All served here; docs/dashboard.md's M7 row is
   the inventory.
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

The two options compose. With both configured, the built-in service is
listed first and the operator's `foci` follow in the order written;
clients read the list as a priority order.

## What to check

- `curl https://matrix.example.org/.well-known/matrix/client` names
  the transport under `org.matrix.msc4143.rtc_foci`. If it does not,
  neither `[rtc.livekit]` nor `[rtc] foci` is set.
- `GET /_matrix/client/versions` lists `org.matrix.msc4140` and
  `org.matrix.msc4143` under `unstable_features`; Element Call checks
  both before it will rely on the server.
- For option A: a joined user's `POST .../sfu/get` returns a `jwt` whose
  decoded `video.room` is the Matrix room ID and whose `exp - nbf` is
  `token_ttl_seconds`. A user who has left gets `403 M_FORBIDDEN`.
- For option B: `GET /_matrix/federation/v1/openid/userinfo?access_token=…`
  with a fresh token returns `{"sub": "@you:example.org"}`; with an
  expired or invented one, `401 M_UNKNOWN_TOKEN`.

The tests that pin each of these: `crates/spindle-server/tests/openid.rs`,
`livekit_jwt.rs`, `rtc_transports.rs`, `rtc_membership.rs` and
`delayed_events.rs`.

## What is not here

- **Remote users on the built-in service.** MSC4195's current draft adds
  a federation endpoint for a remote participant's token; until clients
  speak it, a federated caller needs the external service.
- **MSC4195's homeserver token endpoint**
  (`/_matrix/client/v1/rtc/livekit/get_token`). Shipping clients post to
  `/sfu/get`; the homeserver endpoint is added when they move, with the
  same minting behind it.
- **The SFU and the relay themselves.** Their own documentation covers
  them; this server never speaks to either.
