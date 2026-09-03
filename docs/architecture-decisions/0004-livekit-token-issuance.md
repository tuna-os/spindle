# ADR 0004: LiveKit token issuance — integrate behind config, keep the external path

**Status:** accepted

## Context

A MatrixRTC call carries its media through a LiveKit SFU, and the SFU
admits a participant on a JWT signed with its API secret. Something has
to mint that JWT for a Matrix user. #38 asked whether that something is
this server or a service deployed beside it, and asked for the answer as
a decision rather than a default.

**The reference deployment delegates.** Element's stack runs
`element-hq/lk-jwt-service`: the client fetches an OpenID token from its
homeserver (`POST /user/{userId}/openid/request_token`), posts it with a
room and a device to `{livekit_service_url}/sfu/get`, and the service
redeems the token over federation (`GET /openid/userinfo`) to learn who
is asking before it mints. Tuwunel and Synapse both document that shape.
It is transport-agnostic and it is what every shipping client speaks.

**The external service cannot scope a token to membership.** It holds no
room state. Its legacy endpoint mints for whatever room the client names;
its newer one asks the homeserver over the Client-Server API, as an
appservice, and trusts the answer. Either way the check the token most
needs — *is this user in this room right now* — is made somewhere other
than where the membership lives, or not at all.

**This server holds the membership index.** `Rooms::is_joined` is one
row read. Minting here makes the scoping check a lookup rather than a
round trip, and makes it authoritative rather than trusted.

**Both halves of the round trip are the homeserver's anyway.** The OpenID
endpoints are spec, not LiveKit-specific: a client needs them for any
third-party service that wants to know who it is. They are served
regardless of this decision, and the external service works against them
as it would against Synapse.

**The MSC is moving toward the homeserver.** MSC4195's current draft
defines `POST /_matrix/client/v1/rtc/livekit/get_token` on the homeserver
itself, with membership checked there and a federation counterpart for
remote users. Shipping clients do not speak it yet; when they do, the
homeserver minting tokens will be the spec's shape, not this server's
deviation from it.

## Decision

1. **Both OpenID endpoints are served**, in full, whether or not anything
   else in this ADR is configured. `openid.rs` mints and redeems; tokens
   expire and are refused after expiry; an OpenID token opens no other
   endpoint on this server.

2. **A built-in LiveKit JWT service exists, behind `[rtc.livekit]`, off
   by default.** `livekit.rs` serves `lk-jwt-service`'s `/sfu/get`
   contract at `/_spindle/rtc/livekit/sfu/get`, so a client cannot tell
   which minter it reached. When configured it advertises itself as the
   first `livekit` transport, ahead of the operator's `foci`.

3. **A token is scoped to current membership**, checked against the
   membership index at mint time. A user who is not joined — never was,
   only invited, or has since left — is refused with `M_FORBIDDEN`, and
   a room that does not exist is refused identically.

4. **The window is short and configurable**; `token_ttl_seconds`
   defaults to fifteen minutes, `exp - nbf` is exactly that, and a zero
   is refused at startup. Minting is rate limited per user.

5. **The signing secret is LiveKit's, and only LiveKit's.** It is not
   the server's signing key and is not derived from it. It is never
   logged.

6. **The external path stays supported and tested.** `[rtc] foci`
   continues to advertise any `lk-jwt-service`, the OpenID endpoints it
   calls back to are pinned by `tests/openid.rs`, and the two can run
   side by side.

## Consequences

- **Revocation on leave is not provided, and is not claimed.** A JWT is
  stateless and the SFU never asks this server again. A user who leaves
  after minting holds their token until `exp`. The window is the whole
  of the guarantee; docs/matrix-rtc.md and the config comment say so in
  those words rather than implying otherwise.
- **The built-in service mints for local users only.** A token whose
  `matrix_server_name` is another server is refused rather than verified
  over federation. A remote participant's call is their own server's
  problem, or an external service's; when MSC4195's federation endpoint
  lands, it is that endpoint's.
- **`roomCreate` is withheld** from the grant, because in LiveKit it
  also permits deleting a room, which ends everyone's call. The SFU's
  default `auto_create` makes the room on first join instead; a
  deployment that turned that off needs the external service or a room
  created another way.
- **This couples the built-in path to LiveKit's token format.** That is
  accepted: the coupling is in one module behind one config section, and
  the external path is the escape hatch for any other transport.
- **When clients move to MSC4195's homeserver endpoint**, `livekit.rs`
  gains a second route with the same minting behind it, and `/sfu/get`
  is kept for as long as a shipping client posts to it.
