# ADR 0003: Media authorization — the URI is the capability

**Status:** accepted

## Context

`GET /_matrix/client/v1/media/download/{server}/{id}` and the thumbnail
route bind `Authenticated(_identity)` and discard it. Any account this
server knows can fetch any media it holds, given the MXC URI. #268 asked
for that to be a decision, not something inherited from the handler's
first draft. The reason is that it composes badly with a room-read hole.
An attacker who can read a private room's timeline can harvest its URIs,
and from there its files.

Three facts bear on it.

**The spec has no per-media ACL.** Authenticated media (MSC3916, Matrix
1.11) needs a valid access token or a federation signature. It says
nothing about *which* user may fetch which file. Synapse, Conduit and
their forks all do exactly that: possession of the URI is the
capability. A stricter rule here would make files Spindle's users share
unreadable to peers that follow the spec.

**Media IDs are 128 random bits.** `random_media_id` draws sixteen bytes
from the OS and hex-encodes them. There is no enumeration. To hold a URI,
an account must get it in a message, or read a room that carries it. The
ID is deliberately *not* the content hash. Thus a URI does not double as
an existence oracle for a known file (see the `media` module header).

**The room-read side is now closed and held closed.** #257 and #258
fixed the read holes. `room_read_authorization.rs` walks every read
route with a stranger. `room_route_authorization.rs` extends that to
every room-scoped route, with a table the router cannot drift from. The
composition #268 worried about needs a hole, and a test now refuses to
let that hole back in.

## Decision

1. **Any authenticated account may fetch any media it holds a URI
   for**. The server refuses a request with no authentication
   (`download_needs_a_token` pins that). This matches the spec and every reference server.
2. **Media IDs stay random and at least 128 bits**, and a test pins the
   width. The decision above is only sound while that holds.
3. **Room-scoped authorization is the control**, not media-scoped
   authorization. The route table decides about new room routes.
   Spindle does not add a media ACL as a second line of defence. Such an
   ACL would diverge from the spec, and add no defence beyond the table.

## Consequences

- A leaked URI is a leaked file, for as long as the file exists. That is
  the spec's model. The remedy the spec offers is to delete the upload,
  and `Media` supports it.
- Per-room scope for media may enter the spec one day (MSC3911 is the
  candidate). If it does, Spindle will make that scope and replace this
  ADR. It will not add a local rule.
- `_identity` stays bound in the handlers on purpose. The binding is what
  makes the route need a token at all. The underscore records that the
  server authenticates the identity, and then, by this decision, does not
  consult it.
