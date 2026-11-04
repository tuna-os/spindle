# ADR 0003: Media authorization — the URI is the capability

**Status:** accepted

## Context

`GET /_matrix/client/v1/media/download/{server}/{id}` and the thumbnail
route bind `Authenticated(_identity)` and discard it. Any account this
server knows can fetch any media it holds, given the MXC URI. #268 asked
for that to be a decision rather than something inherited from the
handler's first draft, because it composes badly with a room-read hole:
an attacker who can read a private room's timeline can harvest its URIs,
and from there its files.

Three facts bear on it.

**The spec has no per-media ACL.** Authenticated media (MSC3916, Matrix
1.11) requires a valid access token or a federation signature, and says
nothing about *which* user may fetch which file. Synapse, Conduit and
their forks all implement exactly that: possession of the URI is the
capability. A stricter rule here would make files Spindle's users share
unreadable to peers that follow the spec.

**Media IDs are 128 random bits.** `random_media_id` draws sixteen bytes
from the OS and hex-encodes them. There is no enumeration: the only way
to hold a URI is to have been sent it, or to have read a room that
carries it. The ID is deliberately *not* the content hash, so a URI does
not double as an existence oracle for a known file (see the `media`
module header).

**The room-read side is now closed and held closed.** #257 and #258
fixed the read holes; `room_read_authorization.rs` walks every read
route with a stranger, and `room_route_authorization.rs` extends that to
every room-scoped route with a table the router cannot drift from. The
composition #268 worried about requires a hole that a test now refuses
to let back in.

## Decision

1. **Any authenticated account may fetch any media it holds a URI
   for.** Unauthenticated requests are refused (`download_needs_a_token`
   pins that). This matches the spec and every reference server.
2. **Media IDs stay random and at least 128 bits**, and a test pins the
   width, because the decision above is only sound while that holds.
3. **Room-scoped authorization is the control**, not media-scoped
   authorization. The route table is where new room routes are decided;
   a media ACL is not added as a second line of defence, because it would
   diverge from the spec without adding a defence the table does not.

## Consequences

- A leaked URI is a leaked file, for as long as the file exists. That is
  the spec's model; deleting the upload is the remedy the spec offers,
  and `Media` supports it.
- If per-room media scoping ever enters the spec (MSC3911 is the
  candidate), this ADR is superseded by implementing it, not by adding a
  local rule.
- `_identity` stays bound in the handlers on purpose: the binding is what
  makes the route require a token at all, and the underscore records
  that the identity is authenticated and then, by this decision, not
  consulted.

## Amendment: the frozen unauthenticated surface is served

The authenticated routes above were the whole story until clients
showed otherwise: with no spec version past v1.3 advertised and no
MSC3916 flag, nothing moves a client onto the authenticated endpoints,
so every client that predates them — or gates on a version this server
does not claim — fetched avatars and thumbnails from the frozen
`/_matrix/media/v3/download` and `/thumbnail` endpoints and got 404s.
The spec froze those endpoints without removing them, and every
reference server still serves them.

They are now served as pure capability URLs: the same bytes through the
same content-addressed store, with no token bound alongside the URI.
This extends decision 1 rather than contradicting it — the IDs are 128
random bits, so holding the URI remains the authorization — and the
`download_needs_a_token` pin keeps holding for the authenticated routes.
