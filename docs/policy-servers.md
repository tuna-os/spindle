# Room policy servers

Spindle supports policy servers for Matrix rooms. It uses the stable Matrix
API and Synapse's MSC4284 compatibility. It consumes an external policy
service. It does not host that service or publish its `.well-known` document.

A room opts in with an empty-state-key `m.room.policy` event:

```json
{
  "via": "matrix.org",
  "public_keys": { "ed25519": "PUBLIC_KEY_SUPPLIED_BY_THE_POLICY_SERVICE" }
}
```

The named server must have a joined member in the room. Policy checks stay
inactive for malformed state, this homeserver itself, or a server without
joined members. This matches Synapse. Stable state takes precedence over
`org.matrix.msc4284.policy`. The unstable form uses `public_key` instead of
`public_keys.ed25519`.

Spindle gets approval before it stores or publishes new events in rooms with
an active policy. This covers messages, state, membership, invites,
redactions, delayed events, and background dummy events. Spindle also checks
approval for live federation and membership handshakes.

Spindle soft-fails a denied live PDU with known dependencies. It keeps the
authenticated body for DAG continuity and excludes it from client timelines
and current state. Historical recovery and backfill use normal authorization
for past events. A join into an unknown room relies on admission by a resident
server. Local policy checks start once Spindle receives the room's state.

An existing valid `ed25519:policy_server` signature avoids a network request.
Otherwise Spindle sends the complete wire PDU in a signed federation request:
`POST /_matrix/policy/v1/sign`. Unsupported endpoints fall back to
`/_matrix/policy/unstable/org.matrix.msc4284/sign`. The response is a signatures
map.

Spindle verifies the signature with the public key from room state.
Verification uses the redaction rules for the room version. Spindle retains signatures from the origin and verifies approvals for events
it sends too.

Spindle rejects an event after a refusal, an invalid or absent signature, a
transport failure, or a timeout of 30 seconds. Transport failures and invalid
signatures return `M_FORBIDDEN`. HTTP refusals retain their status, known
error codes from Matrix, and `retry_after_ms`. Spindle converts the
authentication errors that the remote service sends. These errors cannot
invalidate a homeserver login.

A rejection leaves no successful record for the client transaction. A retry
can succeed later. Spindle holds no room lock during the network request.
If the room state changes, Spindle rebuilds the event and requests approval
again. After three tries, Spindle returns a retry error. Concurrent retries of
the same client transaction share its result.

The stable and unstable policy events with an empty state key need no policy
approval. An authorized administrator can change or disable the policy when
its server is unavailable. Normal Matrix authorization still applies.
Stable content of `{}` disables policy checks, even if unstable policy state
remains in the room.

The service from the Matrix Foundation needs enrollment and approval. A `via`
value of `matrix.org` alone does not enroll a room. Follow the
[instructions from the setup bot](https://github.com/matrix-org/policyserv-setup-bot#usage).
Use the public key and room state that the service supplies. Deployment of
Spindle does not automatically subscribe any room.

Protocol reference:
[Matrix policy servers](https://spec.matrix.org/latest/server-server-api/#policy-servers).
