# Room policy servers

Spindle participates in Matrix room policy servers, with the stable Matrix
API and Synapse's MSC4284 compatibility. It consumes an external policy
service; it does not host a policy service or publish a policy-service
`.well-known` document.

A room opts in with an empty-state-key `m.room.policy` event:

```json
{
  "via": "matrix.org",
  "public_keys": { "ed25519": "PUBLIC_KEY_SUPPLIED_BY_THE_POLICY_SERVICE" }
}
```

The named server must have a joined member in the room. A malformed state
event, a policy naming this homeserver itself, or a server with no joined
member leaves policy checking inactive, matching Synapse. Stable state takes
precedence over the unstable `org.matrix.msc4284.policy` event; the unstable
form uses `public_key` instead of `public_keys.ed25519`.

For rooms with an active policy, Spindle obtains approval before storing
and publishing newly authored messages, state, membership, invites,
redactions, delayed events, and background dummy events. Live federation
receipt and membership handshakes also check approval. A denied live PDU
with known dependencies is soft-failed: its authenticated body is kept for
DAG continuity but excluded from client timelines and current state. Historical dependency
recovery and backfill continue to use the room's normal historical event
authorization, rather than applying today's moderation policy retroactively.
A join into an unknown room relies on the resident server's admission
handshake; policy applies locally once the room's state has been received.

An existing valid `ed25519:policy_server` signature avoids a network request.
Otherwise Spindle sends the complete wire PDU as the body of a signed
federation `POST /_matrix/policy/v1/sign` request. Unsupported endpoints fall
back to `/_matrix/policy/unstable/org.matrix.msc4284/sign`. The response is a
signatures map. The room-state public key verifies the returned signature
over the room-version-specific redacted event; origin signatures are
preserved. Spindle verifies approvals for outgoing events too.

A refusal, invalid or missing signature, transport failure, or a 30-second
operation timeout rejects the event. Transport and invalid-signature failures return `M_FORBIDDEN`. Actionable
HTTP refusals preserve their status, recognized Matrix error code and
`retry_after_ms`. Remote authentication errors are rewritten to prevent a
policy service from invalidating a homeserver login. A rejection leaves no
successful client transaction record. A retry can succeed
later. Signing holds no room lock; concurrent room-state changes cause a local
event to be rebuilt and approved again, with three attempts before a retry
error. Concurrent retries of the same client transaction share its result.

The empty-state-key stable and unstable policy events are exempt from policy
approval so an authorized room administrator can change or disable the
policy when its server is unavailable. Normal Matrix authorization still
applies. Setting the stable content to `{}` disables checking, even if an
older unstable policy remains in state.

The Matrix Foundation service requires enrollment and approval; pointing
`via` at `matrix.org` alone does not enroll a room. Follow the
[Foundation setup bot instructions](https://github.com/matrix-org/policyserv-setup-bot#usage)
and use the public key and room state supplied by that service. Deployment
of Spindle does not automatically subscribe any room.

Protocol reference:
[Matrix policy servers](https://spec.matrix.org/latest/server-server-api/#policy-servers).
