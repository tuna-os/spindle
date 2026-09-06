# Federating with a Bluetooth mesh: the Spindle–Neutrino system

The IndiaFOSS Companion project runs Matrix rooms on phones with no
internet: Neutrino (Element's P2P homeserver, in hanthor's fork) over iroh
over Bluetooth LE, one homeserver per phone, federating phone to phone.
Their RFC asks whether those rooms can reach the rest of Matrix through a
Spindle hosted for the conference, so that people at home and people at
the venue share the same rooms, and so that a phone coming back online
catches up from the Spindle. The goal behind the RFC is three thousand
attendees using the mesh and public federation in a venue with poor
connectivity, without noticing the seam.

This page is the design for that system and the evidence behind it. It is
written from both code bases as they stand (this branch of Spindle, the
Neutrino fork branch `e2ee-key-transport` at 3fb6945, neutrino-iroh at its
head), it records what a loopback federation between the two actually did,
and it answers the open issues on the Companion side from Spindle's side.
The rig that produced the evidence is `scripts/neutrino-interop.sh`; the
Neutrino change it runs against is `contrib/neutrino/`.

The short version: with the patch on the mesh side and MSC4242 on this
side, **a mesh user joins a room on the Spindle, the Spindle joins a room
on the mesh, and messages cross in both directions**, over plain
federation, with every event signed and verified.

The design decision the RFC makes -- plain federation, no portal bridge --
is right for Spindle too: this server relays ciphertext and key material
and never holds plaintext. An earlier version of this page claimed that
every endpoint encryption needs was already served across federation. It
was not: until this branch Spindle answered `/keys/query` and
`/keys/claim` for its own users only, served none of the federation key
endpoints, and neither sent nor accepted to-device or device-list EDUs.
The section on encryption below says what is served now.

## What is true today

Some of what the RFC and the earlier version of this page say about
Neutrino is stale; the fork has moved. Read from the code:

| | Spindle | Neutrino fork (`trusted_network = false`, as neutrino-lan runs it) |
|---|---|---|
| Room versions | 11 and 12, and now `org.matrix.msc4242.12` (MSC4242 state DAGs, Hydra phase 2) | `org.matrix.msc4242.12` only: v12 auth rules over a state DAG (`prev_state_events`, no `auth_events`) |
| Event signatures | required on every inbound PDU (ruma `verify_event`) | produced on every event; verified against the origin's node id |
| Key document | served, fetched from peers over `/_matrix/key/v2/server` | served in signed mode (`server_name` = 64-hex node id, key `ed25519:1`, the node id is the key) |
| Request signing | every federation request signed and verified | not produced (`X-Matrix origin,destination` only) and not verified inbound |
| Server names | hostname or literal; no `.well-known`/SRV | the node id; a hostname passes through to the wire unaltered |
| Transport | HTTPS, or `http` for a listed peer | `http://` to a proxy (the `neutrino-lb` egress) which carries CoAP over the iroh link |
| Reaching a name | `[federation] peers` maps a name to a URL | the link takes the destination bytes as a node id; a hostname is unroutable |
| Backoff to a dark peer | per-peer `max_backoff_ms`, rows kept until acked | full-jitter to about fifteen minutes, kicked on peer discovery |
| Media over federation | authenticated endpoint, `413 M_TOO_LARGE` final | 256 KiB cap |

The consequences fall out directly. Events already cross the seam
signed, so "may the older mesh events be unsigned" is moot: they are not.
Requests do not, so a Neutrino node cannot be authenticated by a Spindle
without the patch below, and a Spindle's requests are accepted by a
Neutrino node on faith. A Neutrino node can be reached by a Spindle (the
`peers` map) but cannot reach a Spindle without the patch, because its
only route is a link that addresses node ids. And the two sides created
rooms in versions the other refused, until this branch taught Spindle the
mesh's.

## Evidence: one Neutrino node and one Spindle on loopback

`scripts/neutrino-interop.sh` starts `neutrino-lan` (the LAN build of the
fork: iroh, mDNS, no BLE) and a Spindle that lists the node in `peers`,
then runs the probes below. Against the unpatched fork and a Spindle without
MSC4242, the picture was: the key document served, Spindle's invite refused
for the room version, the node's invite failing after sixty seconds because
the request went to `http://127.0.0.1~:8008` through the egress and the
link could not address it, the alias resolved in 13 ms, the unauthenticated
query answered, the key document fetched. So the transport and naming
layers met in the middle already, and the two gaps were the direction mesh
to Spindle and the room version.

With `contrib/neutrino/` applied on the node and this branch on the
Spindle, every probe passes:

| probe | outcome | detail |
|---|---|---|
| mesh node key document at its loopback URL | served | `server_name` is the node id; key `ed25519:1` |
| Spindle invites `@n:<node>` into a state-DAG room | accepted | the node holds the invite |
| mesh node invites `@alice:<spindle>` | accepted | signed request, verified against the node's key document, in milliseconds |
| mesh user joins Spindle's state-DAG room | joined | `make_join`/`send_join` against Spindle; the node seeds itself from the `state_dag` response |
| messages cross Spindle to mesh and mesh to Spindle | both | in the room the mesh user joined |
| Spindle joins the mesh node's room, a message reaches the node | joined | Spindle seeds itself from the node's `state_dag`, which carries the join itself as a head |
| Spindle resolves `#mesh-session-1:<node>` over federation | resolved | the fork's alias patch answers `query/directory` |
| mesh node answers a federation query with no `X-Matrix` header | 200 | inbound requests are still not verified (step 2 below) |
| Spindle key document over plain http | 200 | what the node's HTTP key resolver fetches |

Two things the run also showed. A Neutrino node drops a PDU for a room
it has not yet registered ("no version on record for this room"): Spindle
fans the node's own join out to it before the node has finished seeding
from the `send_join` response, and that copy is lost, harmlessly, because
the node already holds the event. And a state-DAG resident answers
`send_join` with the DAG *after* the join, in which the join is a head;
Spindle's seeding accepts that shape and seeds the join last.

## Calls across the seam

A call in a session room is MatrixRTC: transport discovery (MSC4143),
delayed events (MSC4140) for the dead-man's switch, and sticky events
(MSC4354) for a membership that lapses instead of lasting forever. Spindle
serves all three (docs/matrix-rtc.md). The rig probes what the mesh node
does with them, in the room the mesh user joined, with `m.rtc.member`
granted to every member the way Element X grants it on every room it
creates:

| probe | outcome | detail |
|---|---|---|
| mesh node advertises msc4140 / msc4143 / msc4354 | none | `unstable_features` names only msc4222 and simplified sliding sync |
| mesh node serves `/rtc/transports` (MSC4143) | 404 | a client on the mesh finds no SFU through the node |
| mesh node honours a delayed send (MSC4140) | sent now | HTTP 200 and the delay parameter ignored: the event goes out at once |
| alice's sticky `m.rtc.member` reaches the node | sticky-kept | the `msc4354_sticky` key on the PDU survives the crossing and the node's store |
| the node's `/sync` has an `msc4354_sticky` section | no | a client on the node sees the membership in the timeline only; a later mesh joiner is not handed it |
| the mesh user's `m.rtc.member` state reaches Spindle | arrived | MatrixRTC 1.0 membership as room state; without the power-level override the node refuses it by auth rules, correctly |
| alice's delayed event fires and reaches the node | delivered | MSC4140 on Spindle; the node needs nothing to receive the result |

What that means for the venue. A participant whose homeserver is a
Spindle -- the gateway, or a hub -- has the whole mechanism: their
membership expires when their phone dies, and their sticky membership
reaches every server in the room, mesh nodes included, as an ordinary PDU.
A participant whose homeserver is their own mesh node has none of it yet,
and the delayed-event row is the one that bites: the node answers 200 to a
delayed leave and sends it immediately, so a client that trusts the
answer removes itself from the call the moment it joins. Element Call
checks `unstable_features` before relying on the server and would not
schedule the leave against this node at all -- which leaves the ghost the
mechanism exists to prevent, when a mesh participant's phone dies. Until
the fork carries MSC4140 (a delay parameter, a timer, a restart endpoint;
Spindle's `delayed.rs` is the shape) and MSC4143 (a static transport list
pointing at the venue's SFU), a call at the venue is hosted with the
participants on Spindles, and a mesh node is a spectator to its
membership. MSC4354 is the smaller gap: the node already keeps the key on
the PDU, so what is missing is the index and the `/sync` section, and
`msc4354` on the versions list.

And the call that needs no SFU at all: a full-mesh call, media straight
between the browsers, signalled over to-device messages and
`org.matrix.msc3401.call.member` state. docs/p2p-calls.md proves it
against this server with Element Call's full-mesh build, two browsers on
a host-to-host candidate pair. Every piece it rides is in the tables
above as crossing the seam, so a full-mesh call between a Spindle
participant and a mesh-node participant has nothing in its way at the
protocol level; driving one across the seam is the next measurement.

## Encryption: session rooms in the clear, everything else encrypted

The policy is the app's: a session room, a hall room, the announcements
room are created unencrypted, because a talk's back-channel is public by
nature and a late joiner on a phone has to be able to read it without a
key exchange over Bluetooth. A direct message or a group chat a person
creates is encrypted by default, and stays encrypted across the seam.

What that asks of the servers is not the encryption -- the clients do
that -- but the plumbing that lets clients on both sides find each
other's keys and pass key material around. Spindle now carries all of it
over federation:

| need | Spindle | Neutrino fork |
|---|---|---|
| a peer asks for our users' device keys | `POST /_matrix/federation/v1/user/keys/query` | served |
| a peer claims our users' one-time keys | `POST /_matrix/federation/v1/user/keys/claim` | served |
| a peer wants a user's whole device list | `GET /_matrix/federation/v1/user/devices/{user}` | served |
| our client asks for a remote user's keys | `/keys/query` and `/keys/claim` ask that user's server, one request per server, and keep the answer as a copy | the same, via the fork's `keys_query` client |
| a to-device message for a user elsewhere | one `m.direct_to_device` EDU per destination in the next transaction, named by the client's transaction so a retry does not deliver twice | the same |
| a to-device message for a user here | delivered from the EDU to the device, or to every device for `*`, the sender checked against the origin | the same |
| a device appears, changes or is deleted | `m.device_list_update` to every server sharing a room with the user, through the durable outbox; on receipt the keys are stored, or the list re-fetched if the update carried none | the same |
| cross-signing keys uploaded | `m.signing_key_update` to the same servers | not sent; stored if received |

The two-Spindle suite `tests/e2ee_federation.rs` pins the directory, the
claim handed out once, to-device both ways including the `*` fan-out
resolved on the recipient's server, and a device change arriving as
`device_lists.changed` on the server sharing a room. The rig runs the
same six probes against the Neutrino node.

A note on what a gateway sees: ciphertext and keys, never plaintext.
Which is the point of choosing federation over a bridge, and what makes
a gateway a laptop anyone at the venue can run.

## The system

Three roles, and the same code in each phone.

**Phones** run Neutrino over BLE and, when they have it, Wi-Fi. They
federate with each other and with whichever gateways are in range. They
never federate with the Spindle: three thousand outboxes backing off
against one server is a port scanner, not a homeserver, and a phone that
walks out of range would keep the Spindle's outbox rows for it forever.

**Venue gateways** (three to five: a laptop or a small computer at the
registration desk, one per hall) are Neutrino nodes with the venue's
uplink. They are the Spindle's only federation peers, listed in
`[federation] peers` with a patient backoff and a plain-http URL, and the
Spindle is the only peer they reach by name. A gateway is a node that
happens to have a hostname and a route; it carries no bridge logic.

**The conference Spindle** is the room's home for everyone with internet:
remote attendees, the organisers' laptops, the schedule bot. It creates
the session rooms and owns the aliases, so `#session-1:conf.example` is
the same room on every side. Attendees at home join it from any Matrix
client; attendees in the venue join it on their phone through a gateway's
copy.

What crosses the seam is ordinary federation: a transaction of signed
PDUs and EDUs from a gateway to the Spindle and back, invites in both
directions, `make_join`/`send_join`, key queries and claims for E2EE,
to-device for Olm sessions and calls, media fetched on demand within the
peer's cap. Nothing is re-signed or re-originated. The Spindle sees three
to five peers it can wait hours for, and the mesh sees the Spindle's
rooms as the copy a gateway carries.

Whether Bluetooth gossip itself scales to three thousand nodes is the
mesh's question, and the harder one; the Companion project's
`neutrino-scale.md` and probe swarm are the right tools for it.

## Convergence, in order

1. **Route names directly and sign requests (done here, as a patch).** A
   Neutrino node with a proxy configured sends every destination through
   the egress; a destination that is not a node id must instead be dialled
   over HTTP, and every request must carry a real `X-Matrix` signature. The
   patch under `contrib/neutrino/` does that and adds an HTTP key resolver
   so a gateway verifies a named peer's events. Small: one client, one
   resolver, a config flag, a widened ingress prefix.

2. **Verify inbound requests on the gateway.** The fork's `auth.rs` reads
   `origin` and ignores `key`/`sig`. On a gateway that is reachable from
   the internet, that is a spoofable identity. The fix is the same object
   the patch signs, verified with the same resolver; it is the next patch,
   and it can be gated by `trusted_network` like event verification is.

3. **Meet on a room version: MSC4242, done on this branch.** The
   mesh's version is not a fork of v12 that Neutrino chose; it is where
   Matrix itself is going. Project Hydra, the matrix.org programme to make
   federation's state handling reliable, landed its phase 1 in room
   version 12 (creator power, hash-derived room IDs, state resolution
   2.1) and has published its phase 2 MSCs: MSC4242 State DAGs, MSC4428
   stable member identifiers, MSC4430 member keys. MSC4242 is the one
   that changes the wire: every event names its *state* parents
   (`prev_state_events`, at most twenty), `auth_events` leaves the wire
   because every server calculates them from the state DAG, current
   state is the resolution of the state DAG's forward extremities, and
   `send_join` answers with the whole state DAG and a slice of timeline
   instead of `state` and `auth_chain`. It has no number yet -- the
   proposal carries "unassigned room version", and the expectation is
   v13 -- so it federates as `org.matrix.msc4242.12`, and Neutrino's
   README says outright that it implements only the newest versions,
   Hydra phase 2 and, in future, 3, to test them in the harshest place.

   Spindle now speaks that version. It is the smaller change on this
   side, and the right one: a server whose state is a linear log has one
   state-DAG head almost all of the time, so "the resolution of the
   forward extremities" is a lookup, and the DAG's discipline -- every
   state event names the state it was written against -- is what the
   log already records. What the branch adds: the version itself, with
   v12's rules and a redaction that keeps `prev_state_events` under the
   reference hash and the signature (docs of `spindle-core::version`);
   events built with state parents and no `auth_events`; the state DAG's
   heads tracked per room; receipt checks on the parents; the
   `send_join` shape both ways; `get_missing_events` with `state_dag`;
   and `/capabilities` advertising it as unstable. When the number is
   assigned, the string changes and nothing else does.

   What it does not do yet is resolve a state-DAG fork: two accepted
   state events neither of which names the other. Today that is the
   fork the log already classifies (docs/divergence.md), and the
   contested key is set aside rather than resolved, exactly as for a
   stock room. Neutrino runs state resolution 2.1 over the same inputs,
   so on a fork the two can disagree until the resolver is wired in --
   the same gap #16 names, now with a version whose whole point is that
   the resolver's inputs are trustworthy.

4. **The MSC3995 hub protocol.** SPEC.md §12 is the design; nothing
   implements it, on either side. Not on the path to the venue.

## The gateway patch

`contrib/neutrino/0001-gateway-federation.patch` applies to the fork at
3fb6945. What it changes and where:

- `neutrino-ctl` `Config`: a derived flag `federation_direct_names`.
  `neutrino-main` sets it whenever the sidecar rides an injected datagram
  link, because the link addresses node ids and nothing else.
- `neutrino-http` `FederationClient`: a second, never-proxied client;
  `via_proxy(dest)` sends a 64-hex node id through the egress and dials
  anything else by name; `with_signer` takes the deployment's event
  signer, and every request now goes through one `request()` that builds
  the `X-Matrix` header as a signature over `{method, uri, origin,
  destination, content}` under `ed25519:1`. Without a signer the header is
  the unsigned form it was. The twelve request sites are unchanged in
  shape; the six construction sites pass the signer and the flag.
- `neutrino-event`: `signable_json_bytes` and `b64_decode` become public;
  `verify_json_signature` checks a plain object's signature.
- `neutrino-main` `keys::HttpKeyResolver`: wraps the medium's resolver;
  for a name it does not understand, fetches
  `http://{name}/_matrix/key/v2/server`, checks the document names the
  server and is signed by the key it advertises, caches until
  `valid_until_ts`. Wired in `event_security`, so nothing in the ffi
  crates changes.
- `neutrino-lb` ingress: forwards `/_matrix/key/` as well as
  `/_matrix/federation/`, so a Spindle can fetch a gateway's key document
  through the federation port.

It does not verify inbound request signatures (step 2), resolve
delegation, or speak TLS: a gateway's upstream is one host the operator
configured, reached over plain http on a venue network the same operator
runs. The Spindle side needs nothing new for this step.

## The open issues, from Spindle's side

**indiafoss-companion #165, venue gateway.** The gateway is the design
above: a Neutrino node with a hostname, listed in `peers`. Its four
questions -- who initiates, how it is named, what it forwards, how it
authenticates -- are answered by: either side (the Spindle dials the URL
in `peers`, the gateway dials the name in the room); by hostname on the
venue network, node id on the mesh, and the key document under the
hostname is the node's own; everything, because it is a federation peer
and not a filter; and by request signatures once step 2 lands, node id
until then on a network the operator controls.

**#166, aliases.** Anchor every conference alias at the Spindle
(`#session-1:conf.example`). The fork already resolves a remote alias over
`query/directory`, and Spindle answers it for its own aliases and resolves
a mesh alias in return (probe four). A phone that cannot see the Spindle
asks the gateway, which holds the room and answers from its own state;
the `aliasServer` in the event manifest is the Spindle's name. No
canonical-alias event has to be minted on the mesh.

**#163, Wi-Fi client isolation.** Isolation blocks phone-to-phone
unicast; it does not block a phone reaching a wired gateway, and it does
not block BLE. So gateways on a wired uplink are the answer to isolation
as well as to fan-out, and the probe-connect that neutrino-iroh already
does on mDNS discovery is the check: a phone that can reach a gateway's
socket has a route, whether or not it can reach the phone next to it.

**#160, identity convergence.** A person is `@alice:conf.example` on the
Spindle and `@<node-id>:<node-id>`-style on the phone, and the two are
different Matrix users. Federation does not merge users; what it gives is
one room with both in it. The honest convergence is at the client: the
Companion app signs the phone's user into the Spindle when it has a
route (Spindle serves ordinary registration and login) and treats the
mesh identity as the offline device. Cross-signing between the two is the
user's own act, exactly as between a laptop and a phone today.

**#129, signing and v12.** Signing is done for events, and this patch
does it for requests. v12 is step 3, and the recommendation there is to
teach Spindle MSC4242 rather than the phone v12.

**#115, a conference Spindle.** `[federation] peers` with patient
backoff, plain-http peer URLs, `allow_internal` for the venue range, the
LiveKit JWT service, and ring limits are all on `main`; the branch name is
`spindle-hub-p2p`, and the config in `scripts/neutrino-interop.sh` is a
working starting point.

**indiafoss-chat-android #26, voice and video calls.** No call code
exists in any of the four repositories, so this is a design answer.
Two things, in this order:

1. *Voice messages over the mesh.* An `m.audio` event with a short Opus
   clip within the 256 KiB media cap is a message, and everything about
   messages already works across BLE and across the seam. It is what a
   venue without connectivity can actually carry, and it needs no new
   protocol.
2. *Calls via a venue LiveKit focus, advertised by Spindle.* MatrixRTC
   (MSC4143) puts call membership in room state (`m.rtc.member`) and the
   media on a selective forwarding unit; Spindle already serves the
   LiveKit JWT service and the OpenID round trip (docs/matrix-rtc.md)
   and advertises foci in `.well-known/matrix/client`. A LiveKit server on
   the venue LAN, reachable by anyone with Wi-Fi, is a focus the Spindle
   advertises; a phone joins the call when it has a route to it and shows
   the call as unreachable when it has only BLE. Peer-to-peer WebRTC over
   the mesh is not viable: BLE has neither the bandwidth for audio nor a
   path for ICE, and every hop is a homeserver, not a router.

## What this page does not promise

- The MSC3995 hub protocol, on either side.
- Delegation. A peer whose name has `.well-known` or SRV delegation is
  reached at the name; `peers` is the explicit override, not a resolver.
- Merging the Neutrino patches upstream. `contrib/neutrino/` is a patch
  against the fork; the fork's owner carries it, and this page records
  what it does so it can be re-derived.
