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
written from both code bases as they stand (Spindle `main`, Neutrino fork
branch `e2ee-key-transport` at 3fb6945, neutrino-iroh at its head), it
records what a loopback federation between the two actually did, and it
answers the open issues on the Companion side from Spindle's side. The rig
that produced the evidence is `scripts/neutrino-interop.sh`; the Neutrino
change it was re-run against is `contrib/neutrino/`.

The design decision the RFC makes -- plain federation, no portal bridge --
is right for Spindle too: this server relays ciphertext and key material
and never holds plaintext, and every endpoint that needs is served
(client-server and federation E2EE, to-device delivery, device-list EDUs,
authenticated media).

## What is true today

Some of what the RFC and the earlier version of this page say about
Neutrino is stale; the fork has moved. Read from the code:

| | Spindle | Neutrino fork (`trusted_network = false`, as neutrino-lan runs it) |
|---|---|---|
| Room versions | 11 and 12, created as 11 | `org.matrix.msc4242.12` only: v12 auth rules over a state DAG (`prev_state_events`, no `auth_events`) |
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
Requests do not, so a Neutrino node cannot yet be authenticated by a
Spindle, and a Spindle's requests are accepted by a Neutrino node on
faith. A Neutrino node can be reached by a Spindle (the `peers` map) but
cannot reach a Spindle, because its only route is a link that addresses
node ids. And the two sides create rooms in versions the other refuses.

## Evidence: one Neutrino node and one Spindle on loopback

`scripts/neutrino-interop.sh` starts `neutrino-lan` (the LAN build of the
fork: iroh, mDNS, no BLE) and a Spindle that lists the node in `peers`,
then runs six probes. Against the unpatched fork:

| probe | outcome | detail |
|---|---|---|
| mesh node key document at its loopback URL | served | `server_name` is the node id; key `ed25519:1` |
| Spindle invites `@n:<node>` into a v12 room | refused | `400 M_INCOMPATIBLE_ROOM_VERSION`, `room_version: org.matrix.msc4242.12` |
| mesh node invites `@alice:<spindle>` | failed | after 60 s: the request went to `http://127.0.0.1~:8008` through the egress, and the link could not address it |
| Spindle resolves `#mesh-session-1:<node>` over federation | resolved | 13 ms; the fork's alias patch answers `query/directory` |
| mesh node answers a federation query with no `X-Matrix` header | 200 | inbound requests are not verified |
| Spindle key document over plain http | 200 | what a key resolver on the gateway fetches |

So the transport and naming layers meet in the middle already -- a
Spindle reaches a node, fetches its keys, and resolves its aliases -- and
the two gaps are the direction mesh to Spindle and the room version. The
first is a small patch; the second is the real work.

Against the fork with `contrib/neutrino/` applied (see below), the third
probe changes: the node dials the Spindle directly, the request carries a
signature Spindle verifies against the node's key document, and the
refusal moves from the transport to the room version -- which is the
right place for it to be.

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

3. **Meet on a room version.** This is the cost that dominates and the one
   the RFC has to decide. Two ways:
   - *Neutrino speaks v12.* Its wire layer is structural for MSC4242
     (`validate.rs` refuses `auth_events` and requires
     `prev_state_events`; `RoomVersions` holds at most two versions), and
     its state resolution is v12's algorithm run over MSC4242 inputs. Adding
     v12 means a version-dispatched validator, an `auth_events` path in
     event building, and state resolution over a DAG on the phone. Weeks,
     and it lands on the phone's battery.
   - *Spindle speaks MSC4242.* Spindle keeps a linear log per room and
     already resolves nothing; an MSC4242 room is a DAG of state events
     where every event names its state ancestors. Spindle would accept the
     version, validate the MSC4242 shape, and treat `prev_state_events`
     as the fork signal it already classifies (docs/divergence.md).
     Smaller than the phone-side change, and the phones stay as they are.
     It is an experimental version, so it belongs behind a config flag and
     on the `spindle-hub-p2p` branch, not in the default set.
   The recommendation is the second, because the mesh is the constrained
   side and because the RFC's "hub" intuition is right: the server with
   the uplink should absorb the complexity.

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
