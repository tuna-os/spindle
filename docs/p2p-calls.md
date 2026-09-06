# Peer-to-peer calls: full mesh, no SFU

What a voice or video call looks like when there is no media server to
carry it -- a mesh with no uplink, a room of five people on a LAN, a
hall where the only servers are phones -- and what this server does for
it, measured with the real client.

## Two kinds of call

Element Call's current line carries media through a LiveKit SFU and
nothing else: every participant sends one stream up and receives the
others down, which is how a session room holds hundreds. It is what
docs/matrix-rtc.md deploys and what `contrib/element-call` proves
against this server. It needs the SFU reachable, and at a venue that
means the uplink or a LiveKit on the venue LAN.

The other kind is **full mesh**: every participant holds a WebRTC
connection to every other, and media goes straight between them. No
server touches it. It scales as the square of the room -- five is
comfortable, seven is the ceiling Element found -- and that is exactly
the size of a corridor conversation, a DM, a team huddle. Element Call
shipped full mesh first and moved off it in mid-2023; the implementation
lives frozen on the `full-mesh` branch, built on matrix-js-sdk's MSC3401
group calls:

- call membership is room state, `org.matrix.msc3401.call.member`, one
  per participant, with the devices in the call;
- WebRTC offers, answers and ICE candidates ride **to-device messages**
  (`m.call.invite`, `m.call.answer`, `m.call.candidates`, …), Olm
  encrypted, between the two devices of each pair;
- TURN, if there is one, comes from `/voip/turnServer`; on a LAN the host
  candidates connect and no relay is needed.

Everything in that list is an ordinary homeserver duty, and this server
serves all of it. The one thing it did not was the API prefix: a 2023
matrix-js-sdk asks for `/_matrix/client/r0/…`, which the spec deprecated
and every homeserver in the wild still answers. This server now does too
(`legacy_prefix` in routes.rs, pinned by `tests/legacy_prefix.rs`).

## Evidence

`contrib/element-call-full-mesh/run.sh` builds the `full-mesh` branch at
its last commit, points it at a Spindle that was empty a moment ago, and
drives two browsers through a call with `e2e.cjs`: Alice creates the
call as a guest, joins; Bob opens the invite link as a guest, joins; both
see two tiles with the other's video playing; Bob leaves and Alice sees
it. The script reads each `RTCPeerConnection`'s selected candidate pair:

```
--- alice creates the call as a guest
--- alice joins
--- bob opens the invite as a guest
--- bob joins
--- media flows both ways, peer to peer
alice: 2 tiles, both playing
bob: 2 tiles, both playing
alice: candidate pairs ["host->host"]
bob: candidate pairs ["host->host"]
--- bob leaves and alice sees it
full-mesh call: ok
```

`host->host` is the claim: the media went between the two browsers
directly, with no SFU and no relay in the path. The `full-mesh-e2e` job
in `.github/workflows/compliance.yml` runs it nightly and on demand.

The browsers' cameras and microphones are synthesized in the page (a
painted canvas and a Web Audio oscillator), because Chromium's own fake
devices need a media stack a CI runner may not have. The tracks are real
and cross the real peer connection; only their origin is faked.

## At the venue

Which kind a room uses is the client's decision, not the server's, and
today it is two clients: the current Element Call for LiveKit rooms, the
full-mesh build for rooms with no SFU. The venue serves both from the
same homeserver; docs/venue-playbook.md says where each is linked from.

Across the mesh seam, the pieces a full-mesh call rides -- to-device
messages, device keys, `org.matrix.msc3401.call.member` state -- all
cross to a Neutrino node (docs/mesh-federation.md, the encryption and
calls tables), so a full-mesh call between a participant on a Spindle
and one on a mesh node has nothing in its way at the protocol level. It
has not been driven end to end: the rig above is one server, two
browsers. Doing it across the seam is the next measurement.

What the client does not do, and no server can add: a call of more than
a handful. Above that, media has to go through something, and that is
the LiveKit path.

## Running it

```sh
# builds the server, clones and builds the full-mesh branch (node 22,
# yarn 1), installs nothing globally
contrib/element-call-full-mesh/run.sh

# with a prebuilt client
FULL_MESH_DIST=/path/to/element-call/dist contrib/element-call-full-mesh/run.sh
```

It needs the pinned Playwright from `scripts/element-web-e2e` (`npm ci`
there, then `npx playwright install chromium`). Screenshots and the
server log land in `tmp/element-call-full-mesh/`.
