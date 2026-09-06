# Neutrino patches

Two patches, applied in order, against hanthor/neutrino at 3fb6945.

## 0001: gateway federation

`0001-gateway-federation.patch` applies to hanthor/neutrino at 3fb6945
(branch `e2ee-key-transport`), the revision neutrino-iroh pins. It is
what docs/mesh-federation.md calls step one of convergence:

- a Neutrino node dials a peer that is not a node id directly over HTTP,
  instead of handing its name to a datagram link that cannot route it;
- every outbound federation request carries an `X-Matrix` signature under
  `ed25519:1`, verifiable against the node's `/_matrix/key/v2/server`;
- inbound, a key resolver fetches a named peer's key document (checking
  its self-signature) so that peer's events verify on the node;
- the `neutrino-lb` ingress forwards `/_matrix/key/` so a peer can fetch
  the node's document through the federation port.

It does not verify inbound request signatures, resolve delegation, or
speak TLS. The Spindle side needs nothing for it.

To try it:

```sh
git -C neutrino checkout 3fb6945 -b gateway-federation
git -C neutrino am contrib/neutrino/0001-gateway-federation.patch
# in neutrino-iroh/Cargo.toml, for a local build only:
# [patch."https://github.com/hanthor/neutrino"]
# neutrino-ffi  = { path = "../neutrino/crates/neutrino-ffi" }
# neutrino-main = { path = "../neutrino/crates/neutrino-main" }
cargo build --release -p neutrino-ffi-ble --bin neutrino-lan
NEUTRINO_LAN=neutrino-iroh/target/release/neutrino-lan scripts/neutrino-interop.sh
```

Before the patch the node's invite fails after sixty seconds (the
request went to `http://127.0.0.1~:8008` through the egress); after it,
and with this branch's MSC4242 support on the Spindle, every probe
passes: invites both ways, a mesh user joining a Spindle room, the
Spindle joining a mesh room, and messages crossing in both directions.

## 0002: MatrixRTC

`0002-matrixrtc.patch` applies on top of 0001. It is convergence step
four: the two homeserver pieces a call client checks before it will
place a call, which the node served neither of.

- `GET /_matrix/client/v1/rtc/transports` (and the MSC4143 unstable path)
  answers the LiveKit JWT services named in `NEUTRINO_RTC_LIVEKIT_URL`,
  comma separated; unset is a working configuration that answers an
  empty list;
- `org.matrix.msc4140.delay` on `/send` and `/state` holds the event,
  with list, send, cancel and restart under the MSC4140 unstable prefix;
  `restart` re-applies the whole original delay, which is what makes it
  a heartbeat; the send is authorised by the room actor when it fires; a
  day is the longest delay and a thousand the most one user may hold;
- both advertised on `/versions`.

Delays are held in memory and a restart drops them; `rtc.rs` says why
that is the accepted trade on a phone and what the next step is. MSC4354
sticky events are not in this patch.

```sh
git -C neutrino am contrib/neutrino/0002-matrixrtc.patch
cargo build --release -p neutrino-ffi-ble --bin neutrino-lan
NEUTRINO_RTC_LIVEKIT_URL=https://rtc.venue.example/livekit/jwt \
  NEUTRINO_LAN=neutrino-iroh/target/release/neutrino-lan scripts/neutrino-interop.sh
```

The rig's RTC rows go from `none` / `404` / `sent now` to `some` / `200`
/ `held`, and the node's own delayed event fires and reaches the Spindle.
