# Neutrino gateway patch

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
