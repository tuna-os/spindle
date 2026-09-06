# The venue gateway

A venue gateway is a Neutrino node that has the venue's uplink. It is the
one kind of mesh node the conference Spindle federates with, and the one
kind of mesh node that dials a hostname. Everything else about it is an
ordinary node: it holds rooms, signs its events with its node key, and
gossips with the phones around it. It carries no bridge logic, because
there is nothing to bridge -- both sides speak Matrix federation, in the
same room version (docs/mesh-federation.md).

This page is the operator's: what to run, on what, with which flags, and
how to know it is working. The design is in docs/mesh-federation.md and
the test ladder in docs/venue-playbook.md.

## What it is for

Three to five of them, one per hall, so that:

- the Spindle has a handful of peers it can wait hours for, instead of
  three thousand phones it cannot;
- a phone with only the mesh reaches the Spindle's rooms through the
  copy the nearest gateway carries, and the Spindle hears the phone's
  events the same way;
- the deterministic aliases (`#session-<id>:conf.example`) resolve for a
  phone that cannot see the Spindle, because the gateway holds the room.

## The machine

A laptop or a small computer per hall, on mains power, with:

- **a wired uplink** to the venue router, so the Spindle can reach it and
  it can reach the Spindle whatever the Wi-Fi is doing;
- **an address on the venue LAN** the phones can reach. Client isolation
  on the venue Wi-Fi blocks phone-to-phone unicast; it does not block a
  phone reaching a wired host, which is what makes the gateway the answer
  to isolation as well as to fan-out (companion issue #163).

The LAN build (`neutrino-lan`) has no Bluetooth. A laptop gateway serves
phones that are on the venue Wi-Fi, and the BLE mesh reaches it through
any phone that has both radios. A gateway that phones must reach over
Bluetooth alone is a phone-class device running the BLE build, placed
where the crowd is; treat it as the same role on different hardware.

## Build

The fork needs `contrib/neutrino/0001-gateway-federation.patch`, which
is what lets a node dial the Spindle by name and sign its requests.
Without it every request from the gateway to the Spindle dies inside the
node's own egress after sixty seconds.

```sh
git clone -b e2ee-key-transport https://github.com/hanthor/neutrino
git -C neutrino checkout 3fb6945 -b gateway-federation
git -C neutrino am spindle/contrib/neutrino/0001-gateway-federation.patch

git clone https://github.com/hanthor/neutrino-iroh
cat >> neutrino-iroh/Cargo.toml <<'TOML'
[patch."https://github.com/hanthor/neutrino"]
neutrino-ffi  = { path = "../neutrino/crates/neutrino-ffi" }
neutrino-main = { path = "../neutrino/crates/neutrino-main" }
TOML
cargo build --release --manifest-path neutrino-iroh/Cargo.toml \
  -p neutrino-ffi-ble --bin neutrino-lan
```

When the fork carries the change itself, drop the `[patch]` block.

## Run

```sh
neutrino-lan --bind 10.20.0.11:8008 \
             --storage /var/lib/indiafoss-gateway \
             --fed-port 8448 \
             --localpart gateway-hall-a \
             --peer <other gateway id>@10.20.0.12:8448
```

The first line it prints is its server name: the node id, 64 hex
characters, which is also its signing key. Every flag matters:

| flag | what it does | what goes wrong without it |
|---|---|---|
| `--bind <addr:port>` | The HTTP listener: the client API for the gateway's own user, and the federation routes the Spindle dials. Bind it on the LAN address, not loopback. | Bound on loopback, the Spindle cannot reach it. |
| `--storage <dir>` | Holds the node secret, and so the node id, and every room. | A fresh directory is a different server: every alias it owned and every room it was in are orphaned. Back it up before touching it. |
| `--fed-port <port>` | The mesh-side federation port: CoAP over the iroh link, for phones and other gateways. | Without it the node federates over plain HTTP to `http://<64-hex id>`, which has no DNS behind it, and every mesh request is a 502 while discovery looks healthy. |
| `--localpart <name>` | The gateway's own user, the one that joins the session rooms. | Defaults to `n`. Name it after the hall. |
| `--peer <id>@<ip:port>` | Seeds another gateway so the gateways find each other without waiting for mDNS. | They still find each other by mDNS on one LAN; across VLANs they do not. |
| `--server-name` | Overrides the derived name. **Do not set it** on a gateway: the name has to be the node id for phones to verify its events without a fetch. | |

Run it under systemd as a user unit with lingering, the way the
companion project's test gateway runs, so it survives logout and reboot:

```ini
# ~/.config/systemd/user/indiafoss-gateway.service
[Unit]
Description=IndiaFOSS venue gateway (Neutrino)
After=network-online.target

[Service]
ExecStart=%h/bin/neutrino-lan --bind 10.20.0.11:8008 --storage %h/indiafoss-gateway --fed-port 8448 --localpart gateway-hall-a
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now indiafoss-gateway
loginctl enable-linger "$USER"
journalctl --user -u indiafoss-gateway -f
```

Restarts are safe. The store is crash-safe and the outbox is what a
restart redelivers from; a gateway that comes back on the same storage
directory picks up where it stopped.

## Pair it with the Spindle

On the Spindle, list the gateway by its node id at the address of its
`--bind` listener, and be patient with it:

```toml
[federation]
peers = { "<gateway node id>" = { url = "http://10.20.0.11:8008", max_backoff_ms = 3600000 } }
allow_internal = ["10.20.0.0/16"]
```

The Spindle fetches the gateway's key document from that URL, verifies
every event and every request the gateway sends against it, and retries
a dark gateway on a schedule that reaches an hour and never drops a row.

Check the pairing from the Spindle's host:

```sh
curl -s http://10.20.0.11:8008/_matrix/key/v2/server | jq .server_name
# the gateway's node id
```

Then have a Spindle account invite the gateway's user into a session
room; the invite is accepted within a second when the gateway can reach
the Spindle's name, and refused with a transport error if it cannot.

## Join the rooms

Before the doors open, the gateway's user joins every session room
through the Spindle, so the mesh has a copy to join from:

```sh
G=http://10.20.0.11:8008
for alias in session-keynote session-hall-a-1 session-hall-a-2; do
  curl -s -X POST "$G/_matrix/client/v3/join/%23$alias:conf.example?server_name=conf.example" \
    -H 'content-type: application/json' -d '{}'
done
```

Each join is a `make_join`/`send_join` handshake against the Spindle,
and the gateway is seeded from the room's state DAG. A phone then
resolves the alias at the gateway and joins there.

## Security posture

- Every event the gateway sends is signed with its node key, and the
  Spindle verifies it. Every request it sends is signed too (the patch),
  and the Spindle verifies that.
- The gateway does **not** yet verify the signatures on requests it
  receives; it trusts the `X-Matrix` origin. On a venue LAN the operator
  runs, that is acceptable. It is why the `--bind` port faces the venue
  network only: never expose it to the internet. Fixing this is the next
  patch to the fork.
- The gateway's client API accepts open registration and has no
  authentication in the LAN build. Same rule: LAN only.
- A gateway relays ciphertext and keys for encrypted rooms and never sees
  plaintext (docs/mesh-federation.md, "Encryption").

## When it goes wrong

| symptom | where to look | what it usually is |
|---|---|---|
| Spindle's `spindle_federation_queue_depth` rises for the gateway's id | the gateway's journal | The gateway is dark or its `--bind` address changed. The rows wait; nothing is lost. |
| Invite from the gateway refused, `M_UNAUTHORIZED` from the Spindle | Spindle log at debug | The gateway's key document is not reachable at the `peers` URL, or the patch is missing and the request is unsigned. |
| Invite refused, `M_INCOMPATIBLE_ROOM_VERSION` | either side | The room was created under a version the other side does not speak. Session rooms are created under `org.matrix.msc4242.12` on the Spindle. |
| `504 M_UNKNOWN: timed out applying room state` on a join | the gateway | A join storm: a hall opened the room at once. The room converges in minutes; the fix is the app's join jitter. |
| Phones see the gateway in their peer list but nothing crosses | both machines' routes | A host-side routing policy, a tailscale exit node without LAN access, looks exactly like client isolation from outside. Check the route table before blaming the Wi-Fi. |
| Everything works from a laptop, nothing from a phone on the same Wi-Fi | the access point | Client isolation. Phones must reach the gateway's wired address; if they cannot, the gateway is on the wrong side of the AP. |

## Test it

`scripts/neutrino-interop.sh` runs one gateway-shaped node and one
Spindle on loopback and prints fifteen probes; it is the fastest way to
know a build of the patch still works. Against a real gateway, run the
same probes by hand in this order: key document, invite in each
direction, the gateway's user joining a Spindle room, a message each
way, a key query each way, a to-device message each way. The playbook's
rung 1 is this list.
