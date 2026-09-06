# The venue playbook: setting up the mesh and the conference Spindle, and testing it for 3,000 attendees

This is the operator's and tester's companion to docs/mesh-federation.md.
That page is the design; this one is what to build, what to run, in what
order, and what number has to come out of each run before the next one is
worth doing. It ends with the go/no-go list for the conference and the
runbook for the days it is on.

The honest summary first. **What is proven** is the seam: a Neutrino node
and a Spindle federate in both directions in an MSC4242 room, with every
event signed and verified, and a hundred Neutrino nodes converge on one
machine when joins are spread out. **What is not proven** is the radio
and the crowd: nothing here has run over real Bluetooth with real phones,
and nothing has run a gateway tier against a Spindle at more than one node
a side. The ladder below is ordered so that each rung answers the cheapest
unanswered question, and the go/no-go list refuses the conference until
the rungs that involve phones have been climbed.

## 1. The parts

| Part | Where | Revision to use |
|---|---|---|
| Spindle | tuna-os/spindle | `main` at or after #372 (MSC4242 rooms, `[federation] peers`) |
| Neutrino fork | hanthor/neutrino, branch `e2ee-key-transport` | 3fb6945 plus `contrib/neutrino/0001-gateway-federation.patch` |
| Neutrino LAN and BLE builds | hanthor/neutrino-iroh | head, built against the patched fork |
| Companion app and harness | hanthor/indiafoss-companion | head; `tools/neutrino-probe` is the swarm harness |
| Chat app | hanthor/indiafoss-chat-android | head |

Three roles run this software (docs/mesh-federation.md, "The system"):

- **Phones** run Neutrino over BLE and Wi-Fi and federate with each other
  and with gateways. They never federate with the Spindle.
- **Venue gateways** are Neutrino nodes on machines with the venue's
  uplink: a laptop or small computer per hall, three to five in all. They
  are the Spindle's only federation peers and the only mesh nodes that
  dial a hostname.
- **The conference Spindle** is the room's home for everyone with
  internet. It creates the session rooms under `org.matrix.msc4242.12`
  and owns the aliases.

## 2. Setup

### 2.1 Build

```sh
# Spindle
git clone https://github.com/tuna-os/spindle && cd spindle
cargo build --release -p spindle-server          # target/release/spindle

# The fork, with the gateway patch
git clone -b e2ee-key-transport https://github.com/hanthor/neutrino
git -C neutrino checkout 3fb6945 -b gateway-federation
git -C neutrino am ../spindle/contrib/neutrino/0001-gateway-federation.patch

# The LAN/BLE node, pointed at the patched fork (local build only)
git clone https://github.com/hanthor/neutrino-iroh
cat >> neutrino-iroh/Cargo.toml <<'TOML'
[patch."https://github.com/hanthor/neutrino"]
neutrino-ffi  = { path = "../neutrino/crates/neutrino-ffi" }
neutrino-main = { path = "../neutrino/crates/neutrino-main" }
TOML
cargo build --release --manifest-path neutrino-iroh/Cargo.toml -p neutrino-ffi-ble --bin neutrino-lan
```

The patch is what lets a gateway reach the Spindle by name and sign its
requests; without it the mesh side of every test below fails at the first
hop. When the fork carries the change itself, drop the `[patch]` block.

### 2.2 The conference Spindle

One host with a public name (`conf.example` below), a TLS terminator in
front of 8448 for the public internet, and a plain-http listener the
venue network can reach. The venue-facing parts of `spindle.toml`:

```toml
[server]
name = "conf.example"

[federation]
# The gateways, by node id (the 64-hex key each one prints at start).
# Plain http on the venue LAN, and an hour's patience for one that is dark.
peers = {
  "<gateway-1 node id>" = { url = "http://10.20.0.11:8008", max_backoff_ms = 3600000 },
  "<gateway-2 node id>" = { url = "http://10.20.0.12:8008", max_backoff_ms = 3600000 },
  "<gateway-3 node id>" = { url = "http://10.20.0.13:8008", max_backoff_ms = 3600000 },
}
# The venue's range, so those literal addresses are allowed.
allow_internal = ["10.20.0.0/16"]
retry_base_ms = 1000

[ratelimit]
# Ring pushes are the expensive notification; ten a minute per user.
rings_per_minute = 10

[metrics]
# Scrape from the operations laptop; the exposition names the peers.

[rtc]
# A LiveKit SFU on the venue LAN, advertised as a focus (docs/matrix-rtc.md).
```

Register the organiser accounts, create each session room with
`room_version: org.matrix.msc4242.12`, and set its alias
(`#session-<id>:conf.example`). The app's `messaging.aliasServer` is
`conf.example`, so every attendee resolves the same room.

Check it stands: `/_matrix/key/v2/server` answers over both listeners,
`/_matrix/client/v3/capabilities` lists the state-DAG version as
unstable, and `spindle_build_info` is on the metrics port.

### 2.3 A gateway

```sh
neutrino-lan --bind 127.0.0.1:8008 --storage /var/lib/gateway \
             --fed-port 8448 --peer <another gateway id>@<its ip>:8448
```

The first line it prints is its server name, the node id: put it in the
Spindle's `peers`. Two flags are load-bearing and the Companion project's
`docs/test-gateway.md` explains why: `--fed-port` puts federation on the
CoAP sidecar over the iroh link, and `--storage` holds the identity, so
**back the directory up before touching it** -- deleting it renames the
gateway and orphans every room it is in. Run it under systemd with
lingering, as the test gateway is.

A gateway joins every session room through the Spindle
(`/join/<alias>?server_name=conf.example`) before the doors open, so the
mesh has a copy to join from.

### 2.4 The app bundle

Point `messaging.aliasServer` at the Spindle's name. Keep the two client
rules the loopback swarm made non-negotiable (Companion
`docs/neutrino-scale.md`): a random delay of a few seconds before joining
a room a crowd opens at once, and rooms per session rather than per
track, with a hundred members as the design ceiling on the mesh.

## 3. The test ladder

Each rung names what it exercises, the command, the number that has to
come out, and what a failure means. Do not skip a rung: the ones above
assume the ones below.

### Rung 0: the code, on one machine

*What:* the seam's mechanics with no network at all.

```sh
cargo test -p spindle-core --lib version
cargo test -p spindle-server --test state_dag_rooms --test federation_fork --test federation_peers
```

*Pass:* all green. *A failure here* is a regression in either repository
and stops everything.

### Rung 1: one node, one Spindle, loopback

*What:* every federation surface the seam uses, in both directions.

```sh
NEUTRINO_LAN=neutrino-iroh/target/release/neutrino-lan \
SPINDLE_BIN=target/release/spindle scripts/neutrino-interop.sh
```

*Pass:* nine of nine probes, as recorded in docs/mesh-federation.md:
invites both ways accepted, the mesh user joined through `make_join` and
`send_join`, messages crossing both ways, the Spindle joined a mesh room
seeded from its state DAG, the alias resolved. *A failure here* is a
version or signing mismatch; the rig prints the peer's refusal.

### Rung 2: a swarm on a shaped link, with a gateway tier

*What:* the mesh's own behaviour on links that look like the venue's,
using the Companion harness, which shapes delay, jitter, loss and
bandwidth per node and can cut and heal a link.

```sh
export NEUTRINO_BIN=.../neutrino-lan
pnpm --filter @indiafoss/neutrino-probe swarm -- --size 24 --profile ble
pnpm --filter @indiafoss/neutrino-probe swarm -- \
  --size 50 --profile ble --gateways 3 --gateway-profile wifi --stagger 250
pnpm --filter @indiafoss/neutrino-probe swarm -- \
  --size 100 --profile wifi --gateways 3 --stagger 250
```

*Pass:* every node joins, one message reaches every node, and p90
delivery is under the profile's expectation: under a second on `wifi`,
single-digit seconds on `ble`. *A failure here* is the mesh, not the
seam; the number to keep is p50/p90 delivery per profile per size, in a
table beside the loopback one.

### Rung 3: the swarm's gateways federated with a Spindle

*What:* the whole path end to end in software: a phone on a shaped BLE
link, a gateway on Wi-Fi, a Spindle on the far side of a WAN profile.

Today the harness has no Spindle in it; this rung is done by hand until
`runSwarm` grows a `--spindle` flag (the next tool change, and the one
this playbook asks for). By hand: start a Spindle as in §2.2 with the
swarm's gateways in `peers` (their node ids print in the harness log),
create a room on the Spindle, have each gateway join it via the Spindle,
then have the swarm's phones join through their gateway and send.

*Pass:* a message from a Spindle account reaches every phone, and a
message from a phone reaches the Spindle account, within the Rung 2
budget plus one WAN round trip. *A failure here* isolates to one hop:
Spindle-gateway (check `spindle_federation_queue_depth` for the gateway's
name), or gateway-phone (the harness's own delivery table).

### Rung 4: the Spindle at conference load, alone

*What:* the side that carries everyone with internet: three thousand
accounts, three thousand sync waiters, the announcements room, push.

Spindle's benchmark tooling already runs sittings against a server
(`scripts/api-benchmark.py`, `scripts/sitting.py`, docs/benchmarks.md);
use it with a 3,000-account, one-big-room population: every account
long-polling `/sync`, one announcement a minute, a ring to every account
once. Watch `spindle_sync_lag_seconds`, `spindle_append_duration_seconds`
and `spindle_http_request_duration_seconds`.

*Pass:* sync lag stays under a second at 3,000 waiters, the announcement
reaches all waiters within a few seconds, and ring delivery obeys
`rings_per_minute` rather than melting the pusher. *A failure here* is
capacity on the box: more cores or a second instance, both of which are
ordinary operations questions.

### Rung 5: the radio, with real phones

*What:* the two numbers no server test can produce: bytes per second per
BLE link, and hop latency, in a room full of people and bodies.

Ten to twenty phones with the app, one room, one message per second from
one phone for five minutes, then the same with a gateway laptop in the
room joined to a Spindle room. Read the app's mesh peers list and the
gateway's journal.

*Pass:* messages arrive on every phone within ten seconds at twenty
phones, and the gateway relays a Spindle message to the room within the
same budget. Record the peer count each phone sees. *A failure here* is
the transport, and it changes the design: fewer members per mesh room,
more gateways, or Wi-Fi as the primary hop with BLE as the fallback.

### Rung 6: a dress rehearsal

*What:* a meetup or a day at the office with a hundred or more people,
the full stack, the real app bundle pointed at a staging Spindle.

*Pass:* the day passes with the runbook (§6) needing nothing but its
first line. Everything it needed beyond that becomes a rung above.

## 4. What 3,000 attendees means, in numbers

The population is not one room. It is:

- **The announcements room**, everyone in it. This lives on the Spindle,
  and the Spindle is built for exactly this shape: one append, three
  thousand sync waiters woken. Rung 4 measures it. Attendees with any
  internet, including the venue Wi-Fi, read it from the Spindle directly.
- **Session rooms**, tens to low hundreds each, one per talk, booth and
  hall. These are the mesh's rooms. A hundred is the ceiling the loopback
  swarm converged at when joins were spread over seconds, and the join
  storm is the failure mode: the app's join jitter is what keeps it a
  ceiling and not a cliff.
- **Direct messages**, two nodes. Free.

The open question, and the only one that could sink the announcements
room for the offline, is **announcements to phones with only BLE**. A
gateway holds the room and fans each announcement out to every phone
member it can see, one transaction per phone, over a shared radio. The
arithmetic is bytes per announcement, times phones per gateway, divided
by the per-link throughput Rung 5 measures. If a two-kilobyte
announcement to two hundred phones on one gateway takes longer than a
minute, the answer is more gateways or a smaller mesh copy of that room,
and Rung 5 is where that number comes from. Until it exists, plan for
announcements reaching offline phones late, not not at all: the gateway
keeps the outbox and delivers when the phone is in range, which is what
`max_backoff_ms` is for.

## 5. Go/no-go

Go only when every line holds.

- [ ] Rungs 0 to 4 green on the revisions in §1, with their numbers
      recorded in this repository (a table under docs/evidence).
- [ ] Rung 5 run at least once with twenty phones; p90 under ten seconds.
- [ ] Rung 6 run once with a hundred people, and its incident list
      folded back into the ladder.
- [ ] Three or more gateways placed, each on a wired uplink, each listed
      in the Spindle's `peers`, each joined to every session room.
- [ ] The Wi-Fi isolation check passed: a phone on venue Wi-Fi can reach
      a gateway's federation port even when it cannot reach another
      phone (Companion #163; gateways on wired uplinks are the answer).
- [ ] Gateway identity directories backed up, and one restore drilled.
- [ ] Spindle backup drilled (docs/lifecycle.md) and the restore
      brought the rooms back with their aliases.
- [ ] The app bundle's `aliasServer` is the Spindle's name, join jitter
      is on, and session rooms are per session.
- [ ] Metrics scraped from the operations laptop, with the three panels
      in §6 on screen.
- [ ] The two known gaps below are either fixed or accepted in writing.

## 6. The runbook for the event

**The panels.** `spindle_federation_queue_depth` per peer (a gateway
that is dark shows as a rising queue and nothing else), `spindle_sync_lag_seconds`
(the announcements room's health), and `spindle_http_request_duration_seconds`
by route. On each gateway, `journalctl --user -u indiafoss-gateway -f`.

**A gateway goes dark.** Nothing to do for a while: the Spindle's outbox
keeps its rows and retries on the patient schedule; the phones near it
keep federating with each other and with other gateways in range. If it
does not come back in an hour, restart it on the same storage directory;
the outbox redelivers. Never start it on a fresh directory.

**The uplink goes.** The mesh keeps working among itself; the Spindle
keeps working for the internet. When the uplink returns the gateways'
outboxes drain into the Spindle and the Spindle's into the gateways.
Expect the announcements room to catch up in the order the gateways
reach it.

**A join storm** (a talk starts and a hall opens the room at once):
the symptom on a gateway is `504 M_UNKNOWN: timed out applying room
state`. The fix is the client jitter that should already be on; if it is
not, nothing on the server side helps and the room converges in minutes
rather than seconds.

**The Spindle restarts.** Sub-second on a warm box; sync waiters
reconnect. If it does not come back, restore from the last backup; the
gateways' outboxes redeliver what it missed.

**Two gateways disagree about a session room** (a state-DAG fork that
neither side names the other's event in). The Spindle sets the contested
key aside and keeps taking writes; the gateways run state resolution and
may pick the other branch until the resolver lands on Spindle. Expect a
room name or topic to differ between sides, never a lost message.

## 7. Known gaps

1. **State-DAG fork resolution on Spindle.** A contested key is set aside
   rather than resolved (docs/divergence.md, #16). Two gateways cannot
   produce a fork the Spindle cannot fold unless they write the same key
   while partitioned from each other; harmless for a conference room,
   and the next piece of work regardless.
2. **Inbound request verification on the gateway.** The fork reads the
   `X-Matrix` origin and does not check its signature. On a venue LAN the
   operator runs, that is a network-layer trust the design accepts; on a
   gateway reachable from the internet it is not. The next Neutrino
   patch, and the reason a gateway's federation port faces the venue
   network only.
3. **No Spindle in the swarm harness.** Rung 3 is manual until
   `runSwarm` grows a `--spindle` flag.
4. **No radio numbers.** Rung 5 has not been run. Everything in §4 that
   depends on BLE throughput is arithmetic waiting for its inputs.
