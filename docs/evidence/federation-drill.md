# Federation drill with an independent witness (2026-10-03)

This page records the drill in
[`docs/synapse-migration-drill.md`](../synapse-migration-drill.md) for
`reilly.asia`, gate "Federation drill with an independent witness server"
of [#563](https://github.com/tuna-os/spindle/issues/563). The raw results
are in [`federation-drill/`](federation-drill/). The rig is in
[`scripts/federation-drill/`](../../scripts/federation-drill/README.md).

## Verdict

| Pass criterion (plan section 5) | Result |
|---|---|
| Synapse A sees the same key ID and public key before and after the cut-over | **Pass** |
| Messages and state changes federate in both directions, in each shared room | **Pass in 5 of 8 rooms.** 3 rooms did not import (importer faults, below) |
| The state on Spindle B is equal to the state of Synapse B at the seal | **Pass in 5 rooms.** The v12 room imported without its create event, so Spindle B cannot show its state. The importer refused 2 rooms |
| Synapse A can verify the signatures on old events from Spindle B | **Pass** after [#570](https://github.com/tuna-os/spindle/pull/570): 148 of 148 events |
| The test clients decrypt messages sent before and after the cut-over | **Pass** (one client-side race, explained below) |
| The rollback rehearsal succeeds | **Pass** |

There were two faults in the federation code of Spindle. Both fixes
are on `main`:

1. [#569](https://github.com/tuna-os/spindle/pull/569): Spindle did not
   read `.well-known/matrix/server`. It could not reach a delegated server.
   `reilly.asia` and matrix.org both use delegation.
2. [#570](https://github.com/tuna-os/spindle/pull/570): Spindle added
   `event_id` to each PDU it served from `/event`, `/backfill` and
   `/get_missing_events`. Synapse refuses such a PDU.

The drill also found four faults in the importer. The importer is the work of
[#557](https://github.com/tuna-os/spindle/pull/557), so this page records
them and does not fix them. See "Importer faults".

The gate is therefore **not complete**. The federation part passes. The
importer must import every room before the drill can pass in full.

## 1. Rig

The rig runs in the `spindle-rehearsal` namespace. CI was not necessary.
The private resolver and the netwatch sidecars give the isolation that the
plan asks for (see "Isolation").

| Part | Revision |
|---|---|
| Synapse A, the witness, `witness.lab` | Synapse v1.156.0, `oci.element.io/synapse@sha256:d2215c4a…`, database `drill_a` |
| Synapse B, `reilly.asia` | The same image, database `drill_b`, production key `ed25519:a_qMqD` |
| Spindle B, pass 1 | #557 at `35848ed`, plus a local stand-in for importer fault 1. Binary `75a07fd9…` |
| Spindle B, pass 2 | Pass 1 plus #569 (binary `39fb0be8…`), then also #570 (binary `a36ed751…`), on the image `ghcr.io/tuna-os/spindle@sha256:2870c411…` |
| TLS front | `nginxinc/nginx-unprivileged@sha256:65e3e85d…`, the same before and after the cut-over |
| Resolver | CoreDNS 1.11.3 |
| Clients | `drill.py` (client API) and `drill-e2ee` (matrix-sdk 0.18.0) |

Both servers use delegation, as `reilly.asia` does in production:
`/.well-known/matrix/server` on the bare name gives `matrix.<name>:443`.
The TLS certificates come from a private CA for the drill.

Synapse B starts from an empty database, not from a copy of the 16 GB
production restore. The rehearsal database shares a disk with production,
and the importer moves only the rooms that it names. The production key
and `server_name` are the ones that matter for this drill.

The local stand-in compares `prev_events` as sets. Without it, no room
with a fork merge imports (importer fault 1). It has the label DRILL-ONLY,
and it is not on any branch that merges.

## 2. Warm-up and baseline (4.1, 4.2)

The rig has no route to the public federation, so the warm-up took place
inside the lab network. Step 4.2 (the move to the isolated network) did
not apply.

| Room | Version | Made by | Content |
|---|---|---|---|
| `v10-general` | 10 | B | 4 members on 2 servers |
| `v12-witness-created` | 12 | A | B joined over federation |
| `v9`, `v6`, `v1` | 9, 6, 1 | B | |
| `history-v10` | 10 | B | 3,275 events from 4 senders on both servers, with topic and name changes |
| `fork-v10` | 10 | B | Contested fork, below |
| `encrypted-v10` | 10 | B | Megolm, both servers, recovery and key backup on both accounts |

**Contested fork.** Both TLS fronts answered 503 to all federation
traffic. During that time, both sides changed `m.room.topic` and
`m.room.power_levels` of `fork-v10`, and A also changed `m.room.name`.
After the partition, each side received the other's branch. State
resolution on both Synapse servers gave the same result: A's topic, A's
name, and power 0 for `@drill-b2`.

**Baseline.** The state map, newest event and forward extremities of each
room are in `baseline-warmup.json` and `extremities-warmup.txt`. In all 8
rooms, the state map on A was equal to the state map on B. Each room had
one forward extremity, and it was the same on both servers. A message in
each direction arrived in each room in 0.5 s (`pingpong-warmup.json`).

**Key.** A fetched B's key through the delegation (`keys-warmup.json`):

```
ed25519:a_qMqD  cQoPy/2xh5Uu/18g41391liTx6tJGyO6t2GaAZyYf6s
```

This is the key that production `matrix.reilly.asia` publishes.

## 3. Seal and import (4.3, 4.4)

`drill.sh seal` waited until no room had unsent PDUs and no destination
was in backoff. Then it stopped Synapse B and made `drill_b_seal` from
`drill_b`. It also put the media store and the key in the `drill-b-data`
volume.

**Divergence list.** The importer replays each room and compares the
result with the current state of Synapse. It refuses a room that diverges.

| Room | Import | Divergence |
|---|---|---|
| `v10-general`, `history-v10`, `encrypted-v10`, `v9`, `v6` | Imported | None |
| `v12-witness-created` | Imported, 17 of 26 events | No state divergence reported, but the create event is missing (importer fault 3) |
| `fork-v10` | Refused: `NeedsStateResolution` on `m.room.power_levels` | Importer fault 4. Synapse and the plan expect a fork here |
| `v1` | Refused: "Synapse metadata and JSON disagree" | Importer fault 2 |

The importer moved the test users `@drill-b1` and `@drill-b2` with their
devices, their cross-signature keys and their key backup
(`import-pass2.log`).

## 4. Pass 1: the cut-over that found the faults

Spindle B (pass 1 build) started in the place of Synapse B, with the same
front, name and key.

- **4.5.1 Key.** A fetched the key from Spindle B through the delegation.
  The key ID and the public key were the same as in the baseline. The
  self-signature verified (`keys-pass1-spindle.json`).
- **4.5.5 Old events: FAIL.** Spindle B answered 401 to all 184 requests
  from A. To check the signature of A, Spindle B must fetch the key of
  `witness.lab`. The fetch went to port 8448 of `witness.lab`. Nothing
  listens on that port, because `witness.lab` uses delegation. The log
  lines are in `spindle-pass1-auth-refusals.txt`. This is fault 1, and
  #569 is the fix.

Spindle B wrote no events in pass 1, so the rollback rehearsal came next.

## 5. Rollback rehearsal (4.7)

`drill.sh rollback` stopped Spindle B and made `drill_b` again from
`drill_b_seal`. It put back the media store, checked that the key file was
the same, and started Synapse B.

- A message in each direction arrived in all 8 rooms, in 0.5 s
  (`pingpong-rollback.json`).
- The state maps on A and B were equal in all 8 rooms
  (`baseline-rollback.json`).
- The device of `@drill-b1` from before the seal decrypted all 30
  encrypted messages (`e2ee-rollback-b.json`).

**Result: pass.** Then, as the plan says, the drill did 4.4 to 4.6 again
and kept Spindle B.

## 6. Pass 2: the cut-over that stays (4.4 to 4.6)

A second seal and import gave the same per-room result as pass 1. Spindle
B started with #569.

**4.5.1 Key: pass.** A fetched `ed25519:a_qMqD` with the same public key.
A kept one key for `reilly.asia` in its cache, the same key as before the
cut-over (`keys-pass2-spindle.json`).

**4.5.5 Old events.** With #569 only, A could fetch events. Synapse then
refused every PDU as invalid JSON, because each one had an `event_id`
field (`oldevents-pass2-v1-sample.json`). This is fault 2, fixed in #570.
With #570, `fedcheck.py events 50` checked the 50 oldest events from
`reilly.asia` in each room:

| Room | Checked | Content hash, signature with A's cached key, and identical to A's copy |
|---|---|---|
| `history-v10` | 50 | 50 |
| `encrypted-v10` | 27 | 27 |
| `v10-general` | 20 | 20 |
| `v9` | 21 | 21 |
| `v6` | 21 | 21 |
| `v12-witness-created` | 9 | 9 |
| `v1`, `fork-v10` | 47 | 0: not imported, 404 |

**4.5.2 and 4.5.3 Messages: pass in 5 rooms.** The 5 rooms are
`encrypted-v10`, `history-v10`, `v10-general`, `v6` and `v9`. In each, a
message from each side arrived on the other side in 0.5 to 1 s
(`pingpong-cutover2.json`).
`v12-witness-created` refused traffic in both directions (importer fault
3). `v1` and `fork-v10` do not exist on Spindle B.

**4.5.4 State changes: pass in the same 5 rooms.** In each room, B gave
the witness power 100 and set a topic. Then A set a topic. Both servers
showed the same power levels and the same topic after each change
(`statechange-cutover.json`). After the changes, the full state map on A
was equal to the state map on B in all 5 rooms (`baseline-cutover.json`).

**4.5.6 Encrypted room: pass.** `@drill-b1` could not use its old access
token, because the importer does not move tokens. It signed in on Spindle
B with a new device. It took the room keys from the server-side backup
with its recovery key.

| Reader | Messages from before the cut-over | Messages from after the cut-over |
|---|---|---|
| `@witness` on A, the same device as in the warm-up | 30 of 30 | 30 of 30 |
| `@drill-b1` on Spindle B, a new device | 30 of 30 | 29 of 30 |

The one failure is the first message that A sent after the cut-over.
A's client encrypted it before it knew the new device. It then shared the
session from message index 1, so the new device cannot read message 0.
Spindle B sent the device list update to A in the same second that the
device appeared (A's log, `m.device_list_update`).

A second batch of 10 messages from A decrypted 10 of 10. This is the usual result
for Megolm when a user adds a device. It is not a server fault.

The `/sync` of `@drill-b1` on Spindle B fails as a whole while the account
is in the broken v12 room (importer fault 3). For this reason, the E2EE
client uses a filter to leave that room out of `/sync` (`sync-exclude`).

**4.6 Observation: pass, shortened.** The observation took 75 minutes,
from 2026-10-03 22:55Z to 2026-10-04 00:16Z. Every 2 minutes, the drill
sent a message each way in the 5 rooms that work. Every 10 minutes, it
changed state from both sides in the same rooms (`observation.txt`,
`observation-rounds.json`). The witness also logged 12 refusals of its own
topic changes in rooms where it has no power. These come from the rig.

- 24 of 25 rounds delivered every message in both directions, in at most
  1.02 s. Round 1 used a script that still included the 3 broken rooms,
  and it timed out on those rooms only.
- All 5 state rounds passed in all 5 rooms.
- The witness logged no signature failure and no rejected event from
  `reilly.asia` (`witness-warnings.txt`). Its 24 warnings about
  `reilly.asia` are refusals by Spindle B in the 3 rooms that did not
  import. Spindle B logged no warning or error outside those rooms.
- The outbox of Spindle B did not grow: every message arrived within a
  round.

## 7. Isolation

| Check | Result |
|---|---|
| netwatch `OUTBOUND` sockets, drill-a (the whole run) | 0 |
| netwatch `OUTBOUND` sockets, drill-b | 0 in each sample: Synapse B in the warm-up, Spindle B in pass 1, and Spindle B (final build) to the end |
| Names asked of the lab resolver by the servers | Only `reilly.asia`, `matrix.reilly.asia`, `witness.lab`, `matrix.witness.lab` (`resolver-queries.txt`) |
| Names that the resolver refused | 6, all from a manual test in the client pod (`example.com`, and an IPv6 lookup of `drill-b`) |

netwatch samples the socket table every 200 ms, so it can miss a
connection that the peer refuses at once. One such case is the pass 1
connection to port 8448 of `witness.lab`. That address is the Service of
the witness. The Service has no port 8448, so nothing else received the
connection.

**A rig fault, found and corrected.** In the first warm-up, the login
response of Synapse B named `matrix.reilly.asia` as the homeserver, and
`drill-e2ee` followed it. The client pod used the cluster resolver, so
these requests went to production. The client sent a lab access token.
Production answered 401 (unknown token) to each request. The lab token is
not valid in production, and no request carried a server key. Now the
client stays on the URL that it gets, and the client pod uses only the
lab resolver.

## 8. Importer faults (reported on #557)

1. `prev_events` order: `event_edges` has no order, but `persist_rehearsal`
   compares the order. Every room with a fork merge fails.
   ([comment](https://github.com/tuna-os/spindle/pull/557#issuecomment-5973804231))
2. Room version 1 `prev_events` are `[id, hashes]` pairs, and the importer
   reads them as strings. Every v1 room fails. (Same comment.)
3. A room that B joined over federation loses its outliers, the create
   event included. The room cannot be used, and the account's `/sync`
   fails. ([comment](https://github.com/tuna-os/spindle/pull/557#issuecomment-5974358891))
4. The importer refuses a contested fork with `NeedsStateResolution`.
   (Same comment.)

Fault 3 also shows a robustness gap in Spindle: one room that `/sync`
cannot render makes the whole `/sync` fail. The comment on #557 records
it.

## 9. What is still open for this gate

- Importer faults 1 to 4. After the fixes, run the drill again with
  `scripts/federation-drill/`. Then all 8 rooms must pass.
- SRV-only peers. #569 resolves `.well-known` but not SRV records.
- A full 24 h observation. This drill observed for 75 minutes.
