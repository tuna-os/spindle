# E2EE migration rig: baseline on the dark Synapse (2026-10-03)

This page is evidence for the E2EE gate of
[#240](https://github.com/tuna-os/spindle/issues/240), and for the
encrypted v10 criterion of [#456](https://github.com/tuna-os/spindle/issues/456).
It shows that the rig itself works, measured before Spindle takes part. The
procedure is in
[`scripts/migration-e2ee-rig/README.md`](../../scripts/migration-e2ee-rig/README.md).

## Rig

| | |
|---|---|
| Source | Restore of the production `synapse` database (taken today) into `rehearsal-pg`: 1,840,117 events. Rooms by version: 1×2, 5×3, 6×15, 9×27, 10×188, 11×5, 12×9 |
| Dark copy | `CREATE DATABASE synapse_dark TEMPLATE synapse`. The pristine restore is not touched |
| Dark Synapse | `oci.element.io/synapse:v1.156.0`, the production image. Single process, `server_name: reilly.asia`, production signing key `ed25519:a_qMqD`, MAS delegation off. Namespace `spindle-rehearsal` |
| Client | `mig-rig`, built on matrix-sdk 0.18.0 without `automatic-room-key-forwarding` |

## Isolation evidence

`./rig.sh isolation` shows the effective configuration as Synapse 1.156
parses it:

```
send_federation (this proc)  False
federation_sender_instances  []
start_pushers (this proc)    False
pusher_instances             []
federation_domain_whitelist  {}
trusted_key_servers          []
ip_range_blocklist           ['0.0.0.0/0', '::/0']
url_preview_enabled          False
push.enabled                 False
email notifs / identity      False None
app_service_config_files     []
msc3861 / MAS                False False
redis                        False
listeners                    [(8008, [['client']])]
resolv.conf                  nameserver 127.0.0.1
exposure                     service/dark-synapse ClusterIP 8008 only; no Ingress/NodePort/LB
```

The dark Synapse ran twice: once from 17:44 to 18:03 UTC, and again on a
fresh copy from 18:04 to past 18:14 UTC. The second run covers the seed and
all verify runs. Over the ~30 minutes of the two runs combined, the
`netwatch` sidecar sampled the pod's socket table once per second. It saw
only one remote endpoint, the database (`10.104.171.212:5432`), plus inbound
client connections, and **0 outbound endpoints**. Each heartbeat reported
`"outbound": 0`.

In the second run's Synapse log, `matrixfederationclient` (DEBUG) logged no
requests and no key fetches, and no pusher started ("Not starting pushers
because they are disabled in the config"). There were 152 lines of the form
`_maybe_retry_device_resync: 403: Federation denied with <server>`, for 6
distinct remote servers. These come from real remote users in the copied
database whose device lists Synapse retries. The whitelist refuses each one
inside the process, before name resolution, and netwatch confirms that no
socket was opened.

The sampler checks once per second, so a sub-second connection could pass
between samples. Layers 1, 3 and 4 in the README do not depend on the
sampler.

## Test data (manifest in `configmap/spindle-mig-rig-manifest`)

| Room | Version | Encrypted | Manifest events | Megolm sessions |
|---|---|---|---:|---:|
| `dm` (a<->b) | 12 | yes | 13 | 2 |
| `group` (a,b,c; c leaves and rejoins) | 10 | yes | 68 | 10 |
| `plain` (a,b) | 11 | no | 7 | 0 |
| `v10` (a,b,c) | 10 | yes | 14 | 3 |

There are 102 events in total, 88 of them encrypted, in 15 distinct Megolm
sessions. They break down as 79 messages, 5 edits, 5 replies, 4 redacted
targets, 4 redaction events and 5 state events (3 topics, 1 power-level
change and 1 topic in v10). In the group room, a's session rotates from
`pfWm…` to `Epvd…` when c leaves, and then to `LZv5…` after c rejoins.

All 3 users have cross-signing (master, self-signing and user-signing keys),
secret storage, backup version `1` and a recovery key. Backup counts are
a=15, b=15 and c=11 sessions. At seed time, each seeding device read
everything it should: a 89/89, b 89/89, c 59/59.

## Baseline verify: fresh device and recovery key against the dark Synapse

```
./rig.sh verify                                  # user a
verify PASS: recovery=true cross-signed=true readable 89/89, failures 0
  by_outcome: decrypted 85, plaintext 4, present 9, redacted 4   (102 events)
  rooms: dm v12 ok, group v10 ok, plain v11 ok, v10 v10 ok

./rig.sh verify <url> b   -> PASS, readable 89/89
./rig.sh verify <url> c   -> PASS, readable 59/59
  (c also reports 15 utd + 20 room-not-joined, all `not-required`: sent while c was not a member)
```

Each verify run logs in a new device with an empty store. It recovers through
secret storage, downloads keys from the server-side backup, and logs the
device out again.

## What was found on the way

The first seed attempt could not read 2 of 89 events. A client that sends
before it has fetched its room-mates' device lists shares its Megolm session
with nobody, and the members only receive that session from a later index.
The seed now waits until every member's devices are known before anyone
sends. This was a seeding race, not a server fault. A homeserver that is
slow to deliver `device_lists` changes could produce the same symptom in
real use.

## Next

Import `synapse_dark` into the dark Spindle, then run
`./rig.sh verify http://<spindle>:<port> a`. The pass criteria are the same
as above.
