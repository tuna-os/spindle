# E2EE migration rig (Synapse -> Spindle)

A repeatable test for the hardest gate in
[#240](https://github.com/tuna-os/spindle/issues/240): after a Synapse
database is imported into Spindle, a **fresh device** must decrypt the
history by recovering with its recovery key and the server-side key backup.

The rig puts known E2EE history into a dark copy of the production Synapse,
records a manifest of what was sent, and checks any homeserver URL against
that manifest. It checks the dark Synapse first, so the rig is shown to work
before Spindle is tested. After the import, it checks the dark Spindle.

| Part | Where | What |
|---|---|---|
| `k8s/dark-synapse.yaml` | `spindle-rehearsal` | Single-process Synapse `v1.156.0` (the production image) on the database copy `synapse_dark`, with the production `server_name` and signing key. **Isolated:** see below. |
| `k8s/toolbox.yaml` | `spindle-rehearsal` | `rust:1.94` pod and a 20 Gi PVC. It builds and runs the client. |
| `rig/` | toolbox | `mig-rig`, a matrix-rust-sdk 0.18 client (the release that `contrib/rust-sdk` pins) with `seed` and `verify` modes |
| `rig.sh` | workstation | Driver. It moves secrets through `kubectl` pipes and never prints them. |

Nothing in git contains a password, recovery key, signing key or message
body. Secrets are stored in:

* `secret/dark-synapse-secrets`: `signing.key` (copied read-only from
  `ess/ess-synapse`), `registration_shared_secret` and `secrets.yaml`
  (macaroon and form secrets).
* `secret/spindle-mig-rig`: `password-{a,b,c}` and `recovery-key-{a,b,c}`.
* `configmap/spindle-mig-rig-manifest`: `manifest.json` (room IDs and
  versions, event IDs, Megolm session IDs, and the SHA-256 of each plaintext
  body or state content) and `seed-summary.json`.

## Test data

Three users are created through the shared-secret admin API:
`@spindle-mig-a`, `@spindle-mig-b` and `@spindle-mig-c:reilly.asia`. Each
user has cross-signing bootstrapped, plus secret storage, key backup and a
recovery key (`recovery().enable()`). All of these are checked before
seeding continues.

| Room | Version | Content |
|---|---|---|
| `dm` | 12 | Encrypted DM a<->b: messages, a reply, an edit and a redaction |
| `group` | server default (10 on this deployment) | Encrypted a,b,c, 60+ messages. c leaves, 15 messages go out without c (the Megolm session rotates), then c is re-invited and rejoins. Also an edit, a reply, a redaction, two topic changes and a power-level change |
| `plain` | 11 | Unencrypted: messages, a reply, an edit, a redaction and a topic |
| `v10` | **10** | Encrypted room at version 10 ([#456](https://github.com/tuna-os/spindle/issues/456)): messages, a reply, an edit, a redaction and a topic |

Each manifest event has `readable_by`, the users joined when it was sent.
For the messages that go out while c is absent, `verify` records c's result
as `not-required`. It never counts that result as a failure.

## Run it end to end

```bash
cd scripts/migration-e2ee-rig
./rig.sh secrets          # once: secrets for the dark Synapse + random user passwords
./rig.sh dark-db          # CREATE DATABASE synapse_dark TEMPLATE synapse (pristine restore untouched)
./rig.sh deploy           # dark Synapse; waits for /health
./rig.sh isolation 10     # effective config, resolver, services, 10 min of log + socket watch
./rig.sh toolbox          # build pod + PVC
./rig.sh build            # cargo build --release inside the pod (~15 min cold, ~2 min warm)
./rig.sh seed             # users, recovery, rooms, history; keys -> Secret, manifest -> ConfigMap
./rig.sh verify           # baseline: fresh device for user a against the dark Synapse
```

To start again from a clean copy, run `./rig.sh reset` and then repeat from
`secrets`. This deletes the dark Synapse, `synapse_dark`, the rig Secret and
the manifest. `dark-synapse-secrets` is kept.

## `verify` against another homeserver (the Spindle dark target)

```bash
./rig.sh verify http://<spindle-service>.spindle-rehearsal.svc.cluster.local:<port> a
```

This runs inside the toolbox pod. It reads the password and recovery key for
user `a` from `secret/spindle-mig-rig`, and the manifest from the ConfigMap.
It also prints a JSON report and keeps a copy in `/work/verify/` on the PVC.
The exit code is non-zero when any check fails. The second argument can be
`b`, `c`, a localpart or a full MXID.

`verify` takes these steps:

1. It logs in with the password as a **new device**, using an empty store.
2. It calls `recovery().recover(recovery_key)`. This step needs secret
   storage, the cross-signing keys and the backup decryption key from the
   target. It records whether the new device is now cross-signed by its
   owner.
3. It downloads room keys from the target's backup (`/room_keys/keys/{room}`).
   The client is built without `automatic-room-key-forwarding`, so no key
   can arrive by gossip from another device.
4. It fetches each manifest event with `/rooms/{id}/event/{eid}` and
   classifies it:
   * `decrypted`: the decrypted `body` matches the manifest SHA-256.
   * `plaintext`: an unencrypted-room message whose body matches.
   * `redacted`, `present`: redaction targets, redaction events and state
     events, with type and content hash.
   * `utd` (with the SDK's reason and session ID), `hash-mismatch`,
     `fetch-failed`, `room-not-joined`.
5. It checks each room's version against the manifest.
6. It logs the device out, unless you pass `--keep-device`.

`pass` is true only when all of these hold: recovery succeeded, the device
is cross-signed, each room is present at its recorded version, and every
event a user should read is read correctly.

To run it without the cluster, against any URL:

```bash
cd rig && cargo build --release
RIG_PASSWORD=... RIG_RECOVERY_KEY=... ./target/release/mig-rig verify \
  --homeserver https://hs.example --user a --manifest manifest.json --report report.json
```

## Isolation of the dark Synapse

The dark Synapse has the production `server_name` and the production signing
key, and the CNI does not enforce NetworkPolicy. So isolation is enforced in
layers, and `./rig.sh isolation` shows each layer as Synapse parsed it:

1. `federation_domain_whitelist: []`. Any federation request, outbound or for
   key fetches, is refused in-process with `403: Federation denied` before
   DNS or a socket.
2. `federation_sender_instances: []`, so no process sends federation, and
   `pusher_instances: []` and `push.enabled: false`, so no pushers start.
   There is no `email`, identity server, appservice, URL preview, OIDC, MAS
   delegation, Redis or `trusted_key_servers`.
3. `ip_range_blacklist: [0.0.0.0/0, ::/0]`. Every outbound HTTP client that
   Synapse owns (federation, push, previews) refuses every address.
4. The pod has no resolver (`nameserver 127.0.0.1`). The database is
   reached through a `hostAliases` entry for the `rehearsal-pg` ClusterIP.
5. The only listener serves `client` on 8008. There is no federation
   listener. A ClusterIP Service is the only way in: no Ingress, NodePort or
   LoadBalancer.
6. A `netwatch` sidecar shares the pod's network namespace. Every second it
   reads `/proc/net/{tcp,tcp6,udp,udp6}`. It logs any remote endpoint that is
   not loopback, the database or an inbound client connection as
   `"OUTBOUND"`.

Expected log noise: the copied database contains remote users whose device
lists Synapse retries resyncing. Each retry is logged as
`403: Federation denied with <server>`, a refusal inside the process at
layer 1. Netwatch shows that no socket was opened.

## Limits

* The dark Synapse database is a point-in-time copy. Real users' rows are in
  it but are never read or written by the rig. Only the three
  `spindle-mig-*` users and their four rooms are created.
* The manifest proves decryptability with matrix-rust-sdk, the library under
  Element X. Element Web uses the same crypto crate through WASM, but its
  recovery UI is not exercised. For that, see `scripts/element-web-e2e/`.
