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

## The dark Spindle

```bash
./rig.sh spindle-build <git-ref>   # spindle --features synapse-import, built in the toolbox
./rig.sh spindle-import            # empty store, import, start the server
./rig.sh spindle-isolation         # switches, resolver, exposure, netwatch summary
./rig.sh verify http://dark-spindle.spindle-rehearsal.svc.cluster.local:8008 a   # also b, c
./rig.sh element dark-spindle a    # also b, c, and dark-synapse for the baseline
```

`spindle-import` runs `spindle import-synapse-rehearsal` (PR #557) in a Job.
In one run it imports every manifest room and the recovery material of users
a, b and c (account data, device and cross-signing keys, signatures, key
backup) from `synapse_dark`. Each user gets a login with their rig password,
read from the Secret through `SPINDLE_REHEARSAL_PASSWORD_DIR`. The Synapse
signing key is installed under its own key ID. The binary and the store
live on the toolbox PVC (`/work/bin/spindle`, `/work/dark-spindle/store`).

Isolation of `k8s/dark-spindle.yaml` follows the dark Synapse:

1. `[federation] enabled = false` (#560). Every outbound federation request
   is refused inside the process, before a name is resolved. The outbox is
   not drained. `/_matrix/federation/*` and `/_matrix/key/*` answer `404`.
2. `[push] enabled = false` and `[previews] enabled = false`. There are no
   appservices, delegated auth, S3, TURN or LiveKit.
3. Neither the import Job nor the server pod has a resolver
   (`nameserver 127.0.0.1`). The Job reaches the database through
   `hostAliases`.
4. A ClusterIP Service on the client port is the only way in. There is no
   Ingress, NodePort or LoadBalancer.
5. A `netwatch` sidecar logs any socket that is not loopback or an inbound
   client connection. `kubectl port-forward` connections show up as loopback.

## `element`: a real Element Web recovery

`./rig.sh element <dark-spindle|dark-synapse> <user>` runs on the
workstation. It serves a pinned Element Web (v1.12.28) against a
port-forward and drives headless Chromium through
`element/recover.cjs`. The Chromium host resolver maps the namespace's
service names to 127.0.0.1 and blocks every other origin. The script takes
these steps:

1. Password login.
2. **Use recovery key**, then **Device verified**, then **Done**.
3. In each encrypted room, page back to the room's start. Every message,
   reply and redaction target the user may read must render without a
   decryption failure, and the room must look like an encrypted room of
   its own version: no "encryption not enabled" notice, no unencrypted
   composer, no unstable-version banner.

The report is written to `$OUT_DIR/<svc>-<user>-<time>/element-<user>.json`,
with screenshots, the console log and the Matrix HTTP status lines.
`NODE_PATH` must resolve `playwright`, and its Chromium must be installed.

## Limits

* The dark Synapse database is a point-in-time copy. Real users' rows are in
  it but are never read or written by the rig. Only the three
  `spindle-mig-*` users and their four rooms are created.
* `verify` proves decryptability with matrix-rust-sdk, the library under
  Element X. `element` exercises Element Web's own recovery and restore
  path, which `verify` cannot. Two Spindle faults showed up only there
  (see `docs/evidence/migration-e2ee-rig-spindle.md`).
* The import Job has no netwatch sidecar. It has no resolver, and its only
  configured peer is the database.
