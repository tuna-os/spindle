# E2EE migration rig: the dark Spindle (2026-10-03)

This page continues
[`migration-e2ee-rig-baseline.md`](migration-e2ee-rig-baseline.md). The
same manifest, recovery keys and pass criteria are used here, but the target
is a Spindle that holds an import of `synapse_dark`. The gate is the one in
[#240](https://github.com/tuna-os/spindle/issues/240): a fresh device that
has only its recovery key and the server-side key backup must decrypt every
historical encrypted event.

## Result

| User | `verify` (matrix-rust-sdk) on dark Synapse | `verify` on dark Spindle, before fixes | `verify` on dark Spindle, after | Element Web on dark Synapse | Element Web on dark Spindle, before | Element Web on dark Spindle, after |
|---|---|---|---|---|---|---|
| a | PASS 89/89 | FAIL: 89/89 readable, 4 redacted targets not redacted | **PASS 89/89** | PASS 81/81 | FAIL: no room state, then UTD | **PASS 81/81** |
| b | PASS 89/89 | FAIL: same 4 | **PASS 89/89** | PASS 81/81 | not run | **PASS 81/81** |
| c | PASS 59/59 | FAIL: 2 not redacted | **PASS 59/59** | PASS 56/56 | not run | **PASS 56/56** |

Element counts are lower than `verify` counts because Element folds edits
into their originals, so edits are not checked separately, and because
plaintext and state events are not counted. After the fixes, 9 Element Web
logins on the dark Spindle had their dehydration request logged: a ×4, b ×2
and c ×3. 4 of those logins created a dehydrated device whose ID contains a
`/`, which is the case the dehydration fix below covers. Each of the 9
dehydration requests returned 200, and each login decrypted every required
event. In one c run the rig's checker reported 55/56, because it counted a
reply's quote of an event c was never allowed to read. The checker now
ignores quoted events.

## What was wrong, and where it was fixed

1. **Imported redactions did not redact.** Synapse keeps a redacted event's
   original JSON in `event_json` and strips it on read. The rehearsal
   importer copied the JSON verbatim, so deleted content came back on the
   new server. The importer now applies every imported redaction to its
   target. (#557, commit "Apply imported redactions to their targets", with
   `tests/synapse_rehearsal_redaction.rs`.)
2. **Element Web received no room state.** matrix-js-sdk sends
   `org.matrix.msc4222.use_state_after=true` on every `/sync` and reads only
   `org.matrix.msc4222.state_after`, or else `state`. Spindle answered with
   the stable `state_after` field. Element therefore showed every room as an
   unnamed room version 1 with "encryption not supported", and the composer
   of an encrypted room offered to send unencrypted. This affected every
   Element Web user, not only migrated ones. Fixed in
   [#559](https://github.com/tuna-os/spindle/pull/559).
3. **Element Web lost its backup key on about half of fresh logins.**
   matrix-rust-sdk names a dehydrated device after its Curve25519 key in
   unpadded base64, and about 49% of those names contain a `/`. Spindle
   refused them with `400 M_BAD_JSON`. Element sets up dehydration after
   recovery, before it loads the backup key from secret storage, so the
   failure skipped the backup restore. The device showed **"Device
   verified"** and then "Unable to decrypt" on every historical message.
   This matches the Element-only failure of 2026-09-20 exactly: identical
   ciphertext and backup, and only Element fails. The dark Synapse does not
   offer MSC3814, which is why Element always passed there. Fixed in
   [#561](https://github.com/tuna-os/spindle/pull/561).
4. **No way to stop the dark copy federating.** It holds the production
   server name and signing key. `[federation] enabled = false` was added in
   [#560](https://github.com/tuna-os/spindle/pull/560).

Fault 2 hid fault 3. With no room state, Element did not treat the rooms as
encrypted rooms, and it decrypted every event: 81/81 with the v1 banner.
Once the state arrived, the dehydration fault surfaced.

## What was checked and found equal to Synapse

The matrix-rust-sdk client had all of these on both servers:

- recovery through secret storage (`m.secret_storage.*` and
  `m.cross_signing.*` account data)
- the new device cross-signed by its owner
- the backup version (`m.megolm_backup.v1.curve25519-aes-sha2`, version `1`,
  15/15/11 sessions)
- per-room `/room_keys/keys` downloads
- room versions 12, 10, 11 and 10
- c's leave and rejoin: 15 events sent while c was away are UTD and are
  `not-required`

## Isolation evidence

`./rig.sh spindle-isolation`:

```
[federation] enabled = false   [push] enabled = false   [previews] enabled = false
resolv.conf                    nameserver 127.0.0.1
service/dark-spindle           ClusterIP 8008 only; no Ingress
/_matrix/key/v2/server         404
/_matrix/federation/v1/version 404
netwatch                       "outbound": 0 (outbound endpoints seen: 0)
```

The server pod was replaced at each of the four re-imports. The netwatch logs of three
of those pods were checked, including the pod that served the final
`verify` and Element runs above. All three show 0 outbound endpoints. The only non-loopback peer was the
toolbox's inbound client connection. `kubectl port-forward` traffic shows up
as loopback. The import Job has no resolver, and its one configured peer is
`rehearsal-pg`.

## Reproduce

```bash
cd scripts/migration-e2ee-rig
./rig.sh spindle-build <ref with #557 + #559/#560/#561>
./rig.sh spindle-import
./rig.sh verify http://dark-spindle.spindle-rehearsal.svc.cluster.local:8008 a   # b, c
NODE_PATH=... ./rig.sh element dark-spindle a                                    # b, c
./rig.sh spindle-isolation
```
