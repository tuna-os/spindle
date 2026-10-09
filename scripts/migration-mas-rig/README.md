# MAS and client-surface rig (#563)

This rig puts a dark MAS and a dark Spindle into `spindle-rehearsal`. It
uses the #558 rig: the same users, rooms, manifest and toolbox. The
results are in `docs/evidence/mas-cutover-rehearsal.md` and
`docs/evidence/client-surface-rehearsal.md`.

## Parts

- `k8s/services.yaml`: the two ClusterIP Services. Apply them first, then
  put their IPs and the `rehearsal-pg` IP into the other manifests:

  ```sh
  sed -i "s/__PG_IP__/$PG/; s/__SPINDLE_IP__/$SP/; s/__MAS_IP__/$MAS/" k8s/dark-*.yaml
  ```

- `k8s/dark-mas.yaml`: MAS 1.23.0 on `mas_dark`. To make `mas_dark`,
  restore the production `mas.dump` into `rehearsal-pg`. The MAS gets new
  secrets from `secret/dark-mas-secrets`: `rsa.pem`, `ec.pem`,
  `encryption`, `matrix_secret` and `admin_client_secret`.
- `k8s/dark-spindle-mas.yaml`: the import Job and the dark Spindle. Its
  `spindle.toml` is in `secret/dark-spindle-mas-config`. It has
  `[federation] enabled = false` and an `[auth.delegated]` section that
  has only `homeserver_secret`.
- `netwatch.py`: the #558 netwatch, with a list of lab peers.
- `mas_gate.py`: the MAS checks (sessions, compat, provisioning,
  revocation). It runs on the workstation, through port-forwards of the
  two Services to `127.0.0.1:18080` and `127.0.0.1:18008`.
- `element/run.sh <a|b|c>`: Element Web signs in through the MAS pages,
  then uses the recovery key and checks the manifest.
- `ssprobe/`: the Element X sync stack (matrix-sdk-ui `SyncService` on
  MSC4186) with a MAS session. `python3 ssprobe/run.py <a|b|c>`.
- `rtc_check.py`: what Element Call and lk-jwt-service need from the
  homeserver.

The rig makes sessions only for rig users. It never makes one for a real
user.
