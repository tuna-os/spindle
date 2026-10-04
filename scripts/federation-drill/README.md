# Federation drill rig

This rig runs the drill in `docs/synapse-migration-drill.md` in the
`spindle-rehearsal` namespace of the migration cluster. The results are in
`docs/evidence/federation-drill.md`.

## Parts

| Part | Object | Address |
|---|---|---|
| Private resolver | `drill-resolver` (CoreDNS) | 10.111.63.10:53 |
| Synapse A, the witness, `witness.lab` | `drill-a`: TLS front + Synapse v1.156.0 + netwatch | 10.111.63.11 (443 federation, 8008 client) |
| Synapse B, then Spindle B, `reilly.asia` | `drill-b`: the same front + Synapse or Spindle + netwatch | 10.111.63.12 (443, 8008) |
| Test clients | `drill-client`: `drill.py` and `drill-e2ee` | lab resolver only |
| Databases | `drill_a`, `drill_b`, `drill_b_seal` on `rehearsal-pg` | |

- The resolver knows four names: `reilly.asia`, `matrix.reilly.asia`,
  `witness.lab` and `matrix.witness.lab`. It refuses every other query
  and logs all queries.
- Both servers use delegation, as production does. `/.well-known/matrix/server`
  on the bare name points to `matrix.<name>:443`. A TLS front (nginx) in
  each pod plays the part of the ESS ingress. The front stays the same when
  Spindle B replaces Synapse B.
- The certificates come from a private CA that exists only for the drill.
  `drill.sh tls` deletes the CA key after the CA signs the two leaf
  certificates.
  - Synapse trusts the CA with `federation_custom_ca_list`.
  - Spindle trusts it with `SSL_CERT_FILE`, so the private CA is its only
    root.
- B uses the production `server_name` and the production server key
  (`ed25519:a_qMqD`). `drill.sh secrets` copies the key from the E2EE rig's
  secret, and does not write it to local disk.

## Isolation

The CNI does not enforce NetworkPolicy. The namespace's PodSecurity level
(baseline) forbids `NET_ADMIN`, so a pod cannot have its own firewall.
These layers keep B away from everything except A:

1. **No cluster DNS.** Each server pod uses `dnsPolicy: None` with the
   lab resolver only. There are no search domains. Each pod finds the
   database through `hostAliases`.
2. **The lab resolver.** It answers only the four lab names. It has no
   upstream, so it cannot resolve anything else.
3. **The servers' own allow-lists.**
   - Synapse: `federation_domain_whitelist` lists the two lab names, and
     `ip_range_blacklist` is `0.0.0.0/0` and `::/0` except the peer's
     front.
   - Spindle: `allow_internal` lists only the witness's front. Spindle
     refuses every other private address by its resolved address.
4. **netwatch.** A sidecar in each server pod logs each socket by its
   remote end: loopback, inbound, database, resolver, peer, or `OUTBOUND`.
   The isolation claim is that `OUTBOUND` stays at 0.
5. **Client isolation.** The client pod also uses only the lab resolver.
   `drill-e2ee` ignores the `well_known` in the login response.
   Synapse names `https://matrix.reilly.asia/` there, and outside the lab
   that is production.

## Running it

```
D=scripts/federation-drill
$D/drill.sh tls /some/private/dir      # CA and certs (keep out of git)
$D/drill.sh secrets /some/private/dir
$D/drill.sh db && $D/drill.sh resolver && $D/drill.sh up-a && $D/drill.sh up-b-synapse
$D/drill.sh client
# 4.1 warm-up (drill.py and drill-e2ee run in the client pod)
drill.py users; drill.py rooms; drill.py history 3000
e2ee.sh drill-b1 prepare --hs http://drill-b:8008 --user drill-b1 --recovery
e2ee.sh witness prepare --hs http://drill-a:8008 --user witness --recovery
e2ee.sh drill-b1 create --name … --version 10 --invite @witness:witness.lab
e2ee.sh witness join --room ROOM; e2ee.sh … send …; drill.py addroom encrypted-v10 ROOM 10
$D/drill.sh partition on; drill.py fork write; $D/drill.sh partition off; drill.py fork check
drill.py pingpong warmup; drill.py baseline warmup; $D/drill.sh extremities
fedcheck.py keys                       # in drill-a's synapse container
# 4.3 seal, 4.4 import and cut-over
$D/drill.sh seal
$D/drill.sh import ROOMS USERS
SPINDLE_BIN=/work/drill/bin/spindle $D/drill.sh up-b-spindle
# 4.5
fedcheck.py keys; fedcheck.py events 50
drill.py pingpong cutover; drill.py statechange cutover; drill.py baseline cutover
e2ee.sh drill-b1 check --room ROOM --manifest /state/e2ee-manifest.jsonl --relogin
# 4.7
$D/drill.sh rollback
$D/drill.sh netwatch
$D/drill.sh teardown
```

`import` runs the full `import-synapse` command against the sealed drill
database, including devices, crypto, backups, account data, and media. It
imports every retained room and local account in that database. `ROOMS`
and `USERS` are the exact expected fixture IDs, rather than import filters.
Known synthetic passwords are passed through the rehearsal password secret;
production authentication remains owned by MAS.

The import Job must finish successfully. `verify-import.py` then checks its
checkpoint and read-back report from a disposable pod with the data PVC
mounted read-only. It requires every expected room, zero exclusions, rejection
policy version 3, verified event signatures, complete pagination positions,
matching state and event samples, and nonempty crypto and backup evidence.
`up-b-spindle` repeats that check before replacing the lab server. These
checks establish import continuity; the subsequent clients must still prove
sign-in and decryption. A seal also refuses to proceed if federation has not
drained.

Use a server image and binary built with `synapse-import`. When providing a
locally built binary through `SPINDLE_BIN`, its runtime image must support
that binary's libc version. The verifier uses its own Python image and does
not require Python in the server image.

`fedcheck.py` runs inside the `synapse` container of `drill-a`, with the
script on standard input. It uses the resolver, trust store, server key
and database of A. It checks events with the event code of Synapse.
