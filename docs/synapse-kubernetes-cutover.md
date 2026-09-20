# Synapse to Spindle cutover on Kubernetes

A homeserver migration has one non-negotiable invariant: Synapse and Spindle
must never both accept writes for the same Matrix server name. A PostgreSQL
snapshot makes an online rehearsal consistent, but it does not make a live
cutover safe. The production import begins only after the source is quiescent.

The first supported deployment profile is Element Server Suite on Kubernetes.
Its Synapse is a worker deployment, so stopping only the `main` pod is not a
quiesce. The profile includes:

- the HAProxy front door;
- Matrix Authentication Service, which owns login and refresh routes;
- Synapse main, federation-sender and sliding-sync StatefulSets; and
- the PostgreSQL `synapse` database, used as the final proof that no source
  process remains connected.

## Safe outage boundary

[`scripts/synapse-k8s-cutover.sh`](../scripts/synapse-k8s-cutover.sh) implements
the reversible part of the cutover:

1. record every selected workload's replica count and Kubernetes UID;
2. scale HAProxy and MAS to zero and wait, closing both ingress paths;
3. scale every Synapse worker to zero and wait;
4. require zero sessions against the `synapse` PostgreSQL database;
5. leave a mode-0600 state file for an ordered rollback; and
6. on rollback, start Synapse workers first and expose HAProxy/MAS only after
   the workers are ready.

`quiesce` is a dry run unless `--execute` is present. Both the kubeconfig and
the exact context are mandatory, preventing an ambient-context typo from
turning into an outage.

```console
scripts/synapse-k8s-cutover.sh plan \
  --kubeconfig /secure/path/cluster.yaml \
  --context production

scripts/synapse-k8s-cutover.sh quiesce \
  --kubeconfig /secure/path/cluster.yaml \
  --context production \
  --state-dir /secure/path/cutover-state \
  --execute

# If any later gate fails:
scripts/synapse-k8s-cutover.sh resume \
  --kubeconfig /secure/path/cluster.yaml \
  --context production \
  --state-dir /secure/path/cutover-state \
  --execute
```

Do not delete the state directory until the migration is accepted. The source
database and media PVC remain untouched, so rollback is start-only rather than
a reverse data migration—as long as Spindle has not been exposed to writes.

## Gates before an automated traffic switch exists

The script intentionally stops at a verified quiesce. Starting Spindle and
patching ingress will be added only when all of these have executable checks:

- every retained room imports or has an explicit operator-approved exclusion;
- all room versions present in the source, including older federated rooms,
  pass Spindle's federation join/send tests;
- all users' recovery data restores and a fresh Element session decrypts a
  pre-migration encrypted event;
- Synapse's server signing key and historical verify-key response survive the
  cutover, so remote homeservers continue to verify old and new events;
- MAS is configured for Spindle's provisioning endpoint and token
  introspection, and an existing MAS session authenticates after the switch;
- media, profiles, account data, devices, receipts, pushers, appservices and
  other selected state domains have count and sample validation;
- the Spindle PVC is empty before import, durable after import, and mounted by
  a readiness-probed workload; and
- ingress is patched only after an offline client/federation validation job
  succeeds, with Synapse still stopped.

Once those checks exist, the final transaction is: quiesce → import → validate
→ start Spindle → switch MAS → switch ingress → smoke-test. Any failure before
the ingress switch restores Synapse automatically. A failure after the switch
first closes ingress, then chooses either a forward fix or a rollback; it never
runs both homeservers concurrently.
