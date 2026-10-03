# Synapse to Spindle cutover on Kubernetes

A homeserver migration has one non-negotiable invariant: Synapse and Spindle
must never both accept writes for the same Matrix server name. A PostgreSQL
snapshot makes an online rehearsal consistent, but it does not make a live
cutover safe. The production import begins only after the source is quiescent.

The first supported deployment profile is Element Server Suite on Kubernetes.
Its Synapse has many workers. Thus a stop of only the `main` pod is not a
quiesce. The profile has these parts:

- the HAProxy front door;
- Matrix Authentication Service (MAS), which owns the login and refresh routes;
- the StatefulSets for Synapse main, the federation sender and `sliding-sync`;
  and
- the PostgreSQL `synapse` database. The final proof that no source process
  stays connected comes from this database.

## Safe outage boundary

[`scripts/synapse-k8s-cutover.sh`](../scripts/synapse-k8s-cutover.sh) does
the reversible part of the cutover:

1. record the replica count and Kubernetes UID of each selected workload;
2. scale HAProxy and MAS to zero and wait. This closes the two ingress paths;
3. scale each Synapse worker to zero and wait;
4. make sure that the `synapse` PostgreSQL database has zero sessions;
5. leave a mode-0600 state file for an ordered rollback; and
6. on rollback, start the Synapse workers first. Start HAProxy and MAS only
   after the workers are ready.

`quiesce` is a dry run unless `--execute` is present. You must give the
kubeconfig and the exact context. This prevents an outage from a typo in the
default context.

```console
scripts/synapse-k8s-cutover.sh plan \
  --kubeconfig /secure/path/cluster.yaml \
  --context production

scripts/synapse-k8s-cutover.sh quiesce \
  --kubeconfig /secure/path/cluster.yaml \
  --context production \
  --state-dir /secure/path/cutover-state \
  --execute

# If a later gate fails:
scripts/synapse-k8s-cutover.sh resume \
  --kubeconfig /secure/path/cluster.yaml \
  --context production \
  --state-dir /secure/path/cutover-state \
  --execute
```

Keep the state directory until you accept the migration. The script does not
change the source database or the media PVC. Thus a rollback only starts the
source again. It is not a reverse data migration. This is true until Spindle
gets its first write.

## Gates before an automated traffic switch exists

The script stops at a verified quiesce on purpose. We will add the Spindle
start and the ingress patch only when each of these items has an executable
check:

- each retained room imports, or has an exclusion that the operator approves;
- each room version in the source, also older federated rooms, passes the
  Spindle federation join and send tests;
- the recovery data of each user restores, and a new Element session can
  decrypt an old encrypted event;
- the Synapse server key and the old verify-key response stay the same after
  the cutover. Then remote homeservers can verify old and new events;
- MAS uses the Spindle provision endpoint and token introspection, and a
  current MAS session can authenticate after the switch;
- media, profiles, account data, devices, receipts, pushers, appservices and
  other selected state domains have count and sample validation;
- the Spindle PVC is empty before import, durable after import, and mounted by
  a workload with a readiness probe; and
- the operator patches ingress only after an offline job validates the client
  and federation paths. Synapse stays stopped until then.

When those checks exist, the final sequence is: quiesce → import → validate
→ start Spindle → switch MAS → switch ingress → smoke-test. If a step fails
before the ingress switch, the script starts Synapse again. If a
step fails after the switch, the operator first closes ingress, then does a
forward fix or a rollback. The two homeservers never run at the same time.
