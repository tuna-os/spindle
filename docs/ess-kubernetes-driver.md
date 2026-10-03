# ESS/Kubernetes operation driver

`scripts/ess-kubernetes-driver.py` is the deployment driver for the
Synapse-to-Spindle one-writer boundary. It is usable directly while the
standalone operator API is being assembled; its JSON plan and checkpoint are
the same durable evidence the migration workspace consumes.

The driver does not infer an installation from names. Pass an explicit
`ess-v1` topology, a kubeconfig, and a context. Discovery lists both workload
kinds under the topology's deployment selector and refuses to continue if a
selected workload is omitted or a declared workload is absent. It also
requires exactly one Synapse, federation sender, sliding-sync, MAS,
PostgreSQL, Element Call, and LiveKit workload, one or more media workloads,
and at least one unambiguous ingress path. This deliberately rejects unknown
ESS layouts until another profile describes them.

Start from [`deploy/operator/ess-topology.example.json`](../deploy/operator/ess-topology.example.json).
The deployment selector should identify only one ESS installation. The
PostgreSQL pod selector must identify exactly one running pod from which
`psql` can inspect `pg_stat_activity`; authentication should come from that
pod's existing environment or local socket, never from this file.

## Plan and discovery

These commands are read-only and produce no checkpoint:

```sh
python3 scripts/ess-kubernetes-driver.py discover \
  --topology topology.json --kubeconfig "$KUBECONFIG" --context production
python3 scripts/ess-kubernetes-driver.py plan \
  --topology topology.json --kubeconfig "$KUBECONFIG" --context production
```

Discovery records UIDs, resource versions, exact replica counts, pod
selectors, workload health, ingress backends, and the count (not the contents)
of relevant PostgreSQL sessions. It never asks Kubernetes for a Secret. Plan
uses that same discovery path, so dry run and execution select the same
resources.

## Seal, validate, and switch

Use an absolute checkpoint path on storage that survives an operator restart:

```sh
COMMON="--topology topology.json --kubeconfig $KUBECONFIG --context production \
  --state /var/lib/spindle-operator/migration-42.json"
python3 scripts/ess-kubernetes-driver.py quiesce $COMMON
python3 scripts/ess-kubernetes-driver.py verify-quiesced $COMMON
python3 scripts/ess-kubernetes-driver.py switch $COMMON \
  --validation /var/lib/spindle-operator/assessment-42.json
```

Quiesce fences MAS, sliding sync, the federation sender, and Synapse in that
order. Every scale uses a JSON-patch resource-version precondition, waits for
desired/current/ready replicas to reach zero, then waits for relevant database
sessions to drain. A process restart observes an already-applied mutation and
checkpoints it instead of submitting it twice. Every actual mutation records
its before and resulting resource versions.

Switch requires fresh, redacted validation evidence:

```json
{
  "passed": true,
  "assessment_id": "assessment-42",
  "target": "spindle/matrix-example-org",
  "expires_at": "2027-01-02T03:04:05Z"
}
```

Only those four fields enter the checkpoint. The driver re-proves source
fencing and zero database sessions immediately before changing ingress. Each
configured host/path must still resolve to exactly one recognized source or
target service, and the driver reads until the changed backend is observed.
A conflict or convergence timeout blocks the operation; retrying resumes from
the checkpoint.

`rollback` restores every ingress path and writer replica count to its precise
discovery value while the source is sealed but traffic switching has not begun.
Starting `switch` closes that ordinary rollback boundary *before* the first
ingress mutation: a request may reach Spindle as soon as Kubernetes accepts the
patch, before an observer can prove whether it wrote. A failed or partial switch
therefore requires the separate post-write recovery procedure rather than an
unsafe guess that Synapse can be restored.

## Permissions and checkpoint custody

[`deploy/operator/ess-driver-rbac.yaml`](../deploy/operator/ess-driver-rbac.yaml)
contains the minimum verbs for an installation where PostgreSQL shares the ESS
namespace. If PostgreSQL is elsewhere, put only the pod `get`, `list`, and
`pods/exec` rules in a Role in that namespace and bind the same service
account. Do not grant Secret reads.

Checkpoint files are atomically replaced with mode `0600`. They contain
resource metadata, selectors, health, route service names, validation identity,
and mutation versions—never environment variables, Secret values, SQL rows,
access tokens, or private signing material.
