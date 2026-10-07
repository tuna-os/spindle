# ESS/Kubernetes operation driver

`scripts/ess-kubernetes-driver.py` is the deployment driver for the
Synapse-to-Spindle one-writer boundary. You can use it directly before the
standalone operator API is complete. Its JSON plan and checkpoint are the
same durable evidence that the migration workspace consumes.

The driver does not infer an installation from names. Pass an explicit
`ess-v1` topology, a kubeconfig, and a context. Discovery lists both workload
kinds under the topology's deployment selector. It refuses to continue if
the cluster omits a selected workload or if a declared workload is absent.
The driver also needs:

- exactly one workload for each of Synapse, the federation sender,
  `sliding-sync`, MAS, PostgreSQL, Element Call, and LiveKit
- one or more media workloads
- at least one ingress path that is not ambiguous

The driver rejects an unknown ESS layout until another profile describes it.

Start from [`deploy/operator/ess-topology.example.json`](../deploy/operator/ess-topology.example.json).
The deployment selector should identify only one ESS installation. The
PostgreSQL pod selector must identify exactly one live pod. In that pod,
`psql` must be able to inspect `pg_stat_activity`. Credentials must come from
that pod's own environment or local socket, never from this file.

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

Quiesce fences MAS, `sliding-sync`, the federation sender, and Synapse in that
order. Every scale uses a JSON-patch resource-version precondition, waits for
desired/current/ready replicas to reach zero, then waits for relevant database
sessions to drain. After a restart, the driver detects a mutation that it
already applied and checkpoints it. It does not submit the mutation twice.
Every actual mutation records the resource version before and after the
change.

Switch needs fresh, redacted validation evidence:

```json
{
  "passed": true,
  "assessment_id": "assessment-42",
  "target": "spindle/matrix-example-org",
  "expires_at": "2027-01-02T03:04:05Z"
}
```

Only those four fields enter the checkpoint. Immediately before it changes
ingress, the driver proves again that the fence holds on the source and that
zero database sessions remain. Each configured host/path must still resolve
to one service that the driver knows as source or target. The driver reads
until it observes the changed backend. A conflict or convergence timeout
blocks the operation; a retry resumes from the checkpoint.

`rollback` restores every ingress path and writer replica count to its precise
discovery value. It applies while the seal holds on the source and before the
traffic switch starts. The start of `switch` closes that ordinary rollback
boundary *before* the first ingress mutation. A request may reach Spindle as
soon as Kubernetes accepts the patch, before an observer can prove whether it
wrote. A failed or partial switch then needs the post-write recovery
procedure. Do not guess that Synapse can safely return to service.

## Permissions and checkpoint custody

[`deploy/operator/ess-driver-rbac.yaml`](../deploy/operator/ess-driver-rbac.yaml)
contains the minimum verbs for an installation where PostgreSQL shares the ESS
namespace. If PostgreSQL is elsewhere, put only the pod `get`, `list`, and
`pods/exec` rules in a Role in that namespace and bind the same service
account. Do not grant Secret reads.

The driver replaces checkpoint files atomically, with mode `0600`. They
contain resource metadata, selectors, health, route service names, validation
identity, and mutation versions. They never contain environment variables,
Secret values, SQL rows, access tokens, or private signature material.
