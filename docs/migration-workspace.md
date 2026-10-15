# Synapse migration workspace

`scripts/migration-workspace.py` is the durable go/no-go control for a
Synapse-to-Spindle cutover. Probes for infrastructure produce evidence. The
workspace validates its shape and freshness. It derives compatibility needs
from the retained-room inventory. It lets authority change only when all gates
for that change pass.

You can use the CLI until the project assembles `spindle-operator`. Its `view` output
is the compact aggregate that the operator API and browser can expose. The
five top-level objects are the five workspace panes: **Runbook**, **Gates**,
**Evidence**, **Resources**, and **Recovery**. Neither a browser nor an
operator has to infer authority from Kubernetes objects.

This tool records decisions; it does not run shell commands or mutate a
homeserver. A deployment driver does the checkpointed changes and attests the
observed outcome. Thus, a driver cannot declare that an incomplete operation
is successful.

## Start with preflight

Keep the workspace on durable operator storage. The tool replaces the file
atomically with mode `0600`. You can retry every command after a process restart.

```sh
WORKSPACE=/var/lib/spindle-operator/migrations/migration-42.json
python3 scripts/migration-workspace.py --state "$WORKSPACE" init \
  --operation-id migration-42 --actor operator@example.org --mode live
python3 scripts/migration-workspace.py --state "$WORKSPACE" advance \
  --to PREFLIGHT --actor operator@example.org
python3 scripts/migration-workspace.py --state "$WORKSPACE" inventory \
  --input inventory.json --actor assessor@example.org
```

The inventory is a redacted list, not a room list:

```json
{
  "rooms": [
    {"version": "10", "disposition": "retain"},
    {"version": "9", "disposition": "exclude", "approval": "approval-27"}
  ]
}
```

The inventory can contain only version, disposition, and an approval reference
for exclusions. Room IDs and names do not enter the workspace. The distribution
of retained-room versions is the compatibility authority. The `room_versions`
attestation must repeat that exact distribution. It must prove client and
federation support for every retained version. A missing version blocks the
source seal and the cutover.

Use `--mode rehearsal` to exercise the complete runbook and evidence path.
Every phase advances, but authority remains `SYNAPSE_LIVE`, the target is never
marked writable, and ordinary rollback is unnecessary.

## Evidence contract

Add evidence with:

```sh
python3 scripts/migration-workspace.py --state "$WORKSPACE" attest \
  --gate room_versions --input evidence/room-versions.json \
  --actor compatibility-probe@example.org
```

Every evidence document has exactly this contract:

```json
{
  "status": "passed",
  "probe_version": "room-compat/1.4.0",
  "timestamp": "2027-01-02T03:04:05Z",
  "target": "dark-target/matrix.example.org",
  "observations": {
    "retained_distribution": {"10": 188},
    "client_supported": ["10"],
    "federation_supported": ["10"]
  },
  "artifacts": ["sha256:0123456789abcdef"],
  "expires_at": "2027-01-02T04:04:05Z",
  "attested_by": "compatibility-probe@example.org"
}
```

Before each phase that changes a system, the workspace checks all required
evidence again. Evidence that is missing, failed, or expired stops progress. Artifact
entries are references, not inline logs. The contract rejects credentials,
access tokens, private keys, server keys, recovery keys, passwords, and
decrypted content. The Element evidence contains boolean results for fresh
login, verification, key recovery, and actual historical decryption. It never
contains the key or plaintext.

## Gates and transitions

The ordered runbook is:

```text
REHEARSE → PREFLIGHT → SEAL_SOURCE → IMPORT → VALIDATE → SWITCH → OBSERVE
```

A live run maps it to these authority states:

```text
SYNAPSE_LIVE → SEALING_SOURCE → SOURCE_SEALED → IMPORTING →
VALIDATING_DARK_TARGET → SPINDLE_LIVE
```

First, the driver must stop every source workload and drain the database
sessions. An operator then records both attestations and runs
`source-sealed --actor ...`. That command enters `SOURCE_SEALED`; import refuses
to start without it. An operator explicitly enters `RECOVERY_REQUIRED` after
the write boundary.

| Transition | Evidence re-checked immediately before it |
|---|---|
| `SEAL_SOURCE` | retained rooms/exclusions, retained room-version client and federation support, signing identity, empty validated target |
| `IMPORT` | all sealing evidence plus source workloads zero and PostgreSQL sessions drained |
| `VALIDATE` | complete restart-safe import progress and durable import-checkpoint evidence |
| `SWITCH` | every hard gate below, completed import accounting, independent approval, and typed operation-ID confirmation |

The full switch gate is: `retained_rooms`, `room_versions`,
`signing_identity`, `element_e2ee`, `users`, `devices`, `keys`, `state`,
`account_data`, `receipts`, `push_data`, `media`, `source_workloads_zero`,
`postgres_sessions_drained`, `target_empty`, `import_checkpoint`,
`dark_target_client`, `federation_bidirectional`, `mas`, and
`ingress_single_writer`.

A status of `passed` does not replace checks of meaning. Workload and session gates
must report zero. Target validation must report an empty target. Ingress must
report exactly Spindle as writer. Federation must work in both directions with
an independent server for every retained room version.

If the inventory retains v10, the Element attestation must come from a v10
room. It must prove recovery of encrypted history in a fresh client.

## Import, approval, and the write boundary

Progress is monotonic and carries a durable checkpoint:

```sh
python3 scripts/migration-workspace.py --state "$WORKSPACE" import-progress \
  --input import-progress.json --actor importer@example.org
```

```json
{
  "rooms": 188,
  "events": 940012,
  "bytes": 82000128,
  "exclusions": 27,
  "checkpoint": "s3://operator-evidence/migration-42/checkpoint-19",
  "complete": true
}
```

Completion needs `rooms + exclusions` to equal the assessed inventory. After a
restart, counters cannot move backwards. The workspace does not reopen a
completed import.

The requester cannot approve their own switch:

```sh
python3 scripts/migration-workspace.py --state "$WORKSPACE" approve \
  --scope switch --actor independent-approver@example.org
python3 scripts/migration-workspace.py --state "$WORKSPACE" advance \
  --to SWITCH --actor operator@example.org --confirm migration-42
```

When an operator advances to `SWITCH`, Spindle can accept writes. Before that
boundary, `rollback --confirm migration-42` returns the authority ledger to
`SYNAPSE_LIVE`. The deployment driver can then execute its recorded
compensation. After the boundary, an operator cannot use ordinary rollback.
Synapse can be missing accepted writes. Use `recovery-required --reason ...`
to enter a separate, visible recovery state and follow a reviewed
reconciliation plan.

## Operator view and audit report

```sh
python3 scripts/migration-workspace.py --state "$WORKSPACE" view
python3 scripts/migration-workspace.py --state "$WORKSPACE" report \
  --output migration-42-report.json
```

The view leads with authority, active step, failed gates, import progress,
recommended action, and rollback boundary. Evidence observations remain in
the protected workspace; the view/report exposes evidence metadata and
artifact references. The final report includes the append-only operation
history and is itself checked for forbidden material before export.

The Kubernetes/ESS driver must use the same operation ID and put its topology,
scale-down, session-drain, and ingress artifacts behind these evidence
references. The migration workspace remains outside both homeserver workloads,
so it stays available while neither homeserver runs.
