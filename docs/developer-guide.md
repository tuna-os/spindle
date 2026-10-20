# Developer architecture guide

This page maps the Rust workspace to the concerns a contributor is likely to
change. It is a starting point for finding code, not a replacement for the
[specification](../SPEC.md), the [operator guide](operations.md), or the
[maintenance guide](maintenance.md).

## Workspace at a glance

The workspace has four crates. The server path and the operator path are
separate processes:

```text
spindle-server  (the `spindle` homeserver binary)
├── spindle-core
└── spindle-store
    └── spindle-core

spindle-operator (standalone deployment control plane)
```

| Crate | Owns | Starts here |
| --- | --- | --- |
| `spindle-core` | Matrix event values, the monotonic linear log, state snapshots and the bounded federation-DAG overlay | `crates/spindle-core/src/lib.rs`, then `log.rs`, `state.rs`, `pdu.rs` and `state_table.rs` |
| `spindle-store` | Durable ordered-key persistence, record codecs, backups and migrations; it uses Fjall and depends on `spindle-core` | `crates/spindle-store/src/lib.rs`, then `codec.rs`, `backup.rs` and `migrate.rs` |
| `spindle-server` | The client-server and server-server HTTP surface, authentication, rooms, federation, media, administration and the `spindle` executable | `crates/spindle-server/src/main.rs`, `lib.rs` and `routes.rs` |
| `spindle-operator` | A separate control plane for durable operations, deployment drivers, audit evidence, operator authentication and its browser console | `crates/spindle-operator/src/lib.rs`, then `engine.rs`, `driver.rs`, `api.rs` and `auth.rs` |

`spindle-operator` intentionally has no path dependency on the homeserver
crates. It stays available while a homeserver is stopped for migration,
cutover or recovery. Do not add operator process logic to `spindle-server` just
because both projects expose HTTP APIs.

## Request and storage path

A normal client or federation request follows this shape:

1. `crates/spindle-server/src/main.rs` loads configuration, opens the
   `spindle-store` backend and builds the application state.
2. `crates/spindle-server/src/routes.rs` mounts the Axum route table. The
   `MOUNTED` table is also used by the surface checks; it must not drift from
   the router.
3. A handler in `crates/spindle-server/src/` authenticates the caller, applies
   the route's access checks and delegates room/event work to the server
   services.
4. Room services use `spindle-core` types such as `RoomLog`, `StateSnapshot`,
   `Pdu` and `LinearIndex`. Core keeps Matrix ancestry (`prev_events`) and
   Spindle's linear storage order as separate concepts.
5. `spindle-store` encodes records and reads or writes the durable keyspaces.
   The server owns the request lifecycle; the store owns persistence details.

State resolution is not a server-only algorithm. The core log asks for a
`StateResolver` when parent states differ. `spindle-server` supplies the
room-version-specific implementation in `state_res.rs` and `state_res_v1.rs`.
That boundary keeps the storage model reusable while keeping Matrix rules at
the protocol edge.

## Where to make common changes

### Add or change an HTTP endpoint

Start in `crates/spindle-server/src/routes.rs` and the handler module that owns
the API family. Then check all of these boundaries:

- `routes.rs`: mount the route and keep `MOUNTED` accurate.
- `auth.rs`: use `Authenticated` or another explicit extractor when the route
  requires an identity. A handler that should authenticate must not parse a
  bearer token ad hoc.
- `surface.rs`: update the advertised Matrix surface only when the route is
  implemented and tested.
- `crates/spindle-server/tests/` or the owning module tests: prove the route's
  response and authorization behavior.
- `docs/dashboard.md` and `docs/spec-gaps.md`: run the generated-page workflow
  described in [maintenance.md](maintenance.md) when the route changes the
  served surface.

A feature flag can change whether a route exists. Keep the route table,
`/versions` claims and tests aligned for each feature combination.

### Fix an authentication or authorization bug

Separate caller identity from event authorization:

- `crates/spindle-server/src/auth.rs` turns a bearer token into an identity and
  handles local sessions, appservice tokens and delegated authentication.
- Route and room handlers apply resource-level checks. Follow the handler into
  `rooms/` or the owning service rather than assuming authentication grants
  room access.
- `crates/spindle-server/src/authorize.rs` converts stored events and the
  materialized state into the input for Matrix's authorization predicate. It
  must not invent a second authorization algorithm.

For state-dependent event rules, compare behavior with `ruma` and read
[ADR 0005](architecture-decisions/0005-matrix-state-resolution-on-the-live-path.md)
before changing the send or federation path. [divergence.md](divergence.md)
records which rules are inherited from Matrix and which behaviors are
Spindle-specific.

### Change event order, state or fork handling

Use `spindle-core` first:

- `crates/spindle-core/src/log.rs` owns `RoomLog`, `LinearIndex`, append order,
  forward extremities and the bounded federation-DAG overlay.
- `crates/spindle-core/src/state.rs` owns state roots, snapshots, trie
  rehydration and state-resolution inputs.
- `crates/spindle-core/src/pdu.rs` owns event parsing and validation of the
  event value.
- `crates/spindle-core/src/state_table.rs` owns the state-key table used by
  the in-memory state representation.

The server adapters in `state_res.rs` and `state_res_v1.rs` provide the
room-version rules. The durable implementation in `spindle-store` should
persist and restore the core model; it should not decide Matrix semantics.
Read [ADR 0001](architecture-decisions/0001-linear-storage-dag-overlay.md) for
the linear-order/federation-DAG decision and [ADR 0005](architecture-decisions/0005-matrix-state-resolution-on-the-live-path.md)
for the current resolver boundary.

### Change a storage read, write or recovery path

Start in `crates/spindle-store/src/lib.rs`:

- `codec.rs` defines the on-disk record representation and versioned encoding.
- `backup.rs` defines store backup and restore behavior.
- `migrate.rs` defines storage migrations.
- The key names and content-addressed state layout come from
  `spindle-core::keys` and the core state types.

Keep storage operations narrow: the store provides ordered key-value reads,
scans and writes; query or protocol policy belongs in the server. Check
restore, migration and corruption behavior when changing a record or keyspace.
The lifecycle contract is in [lifecycle.md](lifecycle.md).

### Change federation or room behavior

The protocol-facing code lives in `crates/spindle-server/src/`:

- `federation.rs` and `federation/` handle signed server-server requests,
  keys and federation-wide behavior.
- `inbound.rs` and `inbound/` handle incoming events, gaps, backfill and
  recovery.
- `rooms/` owns room reads, writes, extremities, policy and room-local
  services.
- `state_res.rs` and `authorize.rs` connect those paths to the core state model
  and Matrix authorization rules.

Use the Complement and federation tests before changing a boundary. The
interoperability and divergence expectations are documented in
[conformance-testing.md](conformance-testing.md) and [divergence.md](divergence.md).

### Change operator workflows

The standalone operator service is under
`crates/spindle-operator/src/`:

- `engine.rs` owns checkpointed operations, leases, approvals, cancellation
  and compensation over the journal.
- `driver.rs` is the deployment-specific driver interface.
- `api.rs` defines the `/_spindle/operator/v1` API used by the console and CLI.
- `auth.rs` owns OIDC-backed sessions, CSRF and roles.
- `homeserver.rs` reads homeserver people, rooms and reports through an admin
  connection; the browser does not hold that credential.
- `console.rs` serves the browser console, while `secret.rs` handles secret
  references and redaction.

Operator state has its own disk and journal. Changes to a deployment driver
should not require changes to the homeserver request path.

## Before opening a pull request

1. Read the relevant section above and the linked ADR or contract page.
2. Add a behavior test at the boundary that would have failed before the
   change. Follow the test and generated-page requirements in
   [CONTRIBUTING.md](../CONTRIBUTING.md).
3. If a route, Matrix surface claim or generated page changed, run the
   regeneration and drift checks described in [maintenance.md](maintenance.md).
4. Run the smallest relevant workspace checks, then the pull-request gates
   from [CONTRIBUTING.md](../CONTRIBUTING.md).

When the code and this guide disagree, update the guide only after confirming
the code and its tests express the intended boundary. The specification and
accepted ADRs are the decision record for architectural changes.
