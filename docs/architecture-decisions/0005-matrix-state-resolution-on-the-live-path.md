# ADR 0005: Matrix state resolution on the live path

**Status:** accepted. Migration evidence remains a gate in #563.

## Context

SPEC §9.2 once used a custom merge for forks. It handled forks in three ways:

1. A non-state event had a stale parent.
2. On each branch, a different slot changed.
3. Branches changed the same slot.

The first two cases did not call the resolver. For the third case, Spindle set a tip aside through `RoomLog::set_aside_contested` (#225).
Local users could still write. Peers could retain a different state indefinitely.

Separate slots do not imply independent authorization. For example, a ban can void a concurrent topic change by the banned user.
A timestamp can also make an older value win over its replacement.
`crates/spindle-core/tests/state_res_equivalence.rs` tests both cases against ruma.

The latest log entry also represented only one branch after a fork.
In Matrix, current state comes from all forward extremities.
Spindle must use that state, and the state before each event from a peer, for authorization.
These differences block the migration of `reilly.asia` until the comparison with peers passes.

## Decision

Spindle uses the algorithm of the room version. It calls the resolver when inputs differ.
`RoomLog::resolve_parents` supplies this operation for three paths:

- **Before an event:** resolve the states after its parents.
  This applies to events from peers, local events, templates, and federation reads at an event.
- **Current state:** resolve the states at all forward extremities.
  Recompute this state after an append with multiple tips, and when the room reopens.
- **Restore:** rehydrate the stored trie for an entry with different parent states.
  Do not substitute another merge algorithm.

The server supplies `state_res::RoomResolver`:

- Version 1 uses `state_res_v1` (#573).
- Versions 2 to 11 use ruma with state resolution v2.0.
- Version 12 and MSC4242 use v2.1, with an empty initial state and the conflicted subgraph.

Resolution uses ruma's `check_state_dependent_auth_rules` for authorization.
The send path uses the same predicate.

### Identical input states

A single parent needs no resolution. Multiple parents also need no resolution when their roots match.
Their state sets and auth chains match, so every supported algorithm returns the same state.
A fork of messages often has this property.
A stale message can still leave a tip with a different state; current state then needs resolution.

The core retains `Strict` for callers without room-version rules.
It returns `NeedsStateResolution` when parents disagree.
The full importer supplies the resolver or a recorded state from Synapse.
We cannot determine a valid result from topology alone.

The server no longer calls `set_aside_contested`.
A local event names up to ten of the newest extremities, as Synapse does.
The server authorizes it against the resolution of those parents.

### Checks for incoming events

After signature and hash checks, `Rooms::ingest` checks authorization in this order:

1. Validate the auth-event list and the state it names.
   If an auth event has a rejection, reject the dependent event.
2. Validate the event against the resolved state before it.
   Failure of either check rejects the event.
3. Validate it against current state.
   Failure of this check alone causes a soft failure.
   Skip this duplicate check when the parents equal the current extremities.

The store retains both rejected events and events with a soft failure as `SidelinedEntry` records.
The `Sidelined` keyspace holds their parents, depths, verdicts, and state roots.

- A rejected event retains the state before it.
- An event with a soft failure contributes its own state change to its retained snapshot.
- Neither event becomes a forward extremity.
- Neither event gets a linear index or a stream row.
- Client endpoints cannot return either event.

Timeline readers therefore need no extra filter.
The log excludes these events by construction.

An unknown parent or auth event shows missing history.
The server refuses the event without a permanent verdict.
A new transaction can retry it after that history arrives.
Automatic gap retrieval through `/get_missing_events` and `/state_ids` remains separate work.

### Cost and caches

Every log entry already holds the content address of its state.
The server can rehydrate a snapshot without a walk through the timeline.
Resolution adds these operations:

- Compare one root per input. Equal roots end the operation immediately.
- Compute the auth difference through a graph walk, following Synapse's approach.
  Each node starts with the sets that contain it.
  Sets flow down auth edges in reverse topological order.
  Stop when every set can reach every node left to visit.
- Cache each node's rank and auth edges in `AuthGraph`.
  Signed bodies fix those edges for the lifetime of the event.
- Give ruma the difference as one chain beside empty chains.
  Its union-minus-intersection operation then preserves that difference.
- Compute the v2.1 subgraph from the same graph.
- Cache results in `ResolutionCache`, keyed by sorted input roots.
  Fixed roots represent the same state and the same resolution question.

The graph supports all input sets. It supports more than 64 sets.
A repeated current-state read or local append can reuse an existing result.
The store does not persist current state over multiple tips; the room resolves it once after restart.

### Validation

The test and evidence paths include:

- Generated forks compared with ruma in `state_res_tests.rs`.
- Two-server and three-server partition tests in `tests/federation_state_resolution.rs`.
- Complement cases against Spindle and Synapse.
- A corpus harness for `Rooms::receive_remote`, with comparison against Synapse's recorded states.
- Property tests for canonical trie removal and shared nodes.

The corpus harness and interop jobs provide evidence paths.
Their presence does not establish that the complete production rehearsal has passed.
Issue #563 tracks those gates.

## Consequences

SPEC §6 describes the linear case. SPEC §9 now follows this ADR.
The previous equivalence claim for separate slots no longer applies.
ADR 0001's fast path narrows to identical states.
`RoomLog::fork_window` remains a bounded search for diagnostics.
It no longer supplies the resolver's input.

`spindle_fork_resolutions_total{case="3"}` counts appends that need resolution because their parents differ.
It counts no deferral.
`spindle_pdus_sidelined_total{verdict}` counts rejections and soft failures.
Use these counters to find disagreements with peers.

The versionless importer refuses a fork with different parent states.
The full importer uses the rules from Matrix and checks its result against Synapse.
A recorded state can also preserve history that Synapse already resolved.

The live resolver omits IDs and senders that ruma cannot parse.
Historical bridge users can expose this limitation.
The corpus check must report these inputs and any differences.
They remain a migration gate.
