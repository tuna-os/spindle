# ADR 0005: Matrix state resolution on the live path

**Status:** accepted (#563, gate "State resolution matches peers on contested forks")

## Context

SPEC §9.2 handled a federation fork with Spindle's own merge, cheapest case
first:

1. a non-state event on a stale parent: append it, no resolution;
2. a state event whose slot nothing else in the fork window touched: fold it
   in, no resolution;
3. a slot both branches moved: hand it to the room version's resolver.

Case 3 was never wired in. The log set the contesting tip aside
(`RoomLog::set_aside_contested`, #225) and authored local events without it,
so the room stayed writable, but Spindle and its peers held different state for
that slot from then on.

SPEC §9.3 claimed cases 1 and 2 were *equal* to state resolution, so only
case 3 needed the resolver. That claim is false. State resolution does not
merge slot by slot; it re-runs the authorization rules over everything that
differs, in an order fixed by power level, `origin_server_ts` and event ID.
Two counterexamples, both now tests in
`crates/spindle-core/tests/state_res_equivalence.rs` against ruma's reference
resolver:

- **A ban voids the other branch's write.** Branch A: Bob sets the topic.
  Branch B: Alice bans Bob. Each branch moved one slot, so §9.2 took both.
  State resolution applies the ban, then re-checks Bob's topic against it and
  drops the topic.
- **Clocks decide ties.** Branch A sets the topic from a server whose clock
  runs behind. Branch B touches another slot. §9.2 took A's topic because only
  A moved it. State resolution orders the two topic values by timestamp, and
  the value A replaced has the later timestamp, so it wins.

There is a third gap. The room's *current* state is the resolution of all its
forward extremities, and Spindle read the newest log entry's state instead,
which after a fork is one branch's. Incoming PDUs were authorized against that
same head state, not against the state before the event as the spec requires.
So soft-failure and rejection did not exist.

Each of these leaves Spindle and every Synapse in the room permanently on
different current state. No later event converges them, because each side
keeps resolving its own forks its own way. After cutover, `reilly.asia` would
drift from its peers on the first contested fork. The corpus has 365 v9, 177
v6 and 15 v1 conflicted forks, plus the v10 rooms (#573), so this is not
hypothetical.

## Decision

**Wherever Spindle needs one state from several, it runs the room version's
state resolution algorithm.** There are three such places, and all three go
through `RoomLog::resolve_parents`:

- **The state before an event:** an incoming PDU, a locally built event, a
  `make_*` template, and `/state` and `/state_ids` at an event. It is the
  states after the event's `prev_events`, resolved.
- **The room's current state:** the states of its forward extremities,
  resolved after every append that leaves more than one, and once when a room
  reopens with a fork open (`RoomLog::current_state`).
- **Restore:** an entry whose parents disagree is not refolded. Its state is
  rehydrated from the trie that was stored when it was resolved.

The resolver is `spindle_server::state_res::RoomResolver`. It dispatches on
the room version:

- room version 1: `state_res_v1` (#573, agrees with Synapse on all 15
  conflicted v1 forks);
- room versions 2 to 11: `ruma::state_res::resolve` with state resolution
  v2.0;
- room version 12 and MSC4242: v2.1 (empty initial state, conflicted state
  subgraph).

Every authorization question inside resolution is ruma's
`check_state_dependent_auth_rules`, the same predicate as the send path.

### What is left of the §9.2 merge

Only the case that provably equals every room version's algorithm survives:
**one parent, or parents whose states are identical** (the same content
address). With identical state sets, every algorithm has an empty conflicted
set and returns the unconflicted state unchanged:

- v1 splits on keys with different values;
- v2.0 and v2.1 build the auth difference from identical chains, which is
  empty.

This is the overwhelmingly common case. A fork of messages, or a non-state
event on a stale parent, has parents with the same state.

Everything else goes to the resolver:

- case 2 (disjoint slots), because of the counterexamples above;
- the current state after case 1, because a stale non-state event leaves an
  extremity whose state differs from the head's.

The core keeps `Strict`, a resolver that resolves nothing and refuses with
`NeedsStateResolution`. It serves callers with no room version: the log's own
tests, and the importer, which takes Synapse's resolved state at a contested
fork.

`set_aside_contested` is gone. With a resolver there is nothing to step around.
A local event names the newest ten forward extremities (Synapse's figure) and
is authorized against their resolution.

### The checks on receipt of a PDU

`Rooms::ingest` now runs the spec's checks in the spec's order, after
signatures and hashes:

1. Against the event's auth events: the state-independent rules on the list
   itself, then the rules against the state the list names. A rejected auth
   event rejects the event.
2. Against the state before the event (resolved as above). Failing 1 or 2
   **rejects** the event.
3. Against the room's current state, unless the event's parents are exactly
   the forward extremities (then the two states are the same). Failing only
   this check **soft-fails** the event.

Rejected and soft-failed events are kept, because a later event may name
them. They are kept *outside the linear log*, as `SidelinedEntry`, under a new
`Sidelined` keyspace with their state root:

- A rejected event's state is the state before it.
- A soft-failed event's state includes the event.
- Neither is a forward extremity.
- Neither has a linear index, a stream row or a body any client endpoint
  returns.

So no timeline reader (pagination, sync, search) needed a filter. Nothing that
walks the log sees them.

Prev or auth events this server does not hold are refused without keeping
anything. That is a gap to fill, not a verdict. Filling gaps
(`/get_missing_events`, `/state_ids` at the gap) is separate work.

### Cost, for a room of a million events

What Synapse spends on state groups, Spindle already has: every entry carries
the content address of the state after it. The state at any event is one trie
rehydration, and resolution inputs are snapshots in hand. What resolution adds:

- **Comparing the parents:** one root comparison per parent, so free in the
  linear case.
- **The auth difference:** Synapse's own walk
  (`_get_auth_chain_difference_txn`), not full chains handed to ruma. Each
  state event is seeded with the sets that contain it. Sets flow down
  `auth_events` edges, highest rank first. The walk stops as soon as
  everything left is reached by every set.
  - The rank (one more than the highest auth event's) lives in a per-room
    `AuthGraph`. It is built from stored bodies the first time a room resolves
    and kept for as long as the server runs: an auth edge is part of a signed
    body and never changes.
  - The walk is in-memory integer work proportional to the state, not to the
    room's history.
  - The difference is handed to ruma as one chain beside empty ones, which
    ruma's union-minus-intersection returns unchanged.
- **The conflicted subgraph (v2.1):** computed from the same graph.
- **Repeats:** a `ResolutionCache` keyed by the sorted input roots. A root
  addresses a whole state, and every input a resolution reads is fixed by
  those states, so a hit is the same question. The next local event, the
  current state over the same tips, and a peer's event naming them all cost
  one resolution between them.

The resolved current state is not persisted. A room that reopens with a fork
open resolves once.

## Consequences

- Spindle resolves contested forks the way its peers do. The tests and the
  evidence are in #563:
  - unit tests per room-version family;
  - two-server and three-server contested forks;
  - a replay of the production corpus's conflicted forks through
    `Rooms::receive_remote`, compared with Synapse's state groups.
- SPEC §6's heading "State without state resolution" now describes the linear
  case only. SPEC §9 is rewritten to match this ADR. §9.3's equivalence claim
  is withdrawn and replaced by the identical-states rule, which is the only
  form of it that is true.
- ADR 0001's "if the parent states are identical or differ only on disjoint
  state slots, their materialized snapshots merge without full state
  resolution" narrows to "identical".
- The fork window (`RoomLog::fork_window`, SPEC §9.1) no longer feeds
  resolution. It stays as the bounded ancestry search it is, for diagnostics.
- `spindle_fork_resolutions_total{case="3"}` now counts appends whose parents
  were resolved. It no longer counts deferrals.
- `spindle_pdus_sidelined_total{verdict}` counts soft-failed and rejected
  PDUs. A peer whose events land there disagrees with this server about the
  room's state.
- The importer's `append_remote` refuses every fork whose parents disagree,
  not only same-slot ones, so more imported events take Synapse's state. That
  is the correct answer for history Synapse already resolved.
- Unparseable IDs. An event ID ruma cannot parse is left out of the maps
  handed to the resolver, and so is an event whose sender ruma refuses (#573
  found one bridge user). These are the inputs where a resolution can still
  differ from Synapse's. The corpus check counts them.
