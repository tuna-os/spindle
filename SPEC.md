# Spindle — a linearized Matrix homeserver

**Status:** design specification, v0.1
**Scope:** a Matrix homeserver whose internal room model is an append-only linear
log rather than a DAG, which speaks the unmodified Matrix Client-Server API to
existing clients and the unmodified Server-Server API to existing homeservers,
and which pays the cost of state resolution only in the narrow cases where a
peer actually forces a fork.

---

## 1. Summary

Matrix's room model is a Directed Acyclic Graph replicated across homeservers.
Every design decision downstream of that — state groups, `auth_chain_difference`,
State Resolution v2, topological ordering for pagination, backfill — exists to
answer one question: *given several concurrent branches, what is the room state?*

In the overwhelming majority of real traffic there are no concurrent branches.
A room owned by one server, or a room whose events all flow through one
serializing node, has a DAG that is a **chain**: every event has exactly one
`prev_event`, and there is never more than one forward extremity. On a chain,
state resolution is the identity function. Every mechanism built to support it
is pure overhead.

Spindle takes the Linearized Matrix insight (MSC3995 / `draft-ralston-mimi-linearized-matrix`)
and applies it *inward*, as a server implementation strategy, rather than only
outward as a federation profile:

1. **Rooms are stored as a linear log.** Order is assigned once, at ingest, by
   the room's serializing authority. `(room_id, li) -> event`, `li` a signed
   64-bit linear index.
2. **State is materialized, not computed.** Room state at any point is a
   persistent hash-array-mapped trie with structural sharing. Advancing state by
   one event copies ~3 nodes. State at an arbitrary historical point is a single
   pointer lookup.
3. **State resolution is an exception path.** It runs only over the bounded
   window between a fork point and the current head, only when a legacy DAG peer
   actually forks, and only when the fork contains conflicting *state* events.
   It never runs over a whole room, and in a non-federated room it never runs at
   all.
4. **Wire format is unchanged.** Native Spindle rooms are ordinary **room
   version 11** rooms. A chain is a valid DAG. Existing clients and existing
   homeservers cannot tell the difference, which is what makes "completely
   support existing Matrix clients and API" achievable rather than aspirational.
5. **The MSC3995 hub protocol is an optimization on top**, negotiated per room
   via `m.room.hub`. When peers support it, forks become structurally impossible
   and the exception path is dead code. When they don't, we fall back to
   tolerating rare forks cheaply.

The result: the fast path for a message in a local or hub-owned room is an
in-memory authorization check, a hash, a log append, and a push to subscribers.
No transaction spanning multiple tables, no state group allocation, no
topological sort, no auth chain walk.

---

## 2. Goals and non-goals

### Goals

| # | Goal |
|---|---|
| G1 | Unmodified Element Web/Desktop, Element X, Fluffychat, Cinny, Nheko, and any spec-compliant client work against Spindle with no client changes and no capability negotiation beyond what the spec already defines. |
| G2 | Full Matrix Client-Server API v1.16 surface, including E2EE plumbing, threads, spaces, authenticated media, and both `/sync` and Simplified Sliding Sync (MSC4186). |
| G3 | Federate with Synapse, Dendrite, Conduit/conduwuit and any other spec-compliant homeserver over the unmodified Server-Server API, for room versions 6–11. |
| G4 | Zero state-resolution work, zero auth-chain traversal, and zero topological sorting on the ingest and read paths for rooms with no DAG peers. |
| G5 | Per-room throughput and latency that scales with cores by sharding rooms across single-writer executors, with no cross-room coordination on the hot path. |
| G6 | Ordering authority (the hub) is trusted for *sequence*, never for *content*: every event remains origin-signed and hash-chained, and hub equivocation is detectable and provable. |
| G7 | Interoperate with the IETF MIMI direction: MSC3995 linearization as a first-class federation mode, with a path to MLS (MSC4244 / MSC4256) once those stabilize. |

### Non-goals

- **Not** a new client protocol. No client SDK changes, no bespoke API.
- **Not** peer-to-peer or serverless Matrix.
- **Not** a replacement for the DAG in rooms that genuinely need leaderless
  operation. Those rooms keep the full DAG semantics; they just don't
  subsidize the ones that don't.
- **Not** an MLS implementation in v1. Megolm/Olm are supported unchanged
  (the server is largely oblivious to either). MLS is a v2 track, §16.
- **Not** a bridge, identity server, or push gateway, though it speaks to all
  three.

---

## 3. Design thesis: where the time actually goes

The costs Spindle is designed to eliminate, and why they exist:

| Mechanism | Why the DAG needs it | Cost class | Spindle |
|---|---|---|---|
| State Resolution v2 | Merge divergent state across concurrent branches | O(conflicted state × auth chain) — superlinear, and the pathological cases are the "state reset" bugs operators know by name | Runs only over a bounded fork window; never in Class L/H/P rooms |
| `auth_chain_difference` | Input to state res v2 ordering | Graph reachability over the whole auth chain; the single hottest query in large-room Synapse | Never computed globally; window-bounded, and unnecessary under MSC3995 |
| State groups + deltas | Avoid storing full state per event | Chains of deltas that must be walked; periodic compaction; unbounded growth on fork-heavy rooms | Persistent HAMT with content-addressed nodes; O(log n) copy per update, O(1) historical lookup |
| Topological ordering | `/messages` must paginate in DAG order, which is not insertion order | Sort at read time, or maintained `topological_ordering`/`stream_ordering` pairs | `li` **is** the topological order, assigned once at write |
| Backfill + `/get_missing_events` | Reconstruct ancestors of a received event | Recursive fetch, re-auth, re-state | Still needed for legacy peers; linearized once at ingest, never re-derived |
| Forward extremity management | Multiple heads must be tracked and merged | Extremity table growth is a known Synapse pathology | Exactly one extremity in classes L/H/P; in class D a stale peer PDU adds one transiently, and the next local event merges it away (§4) |
| Full state on join | `/send_join` returns the whole room state | 10k-member room = tens of MB and a state res over it | Materialize once into a HAMT root; faster joins (MSC3706/MSC3902) for large rooms |

The observation that makes this tractable: **all of these are federation
mechanisms.** A homeserver running a room whose members are all local executes
every one of them, on every event, to solve a problem it does not have.

---

## 4. Room classes and the linearity invariant

Every room on a Spindle server is in exactly one class. Class is derived state,
recomputed on membership change, and stored in room metadata.

| Class | Definition | Serializer | State res | Signing |
|---|---|---|---|---|
| **L — Local** | Every joined/invited member is local. No remote server in the room. | This server | Never | Lazy (§8.4) |
| **H — Hub** | This server holds `m.room.hub`; all remote participants are LM-capable. | This server | Never | Eager |
| **P — Participant** | Another server holds `m.room.hub`; we submit proposals to it. | Remote hub | Never | Eager (origin signature) |
| **D — DAG** | At least one participant is a legacy homeserver that authors its own `prev_events`. | This server for local events; forks possible | Bounded window only (§9) | Eager |

**Linearity invariant (LI):** *storage order is always linear — every accepted
event receives exactly one monotonic `li` — and the federation overlay is
normally, but not always, a chain.*

In classes L, H and P the whole room is a chain: this server authors every event
with exactly one `prev_event`, the current head, because nobody else appends.

Class D is the exception, and it is why the invariant is stated about storage
order rather than about `prev_events`. When a legacy peer sends a PDU naming a
stale predecessor, that PDU **cannot be rewritten** — its signature covers
`prev_events` — so the room briefly holds more than one forward extremity. The
next locally authored event references *every* current extremity, up to Matrix's
limit of 20, which collapses the DAG back to a single head.

The naive alternative — appending after our own head and ignoring the stale
event — does not merge anything: the stale event remains a forward extremity
indefinitely, and the two heads can carry different state. See
[ADR 0001](docs/architecture-decisions/0001-linear-storage-dag-overlay.md), which
records this correction and is the normative statement where it and this section
disagree.

### 4.1 Class transitions

```
L ──first remote member joins, peer advertises LM──▶ H
L ──first remote member joins, peer is legacy─────▶ D
H ──legacy server joins──────────────────────────▶ D
H ──we hand off m.room.hub───────────────────────▶ P
P ──we are elected hub───────────────────────────▶ H
D ──last legacy server leaves────────────────────▶ H  (requires quiescence, §9.4)
* ──last remote member leaves─────────────────────▶ L
```

Transitions are themselves state events in the log, so the class at any `li` is
recoverable. `D → H` demotion is the only transition that requires care: we must
be certain no in-flight legacy PDU can still arrive. We require a quiescence
period of `2 × federation_timeout` after the last legacy server's `m.room.member`
leave is committed before the room may be treated as fork-free.

The critical consequence: **the class-D machinery is entirely absent from the
class-L and class-H hot paths.** It is not a branch that evaluates to false; the
executor for those rooms does not contain the code.

---

## 5. Core data model: the linear log

### 5.1 The linear index

Each room has an ordering key `li: i64` and two monotonic counters in room
metadata:

- `next_forward: i64`, starting at `1`, incremented for every appended event.
- `next_backward: i64`, starting at `0`, decremented for every backfilled event.

Live events get ascending positive `li`. History fetched by backfill gets
descending non-positive `li`. Backfill always proceeds strictly backwards from
the current earliest known event, so no insertion *between* two stored events is
ever required and a plain integer key suffices — no fractional indexing, no
rebalancing.

`li` is the room's topological ordering by construction. `/messages` pagination
is a reverse range scan. `prev_batch`/`next_batch` tokens are `t{li}`.

### 5.2 Event record

```rust
struct LogEntry {
    li: i64,                      // ordering key, primary
    event_id: EventId,            // $ + unpadded-b64url(reference_hash)
    prev_li: i64,                 // doubly-linked: predecessor's li
    kind: EventKind,              // Message | State | Ephemeralized | Rejected
    state_key_slot: Option<u32>,  // interned (type, state_key) id, state events only
    sender: UserId,
    origin_server_ts: u64,
    depth: u64,                   // maintained for DAG projection only
    state_root: Option<StateRoot>,// present iff this entry changed state
    flags: u16,                   // redacted, soft_failed, outlier, locally_authored, ...
    federation_json: Blob,        // canonical JSON PDU, exactly as signed
    client_json: Blob,            // pre-rendered client-format event (§10.6)
}
```

Two rendered forms are stored. The read:write ratio in a chat server is
enormous — every message is written once and read by every member, on every
device, plus every reconnect and every back-scroll. Rendering the client
representation at write time turns `/messages` and `/sync` timeline assembly
into a framing operation over blobs, with no JSON reparse and no re-serialization.
The cost is disk, which is cheap, and a rebuild step on format changes, which is
a versioned migration.

`federation_json` is the byte-exact canonical JSON that was signed. It is never
regenerated, because regenerating it risks a different byte sequence and a
signature that no longer verifies.

### 5.3 The hash chain

Beyond the standard Matrix `prev_events`/reference-hash linkage, the serializing
server maintains a **log chain**: a running hash

```
chain[li] = BLAKE3( DOMAIN || chain[li-1] || event_id[li] )
```

seeded from `BLAKE3(DOMAIN)`, where `DOMAIN` is `"spindle-log-chain-v1\0"`. The
serializer signs `(room_id, li, event_id, chain[li])` with its Ed25519 server
key and stores that signature. This is a transparency-log construction, and it
is what upgrades "trust the hub for ordering" into "detect the hub cheating
about ordering" (§13.3).

Two properties are load-bearing and are tested as such. Each value commits to
the *entire* ordered history before it, so the same events in a different order
produce a different chain — attesting to sequence, not merely to membership.
And a divergence never re-converges: two histories that differ at one index
disagree at every index after, even where later events are identical, so the
first differing value localises the change.

**Only forward-appended entries carry a chain value.** Backfilled history was
sequenced by another server and arrives with its own provenance; attesting to
an order we did not choose would be a claim we cannot back. A server's chain
covers what it ordered.

An earlier revision specified SHA-256 here. BLAKE3 is used instead, for
consistency with the state trie's content addressing (§6.1) and its
domain-separation convention: one hash function and one input-framing rule
across the codebase means no construction's value can be replayed as another's.
Nothing in Matrix constrains this choice — the chain is Spindle's own
attestation, not a spec-defined wire hash — but if it is ever standardised for
cross-implementation equivocation proofs, the algorithm becomes an interop
concern and should be revisited then.

### 5.4 Indexes

| Index | Key → Value | Purpose |
|---|---|---|
| `log` | `(room_id, li)` → `LogEntry` | Primary; range scans for pagination |
| `event_index` | `event_id` → `(room_id, li)` | `/event`, `/context`, redaction targets |
| `state_nodes` | `node_hash` → `HamtNode` | Content-addressed state trie (§6) |
| `state_roots` | `(room_id, li)` → `StateRoot` | Sparse: only at state-changing `li` |
| `relations` | `(room_id, target_event_id, rel_type, li)` → `event_id` | Threads, edits, reactions |
| `membership` | `(room_id, user_id)` → `(membership, li)` | Fan-out, ACL, room lists |
| `user_rooms` | `(user_id, room_id)` → `membership` | Room list, sliding sync |
| `stream` | `stream_id` → `(room_id, li)` | Global order for `/sync` catch-up (§10.2) |
| `chain_sigs` | `(room_id, li)` → `Signature` | Log-chain attestations |

All of these are ordinary sorted-key ranges. There is no join, no recursive CTE,
and no graph traversal in any read path.

---

## 6. State without state resolution

### 6.1 The structure

Room state is a map `(event_type, state_key) -> event_id`. Spindle represents it
as a **persistent hash-array-mapped trie** (HAMT), 32-way branching, keyed by a
64-bit hash of the interned `(type, state_key)` pair.

- Nodes are **content-addressed**: a node's identity is the BLAKE3 hash of its
  serialized contents. Identical subtrees across snapshots, across rooms, and
  across restarts deduplicate automatically in the `state_nodes` column family.
- Updating one key is **path copying**: allocate a new leaf and ~`log32(n)` new
  internal nodes, reusing every untouched subtree. For a 30,000-state-event room
  that is 3–4 node writes, roughly 500 bytes.
- A `StateRoot` is a 32-byte hash. Storing the full room state at every
  state-changing event costs 32 bytes plus the path copy.

### 6.2 The two operations

```
apply(root, event) -> root'          // fold one state event; O(log n) node copies
lookup(root, type, state_key)        // O(log n) pointer chases, all in memory when hot
```

That is the entire state subsystem for classes L, H and P. There is no state
group table, no delta chain to walk, no compaction job, no `state_group_edges`,
no "prune the state groups" cron, and no way to produce a state reset — because
there is nothing to resolve.

### 6.3 State at an arbitrary point

```
state_at(room, li) = state_roots.range(..=(room, li)).next_back()
```

One reverse seek in a sorted index, then O(log n) lookups in the trie. This
makes historical state — which Synapse pays for with state groups and which
drives a large fraction of its storage — effectively free, and it makes
`/messages` with `lazy_load_members`, `/context`, and `/state` at a point all
trivial.

### 6.4 In-memory representation

Each active room's executor holds `Arc<HamtNode>` for the current state root,
fully resident. Cold subtrees are loaded on demand from `state_nodes` and cached
globally (content addressing means one shared cache serves all rooms).
A room with 50k state events holds on the order of a few MB resident; rooms
evict to disk under an LRU keyed by last activity, retaining only the 32-byte
root.

Within a room the same rule applies per entry. Every log entry keeps its state
root — 32 bytes, forever — but the materialized snapshot it names is held only
while something can still ask for it. Retaining one snapshot per entry sounds
free, because the trie shares structure perfectly, but it is not: each append
path-copies `O(log n)` nodes and keeping every root alive keeps every version of
every copied path alive with it, so memory grows with the length of the log
rather than with the size of the state.

Snapshots are therefore retained for:

- the most recent `resident_window` entries, defaulting to `max_fork_window`
  (§9.1). The coupling is the argument: a fork deeper than the window already
  falls back to full state resolution, which reads the trie from the store, so
  a window this size holds everything the fast path can reach and nothing that
  only the slow path can;
- every forward extremity, at any age. A class-D stale peer event can leave an
  extremity arbitrarily far back (ADR 0001), and the next local event has to
  merge that extremity's state with the head's;
- the entry just written, so a backfill prepend — which takes an index far
  below the window floor — can hand its `/state_ids` state to the store before
  it is dropped.

Anything else is rehydrated from `state_nodes` by its root, which is `O(log n)`
in the size of the state. The bound is asserted rather than assumed: a room
whose resident count tracks its length has lost it.

### 6.5 Backfilled history

Backfilled events have `li <= 0` and their state must be established backwards.
Rather than computing state per event, Spindle backfills in chunks:

1. Fetch a chunk via `/_matrix/federation/v1/backfill` (descending).
2. Reverse it to ascending order.
3. Fetch `/_matrix/federation/v1/state_ids/{roomId}?event_id=` **once**, at the
   oldest event of the chunk.
4. Materialize that state into a HAMT root.
5. Fold forward across the chunk, writing `state_roots` as it goes.

One `/state_ids` round trip per chunk rather than per event, and one materialize
rather than a state res per event. Fetching state for backfilled ranges is
asynchronous and does not block `/messages`: events are served with their
`li` order immediately, and lazy-loaded member state resolves as the chunk's
state materializes.

---

## 7. Authorization

Authorization is unchanged from the Matrix spec — the same rules, evaluated in
the same order, producing the same accept/reject/soft-fail outcomes. What
changes is how the inputs are obtained.

### 7.1 Auth on the fast path

For an event authored locally or received into a linear room, the auth check is:

1. `lookup(current_state_root, "m.room.create", "")`
2. `lookup(current_state_root, "m.room.power_levels", "")`
3. `lookup(current_state_root, "m.room.member", sender)`
4. For `m.room.member`: also `("m.room.member", state_key)`,
   `("m.room.join_rules", "")`, `("m.room.third_party_invite", token)`, and for
   restricted joins the `join_authorised_via_users_server`'s member event.

At most six trie lookups against an in-memory structure, then the auth rules.
**No auth chain is traversed.** The DAG's auth chain exists to let a server
verify an event against state it may not have; a serializer that holds the
authoritative current state does not need it.

`auth_events` is still *written into* the event, derived from the same lookups,
because the DAG projection and every legacy peer expect it. Deriving it is free —
it is the same six lookups.

### 7.2 Rejection and soft-fail

Both are retained exactly per spec. A rejected event is persisted with
`flags.rejected` and excluded from state and from client-visible timelines. A
soft-failed event is persisted and not sent to clients, but remains a valid DAG
ancestor. These flags live in the log entry, so "was this soft-failed" is a field
read rather than a query.

### 7.3 Power level changes

A `m.room.power_levels` change is a single `apply()`. Nothing is recomputed for
existing events — Matrix authorizes events against the state *at* the event, not
current state, and `state_at(li)` is already O(1). This is the case that
produces the worst state-group behavior in DAG servers and it is uneventful here.

---

## 8. The ingest pipeline

### 8.1 Local event, class L or H — the hot path

```
client PUT /_matrix/client/v3/rooms/{r}/send/{type}/{txn}
  │
  ├─ 1. transaction-id dedup (per-device LRU + durable table)
  ├─ 2. route to room executor for shard(r)          ── no lock; mpsc to owner
  │
  │  ── inside the room executor, single-threaded, no contention ──
  ├─ 3. auth check: ≤6 HAMT lookups against resident state_root
  ├─ 4. li = next_forward++;  prev_event = head_event_id
  ├─ 5. build PDU: auth_events from step 3, depth = head.depth + 1
  ├─ 6. canonical JSON (streaming, no intermediate Value)
  ├─ 7. content hash (SHA-256); redact; reference hash → event_id
  ├─ 8. render client_json
  ├─ 9. if state event: state_root' = apply(state_root, e)
  ├─ 10. append to WAL  ─────────────────────────────▶ group commit (§8.3)
  ├─ 11. head = (li, event_id, state_root'); chain[li] = H(chain[li-1] || id)
  └─ 12. publish (room, li) to the room's subscriber list  ──▶ §10.3
```

Steps 3–9 are pure CPU on resident data. Step 10 is a sequential append. Step 12
is a slice iteration over local subscribers. Nothing in this path touches
another room, another shard, or a shared mutable structure.

Note what is *absent*: no state group allocation, no `event_auth_chains`
insertion, no forward-extremity update, no topological ordering computation, no
`current_state_delta_stream` maintenance, no cross-table transaction.

### 8.2 Federation ingest, class D or H

```
POST /_matrix/federation/v1/send/{txnId}
  │
  ├─ 1. X-Matrix auth; reject unsigned/unknown origin
  ├─ 2. structural validation, size caps, per-origin rate limit
  ├─ 3. batch-verify Ed25519 signatures across all PDUs in the transaction
  ├─ 4. durable enqueue of raw PDUs, partitioned by room
  ├─ 5. respond 200 with per-PDU results
  └─ 6. per-room executors drain their partitions:
         ├─ prev_events all known?  ── no ──▶ /get_missing_events, then retry
         ├─ prev_events == our head? ── yes ─▶ append at tail (§8.1 steps 3–12)
         └─ otherwise ─────────────────────▶ fork handling (§9)
```

Step 3 uses batched Ed25519 verification, which amortizes the dominant per-PDU
cost across a transaction of up to 50 PDUs. Step 5 acknowledges after durable
enqueue rather than after full processing; this is the difference between a
federation `/send` that responds in single-digit milliseconds and one that
blocks a remote server's whole outbound queue behind our slowest room.

### 8.3 Durability

WAL append with **group commit**: the fsync is batched across all rooms on a
shard, flushed on whichever comes first of `N` pending entries or `T`
microseconds. Three configurable modes:

| Mode | Behavior | Use |
|---|---|---|
| `strict` | fsync before responding to the client | Regulated / single-node deployments |
| `group` *(default)* | fsync batched, ≤1 ms window, response after batch | General |
| `relaxed` | OS page cache, periodic fsync | Ephemeral / test |

Because ordering is decided before durability, a crash can only lose a suffix of
the log — never reorder it, never fork it. Recovery truncates to the last
complete chain-hash entry and resumes; any client whose event was in the lost
suffix retries with the same transaction ID and gets a fresh `li`.

### 8.4 Lazy signing

The Matrix reference hash (and therefore the event ID) is computed over the
**redacted event with `signatures`, `age_ts` and `unsigned` removed**. Signing
therefore does not affect the event ID.

In class-L rooms, Spindle computes the event ID and appends immediately, and
signs asynchronously (or not at all until the room first federates). Ed25519
signing is the single most expensive operation in the local send path; deferring
it off the latency path is a meaningful win for the most common room type on any
private deployment. Signatures are backfilled over the log — in `li` order,
which the chain hash makes verifiable — at room promotion `L → H` or `L → D`.

---

## 9. Fork handling: the only place state resolution survives

Forks are possible only in class D, only from legacy peers, and only when a peer
authors an event whose `prev_events` are not our head — i.e. it sent concurrently
with us or was partitioned.

### 9.1 The window

Let `A` be the greatest `li` such that every `prev_event` of the incoming event
is at `li <= A`. The **fork window** is `(A, head]`. In practice `|window|` is
bounded by the network round trip times the room's event rate: single digits in
almost every real case. Spindle caps it at `max_fork_window` (default 512); a
window that exceeds the cap falls back to full spec-compliant state resolution
over the affected range, which is correct but slow, and is logged as an anomaly.

The cap bounds the **work**, not merely the answer. Discovering the window must
not require walking each tip's full ancestry back to the room's first event and
intersecting: that would make detecting a three-event fork in a million-event
room cost a million-node traversal, which is exactly the cost this section
claims to remove. The window is found by a bounded reverse breadth-first search
from the tips that stops as soon as the frontiers meet, with the budget applied
to nodes *visited*.

### 9.2 Three cases, cheapest first

**Case 1 — non-state event, no state conflict (the common case, ~99%).**
The incoming event is not a state event. It cannot conflict with anything. Its
DAG position is behind our head, but the client-visible order is `li` order, and
`li` order is a valid linearization of the DAG. Append at the tail with
`prev_li = head`, preserving its original `prev_events` in `federation_json`
(we must not alter a signed event). Cost: identical to §8.1. **No state
resolution.**

**Case 2 — state event, no conflict in window.**
The incoming event is a state event whose `(type, state_key)` was not modified
by any event in the fork window. The fold is order-independent for
non-overlapping keys, so `apply()` at the tail produces exactly the state that
state res v2 would produce. Append at the tail. Cost: one `apply()`. **No state
resolution.**

**Case 3 — state event conflicting within the window.**
Run State Resolution v2, but with both inputs bounded by the window:

- The conflicted state set is the ≤`|window|` state events in the window plus
  the incoming event.
- The auth difference is computed over the auth events of *those events only*,
  which are already resident in the trie — not over the room's auth chain.

The resolved state is materialized as a new root and appended as a state
correction. Cost: O(|window| log |window|) with a small constant, over a set that
is almost always under ten events.

### 9.3 Equivalence argument

The claim that makes this safe: **on a chain, `fold` and `state_res_v2` agree,
and on a fork, window-bounded state res agrees with full state res.**

- On a chain, the conflicted state set is empty (no two branches), so state res
  v2 reduces to "take the unconflicted state", which is exactly the fold.
- On a fork, events at `li <= A` are common ancestors of both branches and
  therefore unconflicted by definition; state res v2 passes unconflicted state
  through unchanged. Restricting the input to the window is therefore not an
  approximation — it discards only inputs that provably cannot change the output.

This is stated as a theorem and tested as one: §19.2 specifies a differential
property test that runs both algorithms over generated DAGs and asserts equality.

### 9.4 Making forks impossible

Case 3 exists only because legacy peers author their own `prev_events`. Under
MSC3995 (§12) participants submit *proposals* and the hub assigns
`prev_event`, so a fork cannot be constructed. For rooms where every peer is
LM-capable, the class is H, and §9 is unreachable code.

---

## 10. Client-Server API compatibility

**The contract is the published spec, not a subset.** Every mapping below exists
to make the standard endpoint behave exactly as specified while exploiting the
linear log underneath.

### 10.1 Compliance surface

| Area | Endpoints | Notes |
|---|---|---|
| Auth | `/login`, `/logout`, `/refresh`, `/register`, UIA flows, `/account/*` | Password + SSO; MSC3861 (OAuth 2.0 / next-gen auth) as a delegated mode |
| Sync | `/sync` (v3), `/sync` Simplified Sliding Sync (MSC4186) | Both, §10.2–10.3 |
| Rooms | `/createRoom`, `/join`, `/knock`, `/invite`, `/leave`, `/forget`, `/kick`, `/ban`, `/upgrade` | Room versions 6–11; native rooms are v11 |
| Events | `/send`, `/state`, `/event`, `/context`, `/messages`, `/relations`, `/redact` | §10.4–10.5 |
| Threads | `/relations/{id}/m.thread`, `m.thread` aggregation, `/threads` (MSC3856) | Server-side aggregation from the `relations` index |
| Receipts | `/receipt`, `/read_markers`, `m.fully_read` | Ephemeral stream |
| Typing / presence | `/typing`, `/presence` | Presence off by default (§18.4) |
| E2EE | `/keys/upload`, `/keys/query`, `/keys/claim`, `/keys/changes`, `/sendToDevice`, `/room_keys/*`, cross-signing, key backup, dehydrated devices | Server is a transport; §16 |
| Media | `/_matrix/client/v1/media/*` (authenticated media, Matrix 1.11) with legacy `/_matrix/media/v3` for compatibility | §17.3 |
| Spaces | `/hierarchy`, `m.space.child`, `m.space.parent` | Hierarchy walked from the `relations` and state indexes |
| Push | `/pushrules/*`, `/pushers/*`, push gateway protocol | Rule evaluation at fan-out |
| Capabilities | `/capabilities`, `/versions` | Advertises supported spec versions and room versions honestly |
| Admin/AS | Application Service API v1, `/_synapse/admin`-equivalent under `/_spindle/admin` | AS transactions ordered by the same stream |

Anything a spec-compliant client may call, Spindle answers. Where a client
depends on Synapse-specific behavior that is not in the spec, that is tracked as
a compatibility bug against Spindle, not as client breakage.

### 10.2 Sync tokens and the global stream

`/sync` requires a total order across rooms. Spindle assigns each committed event
a server-global `stream_id` from a sharded atomic counter, indexed by
`stream -> (room_id, li)`.

Because commits complete out of order, the *visible watermark* is the highest
contiguous committed `stream_id`: an id is publishable only when every lower id
has been durably committed. In-flight ids are tracked in a small interval set per
shard. This is the standard multi-writer stream problem and it is solved the
standard way; the important part is that it is a per-shard integer structure, not
a database query.

Sync tokens are opaque multipart strings:

```
s{events}_{receipts}_{account_data}_{to_device}_{device_lists}_{presence}
```

Each component is an independent stream position, so a burst on one stream
cannot stall another.

### 10.3 Sync as push, not poll

Every long-polling `/sync` and every sliding-sync connection registers with the
subscriber list of each room it watches. Step 12 of §8.1 pushes `(room, li)`
directly to those subscribers. The response is assembled from the room's **hot
tail** — an in-memory ring buffer of the last N (default 512) entries holding
pre-rendered `client_json`.

For an active client, a `/sync` response involves no storage read at all: the
events are in the ring, the state is in the resident trie, and the response is
a framing of existing byte slices.

Storage is touched only for catch-up (a client returning after being offline),
which is a range scan over `stream` and then over `log`, both sequential.

Simplified Sliding Sync (MSC4186) is the preferred path and what Element X will
use: connection state (the client's list ranges, subscriptions, and per-room
`timeline_limit`) is held in memory keyed by `conn_id`, with a durable cursor so
a server restart degrades to a re-initial-sync rather than a wrong answer.

### 10.4 Pagination

`/messages` is a reverse range scan of `log` between two `li` values. Tokens are
`t{li}`. That is the whole implementation.

This is worth stating plainly because it is the endpoint that most visibly
misbehaves on DAG servers: back-paginating a large room requires topological
ordering over a graph that may need backfilling mid-scan. Here, ordering was
decided at write time, and a gap in history is a contiguous `li` range that is
either present or not.

`limit`, `filter`, and `dir` apply as specified. Filters that exclude by type or
sender are evaluated against the fixed-width header fields of `LogEntry` without
deserializing `client_json`.

### 10.5 `/context` and `/event`

`event_index` gives `(room, li)`; `/context` is a symmetric scan around it and
`state_at(li)` for the state block. `lazy_load_members` intersects the senders in
the returned window with the member state at that root.

### 10.6 Pre-rendered client JSON

`client_json` is the event as a client sees it — `event_id`, `sender`, `type`,
`content`, `origin_server_ts`, `room_id`, `state_key`, and `unsigned` minus the
per-request fields. `unsigned.age` and `unsigned.transaction_id` are
request-dependent and are patched in at framing time by a byte-level splice into
the stored object, avoiding a parse.

Redaction rewrites `client_json` in place and marks the flag;
`federation_json` is retained unmodified because the redacted-original must
still verify. Edits (`m.replace`) are aggregated at read time from the
`relations` index, as the spec requires — the original event is not mutated.

---

## 11. Federation: the Server-Server API

Spindle implements the full S2S API. The linear log is projected into DAG form
on the way out and linearized on the way in; peers see an ordinary homeserver.

### 11.1 The DAG projection

For any log entry, the federation representation is `federation_json` verbatim —
the bytes that were signed. `prev_events` is the array written at ingest — one
element in a fork-free room, or the merged extremity set described in §4 — `auth_events` the derived set, `depth` the monotonic counter. A remote
server receiving our events sees a room whose DAG is a chain, which is a
perfectly ordinary DAG that happens never to require state resolution. Nothing
about it is non-standard, and no peer needs to know Spindle exists.

### 11.2 Endpoints

| Group | Endpoints |
|---|---|
| Transport | `PUT /send/{txnId}`, `/_matrix/key/v2/server`, `.well-known/matrix/server`, SRV resolution |
| Membership | `/make_join`, `/send_join` (v2), `/make_leave`, `/send_leave` (v2), `/invite` (v2), `/make_knock`, `/send_knock` |
| State | `/state/{roomId}`, `/state_ids/{roomId}`, `/event_auth/{roomId}/{eventId}` |
| History | `/backfill/{roomId}`, `/get_missing_events/{roomId}`, `/event/{eventId}`, `/timestamp_to_event` |
| Directory | `/query/directory`, `/query/profile`, `/publicRooms`, `/hierarchy/{roomId}` |
| Devices/keys | `/user/devices/{userId}`, `/user/keys/query`, `/user/keys/claim` |
| Media | `/_matrix/federation/v1/media/download`, `/media/thumbnail` (authenticated media) |
| Misc | `/openid/userinfo`, `3pid/onbind`, `/exchange_third_party_invite` |
| EDUs | `m.typing`, `m.receipt`, `m.presence`, `m.direct_to_device`, `m.device_list_update`, `m.signing_key_update` |

### 11.3 Outbound

One ordered queue per destination, drained by a dedicated task: up to 50 PDUs
and 100 EDUs per transaction, one transaction in flight per destination as the
spec requires. Exponential backoff with jitter on failure; destinations are
marked down after a threshold and probed. On recovery, catch-up walks the
`stream` index forward from the destination's last acknowledged position — a
sequential scan, not a graph traversal, which is precisely the operation that
makes federation catch-up expensive on DAG servers.

Hub fan-out in class H broadcasts to all participant destinations in parallel
from the room's executor, with the per-destination queues absorbing slow peers.

### 11.4 Inbound `/send` and head-of-line blocking

The spec permits per-PDU results, and Spindle uses that: signature verification
and structural validation happen synchronously (so a malformed transaction is
rejected immediately), and semantic processing happens in the room executor.
A transaction touching ten rooms is fanned into ten partitions and never blocks
on the slowest.

Rate limiting is per-origin and per-room, with a separate budget for events that
trigger `/get_missing_events` — the classic amplification vector.

### 11.5 Joining an existing large room

`/send_join` may return megabytes of state. Spindle:

1. Streams the response, materializing state directly into a HAMT root without
   building an intermediate map (each state event is one `apply()`).
2. Verifies signatures in batches during the stream.
3. Sets `li = 1` at the join point, `next_backward = 0`, and starts serving
   immediately.
4. Backfills asynchronously into negative `li` per §6.5.

Faster room joins (MSC3706 partial state / MSC3902) are supported on the receive
side: the room is usable with partial state, marked `partial_state`, and the
remaining state is resynced in the background. Membership-dependent operations
block only until the relevant slice of state has arrived.

### 11.6 Room versions

| Version | Support | Notes |
|---|---|---|
| 1–5 | Read-only interop | Legacy event ID format; joinable, not creatable |
| 6–10 | Full | Full DAG semantics with the class-D path |
| **11** | **Full** | `MSC3820` cleanups: no top-level `origin` (MSC3989), no `creator` in create content (MSC2175), `redacts` in content (MSC2174), updated redaction algorithm (MSC2176/MSC3821) |
| **12** | **Full; default candidate — see below** | Current stable version; supported by Ruma 0.16 and by both surveyed Rust homeservers |
| `org.matrix.msc3995.v1` | Experimental | LM room version with hub-assigned `prev_event` (§12.4) |

The load-bearing decision is **not which version number** — it is that native
rooms use an *ordinary* room version. A room whose DAG is a chain needs no new
room version, no client capability and no peer negotiation, while still
delivering every performance property in this document. The LM room version
(§12.4) is needed only to make forks structurally *impossible*, which is an
optimization, not a requirement.

**Open decision: v11 or v12 as the creation default.** The ecosystem is split.
Continuwuity defaults to v12; Tuwunel supports v12 but still defaults to v11.
Both treat v6–v12 as stable, and Ruma 0.16 implements through v12. Spindle must
*support* v12 regardless — a server that cannot join a v12 room is not
interoperable in 2026 — so the only live question is which version
`/createRoom` picks when a client does not ask. Resolve this before M3 against
the version the reference clients and the majority of federating peers actually
create, and record it as an ADR rather than leaving it implied here.

---

## 12. Linearized Matrix mode (MSC3995)

Class H/P is the MSC3995 star topology: participants send to the hub, the hub
orders and fans out.

### 12.1 Hub designation

`m.room.hub` state event:

```json
{
  "type": "m.room.hub",
  "state_key": "",
  "content": {
    "server_name": "hub.example.org",
    "epoch": 7,
    "prev_epoch_final_li": 10432,
    "prev_epoch_final_chain": "base64(chain[10432])"
  }
}
```

Absent an `m.room.hub` event, the hub is the server that sent `m.room.create`,
per MSC3995. `epoch` is monotonic and, together with the chain commitment,
prevents a deposed hub from continuing to serialize a divergent branch: an event
signed by the hub of epoch `n` is invalid once the log contains an
`m.room.hub` at epoch `n+1`, and the new epoch's first event must chain from the
declared final entry of the previous epoch.

### 12.2 Proposal submission

Participants POST an unlinked, origin-signed event to the hub:

```
PUT /_matrix/federation/unstable/org.matrix.msc3995/send_event/{roomId}
```

The hub:
1. verifies the origin signature over the proposal;
2. authorizes it against current state (§7.1);
3. assigns `li`, `prev_event`, `depth`, and `auth_events`;
4. adds its own signature and the chain attestation;
5. fans the completed PDU out to every participant, including the originator.

The originator learns its event's final `event_id` from the fan-out or the
response. Clients see the standard `/send` response semantics because the
originating server holds the client transaction open across the hub round trip,
exactly as it already does for any event requiring remote authorization.

### 12.3 Dual representation

A hub emits ordinary room-version-11 PDUs. A legacy homeserver in the room
consumes them as a normal DAG and is unaware of the hub. An LM-only participant
consumes the same PDUs as a linked list and never implements state resolution.
This is MSC3995's dual-representation property, and it is what allows a room to
contain both kinds of peer simultaneously — at the cost of readmitting the
class-D fork path, which is why `m.room.hub` rooms with legacy members are class
D, not class H.

### 12.4 The LM room version

`org.matrix.msc3995.v1` is room version 11 plus two rules:

1. `prev_events` MUST have exactly one element and MUST equal the hub's head at
   the time of assignment.
2. Every event MUST carry a hub signature over `(room_id, li, event_id, chain[li])`
   from the server named in the current `m.room.hub`.

A room created at this version cannot fork. Legacy servers cannot join it, which
is the trade — hence rooms default to v11 and use this version only where every
peer is known to support it (federated MIMI/DMA interop deployments, or
single-operator multi-server fleets).

---

## 13. Trust model

### 13.1 What the hub can and cannot do

| Capability | Hub | Rationale |
|---|---|---|
| Decide event order | Yes | That is its function |
| Delay or drop an event | Yes | Detectable by the originator (no fan-out), not preventable |
| Forge an event from another server | **No** | Origin Ed25519 signature |
| Modify an event's content | **No** | Content hash covers content; reference hash covers the redacted event |
| Reorder committed history silently | **No** | Chain hash + hub signature per entry (§13.3) |
| Present different histories to different participants | **No, not undetectably** | §13.3 |
| Read E2EE content | **No** | Megolm/MLS; the hub is a transport |

This is strictly the same content-integrity guarantee as DAG Matrix. What is
given up is *liveness independence*: a partitioned participant cannot make
progress without the hub, whereas DAG Matrix would let it fork and merge later.
That is the deliberate trade — forking and merging is exactly the expensive thing.

### 13.2 Hub failover

If the hub is unreachable for `hub_failover_timeout` (default 60s), participants
may elect a new hub by sending an `m.room.hub` event at `epoch + 1`, authorized
by the ordinary power-level rules (default: PL 100 required, i.e. room admins).
Ties are broken by `(epoch, lexicographically smallest server_name)`. The new hub
must include `prev_epoch_final_li` and the chain commitment it is continuing
from; participants reject an epoch transition that would truncate entries they
already hold attestations for.

Because a partition can produce two candidate hubs, the epoch rule guarantees
that at most one branch survives: the branch whose `m.room.hub` event wins the
ordinary auth/state rules. Events serialized on the losing branch are re-proposed
by their originators, which is the same recovery a client already performs on a
failed send.

### 13.3 Equivocation detection

The chain hash makes the log a transparency log. If a hub signs two different
entries at the same `li`, or two entries whose chain hashes are inconsistent, any
participant holding both signatures possesses a self-contained, non-repudiable
proof of misbehavior.

Spindle additionally supports periodic `m.room.checkpoint` state events carrying
`chain[li]` and the current `StateRoot`. Because the state root is a hash of the
materialized state, a checkpoint lets a participant verify not only ordering but
the resulting *state* — something DAG Matrix cannot offer without recomputing
state resolution.

### 13.4 General hardening

Per-origin and per-user rate limits on every ingress; hard caps on event size
(65536 bytes per spec), state event count per room, and `/get_missing_events`
recursion depth; strict canonical JSON validation before hashing; signature
verification before any allocation proportional to attacker-controlled input;
media served with `Content-Security-Policy` and `Content-Disposition` per the
spec's media repository requirements, with an antivirus/scanner hook.

---

## 14. Storage engine

### 14.1 Shape

A pluggable `Store` trait over an ordered key-value engine. Default backend is an
LSM tree (RocksDB-class; `fjall` is the preferred pure-Rust option) with the
column families listed in §5.4. A PostgreSQL backend is provided for operators
who require it, at a documented performance cost.

Why not a relational schema as the primary: every hot operation is a sorted-range
scan or a point lookup on a synthetic key. There is no query in Spindle's hot
path that benefits from a planner, and the DAG-era schema's cost was largely in
joins that the linear model deletes outright.

### 14.2 Layout choices

- **`log` is keyed `(room_id, li)` big-endian**, so a room's events are physically
  contiguous and `/messages` is a sequential read.
- **`state_nodes` is content-addressed**, so it is write-once, never updated,
  compaction-friendly, and shared across every snapshot and every room.
- **Blobs are stored out-of-line** above a threshold (blob files / BlobDB) so the
  LSM's compaction moves keys, not message bodies.
- **`stream` is a small fixed-width index**, hot in cache, driving sync catch-up
  and federation catch-up.

### 14.3 Retention and compaction

Because the log is append-only and content-addressed, retention is a truncation:
dropping `li < X` for a room is a range delete plus a mark-and-sweep over
`state_nodes` reachable from retained roots. Media retention is independent.
There is no state-group compaction job, which removes an entire class of
operator toil.

---

## 15. Concurrency and process model

- **Rooms shard by `hash(room_id) % N`** across `N` executors, `N` = available
  cores. Each executor is a single-threaded async task owning its rooms'
  mutable state: head, state root, hot tail, subscriber list.
- **No locks on the hot path.** Cross-room work is message passing over bounded
  channels; back-pressure is explicit.
- **Per-user structures** (device inbox, account data, push rules) are
  append-only per-user streams, sharded by user, touched by fan-out via the same
  channel mechanism.
- **HTTP layer** is a work-stealing pool (hyper/axum on Tokio) that does parsing,
  auth, and routing, then hands off to the owning executor.
- **Horizontal scale-out** is a v2 concern (§21). The design admits it — rooms
  are independent and the shard key is the room — but v1 targets vertical scale
  on a single node, which is where the interesting comparison lies anyway: the
  point is to make one node do what currently requires a worker fleet.

Implementation language is **Rust**, on the `ruma` crate family for spec types:
`ruma-events`, `ruma-client-api`, `ruma-federation-api`, `ruma-common`,
`ruma-signatures`, and `ruma-state-res` (used *only* in the §9.2 case-3 path).
Unstable MSCs are gated behind Cargo features (`unstable-msc3995`,
`unstable-msc3820`, `unstable-msc4186`, `unstable-msc4244`, `unstable-msc4256`),
so nothing experimental compiles into a production binary by accident.

---

## 16. End-to-end encryption

### 16.1 v1: Megolm/Olm, unchanged

The server's role in Matrix E2EE is transport and key storage. Spindle
implements it as specified: device key upload/query, one-time key claim with
correct atomicity, `/sendToDevice` with per-device ordered inbox streams,
cross-signing, key backup (`/room_keys`), dehydrated devices, and
`m.device_list_update` over federation.

The to-device inbox is a per-device append-only stream with its own sync token
component, so a key-distribution burst in a large room does not stall the event
stream.

**No client change is required and no client behavior differs.** Megolm's O(N)
per-sender fan-out is a client-side cost; Spindle does not make it worse, and the
device-list and to-device paths are exactly where a server can make it better
(batched `/keys/query`, incremental `/keys/changes` from the device stream).

### 16.2 v2: MLS mode

RFC 9420 MLS requires a **total order on Commit messages** — two concurrent
Commits fork the TreeKEM epoch and desynchronize the group. This is the same
requirement Spindle's log already satisfies structurally.

The hub is a natural MLS Delivery Service: it already assigns a total order, and
`li` order *is* epoch order. MSC4244 (MLS over linearized rooms) fits with no
additional coordination mechanism; MSC4256 (MLS mode with deterministic epoch
progression under enterprise auth rules) is an alternative profile.

Spindle's v2 plan is to implement MLS behind `unstable-msc4244` once the MSC
stabilizes, with `m.room.mls_epoch` state carrying the epoch and the hub
rejecting Commits that do not build on the current epoch — a single trie lookup.
Key backup for MLS follows MSC4038.

This is deliberately *not* v1 work. The MSCs are unstable, no shipping client
implements them, and G1 (unmodified existing clients) forbids depending on them.

---

## 17. Operational surface

### 17.1 Configuration

Single TOML file, no external dependencies required for a default deployment
(embedded store, embedded media, no separate cache tier). Explicit knobs for
everything this document names a default for: `max_fork_window`,
`durability`, `hot_tail_len`, `presence.enabled`, `shard_count`,
`hub_failover_timeout`, retention.

### 17.2 Observability

Per-room and per-shard metrics: append latency histogram, fork-window
occurrences by case (the class-1/2/3 split in §9.2 is the single most important
health metric — case 3 should be near zero), state trie node cache hit rate,
federation queue depth per destination, sync subscriber count, watermark lag.
OpenTelemetry traces spanning client request → executor → commit → fan-out.

### 17.3 Media

Authenticated media (Matrix 1.11: `/_matrix/client/v1/media/*` and
`/_matrix/federation/v1/media/*`) is the primary path; legacy unauthenticated
`/_matrix/media/v3` endpoints are supported for older clients and freezable per
the spec's deprecation guidance. Content-addressed storage by SHA-256 with
pluggable backends (filesystem, S3-compatible). Thumbnailing on demand with a
cache; URL previews behind an allowlist and off by default.

### 17.4 Admin and moderation

Room and user admin API, server ACLs (`m.room.server_acl`) enforced at ingest
before signature verification where possible, spam-checker and event-hook
extension points, and report/quarantine flows. Because state is a trie root,
"what did this room look like at 14:03" is a first-class admin query rather than
a forensic exercise.

---

## 18. Performance model

### 18.1 Complexity comparison

| Operation | DAG homeserver | Spindle (class L/H/P) |
|---|---|---|
| Append local message | State group lookup, auth chain check, extremity update, multi-table txn | ≤6 trie lookups + hash + append |
| Append state event | Above, plus state group allocation/delta | Above, plus O(log n) path copy |
| Current state lookup | State group resolution | O(log n) in-memory |
| Historical state at event | Walk state group deltas | One index seek + O(log n) |
| `/messages` page | Topological ordering, possible backfill | Sequential range scan |
| `/sync` incremental (active client) | Stream queries per stream type | Ring-buffer slice, no storage read |
| Join room with S state events | Fetch + state res over S | Fetch + S folds, no state res |
| Federation catch-up after outage | Graph walk to find what to resend | Sequential scan of `stream` |
| Concurrent-send merge | State res v2 over room state | Case 1/2: none. Case 3: bounded window |

### 18.2 Latency budget, local send, class L

| Step | Expected order |
|---|---|
| HTTP parse, auth token, rate limit | ~µs |
| Channel hand-off to room executor | sub-µs |
| Auth (≤6 resident trie lookups) | hundreds of ns |
| Canonical JSON + SHA-256 (typical event) | ~1 µs |
| `apply()` if state event | ~1 µs |
| WAL append (amortized, group commit) | dominated by the ≤1 ms commit window |
| Fan-out to local subscribers | O(subscribers), ~ns each |

Ed25519 signing — the largest single CPU cost in the path — is off the critical
path in class L per §8.4, and remains on it in classes H/P/D.

### 18.3 Design targets

These are **targets to be validated by the benchmark harness in §19.4**, not
measurements. They exist so the design can be falsified.

| Metric | Target |
|---|---|
| Local send p50 / p99 (class L, `group` durability, warm) | < 2 ms / < 10 ms |
| Sustained local events/sec, single node, 16 cores | ≥ 20,000 |
| `/sync` incremental response, active client | < 5 ms p99 |
| `/messages` page of 50, warm room | < 3 ms p99 |
| Join a 10,000-member remote room (state materialization only, excluding network) | < 2 s |
| Resident memory per active room, 1k state events | < 2 MB |
| Case-3 fork resolutions as a fraction of federated events | < 0.1% |

### 18.4 Presence

Presence is the single largest source of federation traffic in the Matrix
network and delivers little. It is **off by default**, configurable, and when
enabled is rate-limited and coalesced per destination. This is a policy choice,
stated explicitly because it materially affects the numbers above and because
operators deserve to know it was deliberate.

---

## 19. Correctness strategy

The performance argument is worthless if the semantics drift. Four layers:

### 19.1 Conformance suites

**Complement** (the current Matrix conformance suite) and **sytest** run in CI
against every commit. The target is not "most tests pass" — it is a documented,
shrinking list of known failures with a reason for each. Any test that fails
because Spindle is faster-but-different is a bug in Spindle.

### 19.2 Differential property testing — the core safety net

The load-bearing claim of this design is §9.3. It is tested directly:

```
property linear_fold_matches_state_res:
    for arbitrary chain DAG D:
        assert fold_state(D) == ruma_state_res_v2(D)

property window_bounded_matches_full:
    for arbitrary forked DAG D with fork depth ≤ max_fork_window:
        assert window_state_res(D) == ruma_state_res_v2(D)

property linearization_is_valid_topological_order:
    for arbitrary DAG D:
        assert is_topological_order(li_order(D), D)
```

Generated with a DAG generator that produces adversarial shapes: deep forks,
wide fan-in, power-level races, ban/unban races, concurrent membership on the
same target, restricted-join edge cases. `ruma-state-res` is the reference
implementation on the right-hand side — the same code Conduit and others run in
production, used here as an oracle.

### 19.3 Client compatibility matrix

Automated end-to-end runs against Element Web, Element X (iOS/Android), Cinny,
Nheko, and Fluffychat for: login, room creation, invite/join, message send/edit/
redact, threads, E2EE with cross-signing and key backup, device verification,
back-pagination past a gap, spaces, and media upload/download. Element X
specifically exercises Simplified Sliding Sync, which is the newest surface and
the most likely to expose divergence.

### 19.4 Benchmark harness

Reproducible load generation with published methodology and hardware, covering:
single-room burst, many-room steady state, large-room join, back-pagination
sweep, federation catch-up after simulated partition, and a fork-injection
harness that forces §9's three cases at controlled rates. Results published as
ranges with the harness, so they can be reproduced or refuted.

### 19.5 Fuzzing

Continuous fuzzing of: canonical JSON serialization (must be byte-identical to
the reference for all inputs), signature verification, PDU parsing, and the HAMT
(differential against a `BTreeMap` model).

---

## 20. Migration and interoperability

### 20.1 Importing an existing homeserver

A one-shot importer for Synapse (PostgreSQL) and Dendrite:

1. Read events per room; topologically sort (once, offline).
2. Assign `li` in that order.
3. Fold state forward, writing `state_roots`.
4. Verify: recompute each event's reference hash and confirm the event ID;
   compare the final materialized state against the source server's current
   state and abort on any divergence.
5. Copy media, devices, keys, account data, push rules, receipts.

Step 4 is a hard gate. An import that changes any room's current state is a
failed import, not a warning.

Because event IDs, signatures, and room IDs are preserved, the imported server is
the *same* homeserver from the network's point of view; federation continues
uninterrupted.

### 20.2 Coexistence

Spindle can be introduced as an additional homeserver in an existing deployment's
federation, or behind the same domain via `.well-known` delegation during a
cutover. Rooms whose members are all migrated become class L automatically and
immediately stop paying DAG costs — no upgrade, no tombstone, no new room.

### 20.3 What existing peers experience

Nothing. That is the point of §11.1. A Synapse admin federating with a Spindle
server sees a homeserver that answers `/state_ids` quickly and never has 400
forward extremities.

---

## 21. Risks and open questions

| # | Risk | Assessment / mitigation |
|---|---|---|
| R1 | **Case-3 forks are more common than assumed.** If real federation produces frequent conflicting concurrent state changes, the exception path becomes the normal path. | Instrumented from day one (§17.2). The window cap bounds the worst case to correct-but-slow, never incorrect. If the assumption is wrong, the design degrades to a well-optimized DAG server — still a net improvement, but the headline claim would need retracting. |
| R2 | **Hub liveness.** A partitioned participant cannot send. DAG Matrix can. | Explicit trade (§13.1). Failover in 60 s (§13.2); clients already retry sends. Deployments that require partition-tolerant writes should keep class-D rooms. |
| R3 | **`max_fork_window` overflow.** A long partition with a busy legacy peer exceeds the cap. | Falls back to full spec state resolution over the affected range. Correct, slow, logged, alerted. |
| R4 | **Pre-rendered `client_json` doubles event storage and must be regenerated when spec rendering changes.** | Versioned; regeneration is a background range scan. Storage is the cheapest resource in the system. |
| R5 | **Spec drift.** Matrix moves; a from-scratch server must keep up. | Ruma tracks the spec and is used by multiple servers; Complement is the gate. Budget continuous spec-tracking work, not a one-time implementation. |
| R6 | **Client dependence on Synapse-specific behavior** not covered by the spec. | §19.3 finds it empirically; each instance is a Spindle bug. This is the historical failure mode for every alternative homeserver and should be assumed to cost real time. |
| R7 | **MSC3995 and MSC4244 are unstable and may change.** | Gated behind Cargo features and unstable prefixes; nothing in the v1 critical path depends on them (native rooms are plain v11). |
| R8 | **Single-node scale ceiling.** | v1 targets vertical scale. The shard-by-room design admits horizontal partitioning, but cross-node room migration and a distributed stream watermark are genuine v2 work, not a config flag. |
| R9 | **The equivalence theorem (§9.3) is wrong in some edge case.** | §19.2 tests it against the reference implementation continuously. A counterexample is a release blocker, not a bug report. |

---

## 22. Roadmap

| Milestone | Contents | Exit criterion |
|---|---|---|
| **M0 — Core** | Linear log, HAMT state, auth rules, room v11 event construction, storage engine | §19.2 properties pass; can create a room and append 1M events |
| **M1 — Client API, local only** | Login/register, createRoom, send, `/sync` v3, `/messages`, `/state`, receipts, account data, push rules | Element Web fully usable against a class-L-only server |
| **M2 — E2EE + modern sync** | Device/key APIs, to-device, cross-signing, key backup, Simplified Sliding Sync, authenticated media, threads, spaces | Element X fully usable; Complement E2EE and sync suites green |
| **M3 — Federation** | Full S2S API, class D, §9 fork handling, backfill, faster joins, EDUs | Complement federation suites green; interoperates with Synapse in a live room |
| **M4 — Linearized mode** | `m.room.hub`, proposal endpoint, epochs, failover, chain attestations, checkpoints | Two Spindle servers run a class-H room; hub failover under induced partition |
| **M5 — Production** | Import from Synapse, admin API, observability, benchmark harness with published results, appservices | A real deployment migrated with §20.1 step 4 passing |
| **M6 — MLS track** | MSC4244/MSC4256 behind feature flags, MSC4038 key backup | Interop with a reference MLS implementation |

---

## 23. Prior art and relationship to it

- **MSC3995 / `draft-ralston-mimi-linearized-matrix`** — the source of the
  linearized model, the hub topology, and dual representation. Spindle's
  contribution is applying it as an internal storage strategy for *all* rooms,
  including non-federated ones, rather than only as a federation profile for
  thin third-party implementations.
- **MSC3820 (room version 11)** and its component MSCs — the wire format Spindle
  defaults to.
- **conduwuit / Conduit** — demonstrated that a Rust homeserver on an embedded
  KV store is dramatically lighter than Synapse. Spindle takes the same
  substrate and additionally deletes the state-resolution hot path rather than
  optimizing it.
- **Synapse's state groups and faster joins** — the state of the art in making
  DAG state tractable, and the direct source of the cost model in §3. Faster
  joins are adopted wholesale (§11.5).
- **Certificate Transparency / verifiable logs** — the chain-hash and checkpoint
  construction in §5.3 and §13.3.
- **RFC 9420 (MLS)** — the cryptographic direction that *wants* a total order,
  which is the strongest external argument that linearization is the right
  long-term shape.
- **`ruma`** — the type layer, and `ruma-state-res` as both the fallback
  implementation and the correctness oracle.

---

## Appendix A — glossary

| Term | Meaning |
|---|---|
| `li` | Linear index; a room's total ordering key, `i64` |
| Room class | L (local), H (hub), P (participant), D (DAG) — §4 |
| Fork window | `(A, head]`, the range between an incoming event's newest ancestor and our head — §9.1 |
| HAMT | Hash-array-mapped trie; the persistent state structure — §6 |
| `StateRoot` | 32-byte content hash identifying a materialized room state |
| Chain hash | `SHA-256(chain[li-1] || event_id[li])`; makes the log verifiable — §5.3 |
| Epoch | Monotonic hub generation, incremented on hub change — §12.1 |
| Hot tail | In-memory ring of recent pre-rendered events per room — §10.3 |
| Watermark | Highest contiguous committed `stream_id`; the sync visibility boundary — §10.2 |
