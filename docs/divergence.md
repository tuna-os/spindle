# The divergence seam

Where Spindle's implementation should differ from the projects it builds on —
and, more importantly, where it should not.

Spindle sits downstream of four things: the Matrix specification, [ruma],
two sibling Rust homeservers ([tuwunel] and [continuwuity]), and
[Complement]. Every line we write is either inherited from one of them or
deliberately ours. Confusing the two is the main way this project could fail:
diverge where we should inherit and we acquire a permanent spec-tracking
liability; inherit where we should diverge and we have rebuilt conduwuit with
extra steps and no reason to exist.

This document draws that line. It complements [ADR 0001] (linear storage,
DAG overlay) and [ADR 0002] (the ruma-free core), which decided two specific
pieces of it; this is the whole map, and it is expected to change per
milestone.

[ruma]: https://github.com/ruma/ruma
[tuwunel]: https://github.com/matrix-construct/tuwunel
[continuwuity]: https://forgejo.ellis.link/continuwuation/continuwuity
[Complement]: https://github.com/matrix-org/complement
[ADR 0001]: architecture-decisions/0001-linear-storage-dag-overlay.md
[ADR 0002]: architecture-decisions/0002-ruma-dependency-policy.md

## 1. The one-line answer

**We diverge below the wire and nowhere above it.**

Everything a client or a peer homeserver can observe — event JSON, room
versions, auth rules, canonical JSON, signatures, CS and SS endpoint shapes —
is the Matrix specification's, taken from ruma, and must be
byte-for-byte what Synapse would produce. Everything on our side of the
socket — how events are ordered, how state is stored, how state is reached,
what the disk format is — is ours to redesign, and that is where every
performance claim in [SPEC](../SPEC.md) comes from.

A useful test for any proposed change: *could a peer detect it?* If yes, it is
not a divergence, it is a bug or a spec proposal. If no, it is fair game.

## 2. Posture toward each upstream

| Upstream | What we take | What we never take | Fork? |
|---|---|---|---|
| **Matrix spec** | All of it, as the compatibility contract | — | Never. Extensions go through the MSC process. |
| **ruma** | Event schemas, canonical JSON, redaction, reference hashes, Ed25519, room-version rules, `ruma-state-res` as oracle and fallback | Its data structures inside our core (ADR 0002) | No. Tuwunel maintains one; we should not inherit that cost. |
| **tuwunel / continuwuity** | Ideas, and their hard-won operational knowledge (see §5) | Their code, their storage design, their ingest architecture | N/A — not dependencies. |
| **Complement** | The suite, unmodified, plus per-image federation config | — | No, unless we hit a concrete blocker with no upstream path. |

The asymmetry is deliberate. Ruma is a *library* and we depend on it. Tuwunel
and continuwuity are *peers* — we read them to learn what Matrix actually
demands in production, and we deliberately do not converge with them on the
parts we exist to do differently.

## 3. The seam, layer by layer

Reading top to bottom: the further down, the more of it is ours.

| Layer | Source | Ours? |
|---|---|---|
| CS API endpoint shapes, error codes | ruma-client-api (M1, #7/#10/#11) | No |
| SS API endpoint shapes | ruma-federation-api (M3, #14/#15) | No |
| Event JSON, room version rules, redaction | ruma | No |
| Canonical JSON, reference hash, Ed25519 signing | ruma | No |
| Auth rules (the predicate) | `ruma`'s `auth_check` — same rules the siblings call | No |
| **Where the state fed to `auth_check` comes from** | — | **Yes** |
| **Event ordering and pagination** | — | **Yes** — the linear index |
| **State representation** | — | **Yes** — content-addressed HAMT |
| **Federation-fork handling** | ruma-state-res as fallback only | **Yes** — the bounded window |
| **On-disk format** | — | **Yes** — `spindle-store` |
| **Integrity/audit construction** | — | **Yes** — the log chain |

The single most important row is the sixth. Both siblings call ruma's
`auth_check` on the local send path (`service/rooms/timeline/create.rs` in
each), and so do we — `server/src/authorize.rs`, called from `rooms.rs`
before anything is appended. The *rules* are not a divergence and must not
become one; that module deliberately contains no authorization logic at all,
only the conversion into the shape `ruma-state-res` reads. What differs is
that the siblings compute or look up the state to check against, and we index
into a snapshot already hanging off the previous log entry. Same predicate,
different cost to reach its inputs. That is the project's thesis in one row.

## 4. What is genuinely ours today

The load-bearing pieces are in `spindle-core` and `spindle-store`; since M1
landed, `spindle-server` carries divergences of its own (§4.6–4.8). All of it
is invisible to peers. Nothing here changes a byte on the wire.

### 4.1 The linear index (`core/src/log.rs`, SPEC §5.1)

Every accepted event gets one monotonic `i64`. Forward from 1 for live events,
backward from 0 for backfill, so history can be prepended without renumbering.
This is the storage, pagination and client-timeline order. The signed
`prev_events` are retained verbatim and remain the federation truth; `li` is
never on the wire.

**Siblings:** order by `(depth, event_id)` derived from the DAG at read time.

### 4.2 The materialized state trie (`core/src/state.rs`, SPEC §6)

A 32-way bitmap-indexed HAMT, keyed by `(type, state_key)`, with every node
addressed by the BLAKE3 hash of its contents. Path copying gives a persistent
snapshot per event for a bounded number of new nodes, independent of state
size — asserted, not assumed, by `tests/state_sharing.rs`.

**Siblings:** a `state_compressor` layering diffs over `shortstatehash`
chunks, walked at read time to reconstruct a state map.

Note that [`docs/benchmarks.md`](benchmarks.md) found the `im` crate *faster*
than our HAMT at small and medium update counts. The hand-rolled trie is
justified by content addressing — which is what makes `delta_nodes`,
persistence and corruption detection possible — not by speed. A divergence
that survives on architectural grounds after losing on its original grounds is
one to keep honest, not one to quietly restate.

### 4.3 The bounded fork window (`core/src/log.rs`, SPEC §9)

Full state resolution v2 is O(conflicted state × auth chain) and the siblings
invoke it whenever an incoming event's state differs
(`event_handler/resolve_state.rs`, `state_at_incoming.rs` in continuwuity).
We reverse-BFS the ancestry to the nearest common ancestor with a hard cap on
*work done*, not merely on the answer returned (#33), and take the cheapest of
three cases; only a genuine same-slot conflict reaches `ruma-state-res`.

This is the divergence with the most correctness risk attached, which is why
§9.3's equivalence claim is tested differentially against the reference
resolver rather than argued (#34, SPEC §19.2).

### 4.4 The log chain (`core/src/log.rs`, SPEC §5.3)

`chain[li] = BLAKE3(DOMAIN || chain[li-1] || event_id[li])` — a transparency-log
construction over our own ordering, so a server's claimed order can be audited
rather than trusted. Nothing in Matrix requires this; it exists because
linearization concentrates ordering authority (SPEC §13.3), and concentrated
authority should be checkable.

### 4.5 Key encoding and store codec (`core/src/keys.rs`, `store/src/codec.rs`)

Order-preserving `i64` encoding (sign-bit flip, so byte order matches numeric
order across zero), keyspace-tagged and room-prefixed; a hand-written versioned
record format over Fjall. Purely internal, versioned from day one so the format
can move without a flag day.

### 4.6 Read paths as index arithmetic (`server/src/rooms.rs`)

The M1 endpoints lean on the linear index instead of maintaining derived
tables. The unread count is `head − max(receipt, own join)` filtered over a
contiguous range; `/context` is a window either side of one `li` plus the
event's own state snapshot; `/relations` is a prefix scan whose key *ends* in
`li`, so results arrive in timeline order with nothing sorting them.

That last one is a recorded departure from our own SPEC §7, whose key shape
`(room, target, rel_type, li)` cannot serve the type-less `/relations` arity
in timeline order — the length-prefixed `rel_type` sorts by *length* before
bytes. The type moved into the value; the narrowed arities filter on read.

**Siblings:** Synapse maintains `event_push_actions` (written per event, per
user, summarised by a background job) for unread counts, and orders relations
with a stream-ordering sort at read. Ours are computed at read from the index;
the trade is write-time work and storage against a read cost proportional to
how far behind the reader is — cheap here because "which events follow this
one" is subtraction, not a graph walk.

### 4.7 Media: content-addressed blobs, opaque IDs (`server/src/media.rs`)

Blobs are stored under their BLAKE3 hash — upload deduplication for free —
but addressed by a random 128-bit ID, because a hash-addressed URL is an
existence oracle. Content addressing is a storage decision that must not
become an addressing one. The unauthenticated legacy download surface is
absent by decision, not omission.

**Siblings:** Synapse stores one file per upload under a random ID (no
dedup); conduwuit/tuwunel key media by ID in the database. Neither content
addresses; none of the three serves unauthenticated media any more, so there
we agree.

### 4.8 Ephemeral state that is never an event (`server/src/typing.rs`)

Typing lives in memory, expires by being read (no sweeper), and wakes the
`/sync` long-poll only when the *set of typists changes* — a refresh of an
existing notice wakes nobody, which is what keeps a room of phones from
polling in lockstep while someone types. A restart forgets it, correctly.

**Siblings:** Synapse tracks typing in a replicated stream with serial
numbers, because workers must share it. We have one process; the divergence
is having less machinery, and it holds only until scale-out (#24) reopens it.

## 5. What we take from the siblings without taking their code

Tuwunel and continuwuity have run real Matrix traffic; we have not. Their
operational findings are worth more to us than their architecture, and copying
them costs nothing:

- **Ruma by git revision, not crates.io** — all three serious Rust Matrix
  projects do it. We will too, when M1 needs endpoint types the release does
  not expose (ADR 0002, decision 2).
- **Interop as a separate report-only board**, diffed against the homogeneous
  baseline, run in both directions — tuwunel's approach, adopted wholesale in
  [`conformance-testing.md`](conformance-testing.md) §5.1.
- **Lowercasing the `COMPLEMENT_BASE_IMAGE_*` suffix**, because upstream's
  documented uppercase form is silently ignored and leaves the run
  homogeneous — a bug we only found because tuwunel's runner works around it.
- **MatrixRTC groundwork** — conduwuit-lineage work on MSC4140 delayed events
  is the closest prior art to #36, and worth reading before writing ours.

Reading their code to learn what the spec really demands is not divergence
debt. Vendoring it would be.

## 6. Where we deliberately do not diverge

Stated explicitly, because each is a place where a plausible-sounding
optimization would break compatibility:

- **Event format and hashing.** Not "compatible", identical. Anything else
  fails signature verification at every peer.
- **Auth rules.** The predicate is the spec's. We change when it is cheap to
  evaluate, never what it decides.
- **Room versions.** We speak the versions the ecosystem speaks; we do not
  invent one to make our life easier. (The v11-vs-v12 default is still open —
  SPEC §11.6 — but that is a choice *between* real versions.)
- **CS/SS endpoint semantics.** Sync tokens are opaque to clients, which is
  exactly why §10.2 is free to put a linear stream position inside one. Opaque
  is the seam; the endpoint contract is not.
- **Megolm/Olm.** E2EE stays unchanged (SPEC §16.1). MLS is #23 and explicitly
  gated behind shipping Megolm compatibility first.

## 7. Divergence that has not happened yet

Worth being blunt, because the project's name invites the opposite assumption:

**There is no MSC3995 protocol code in this repository.** What is implemented
is linear *storage*, which peers cannot observe — Spindle emits ordinary room
v11 PDUs and federates as a normal homeserver. Linearized Matrix hub mode is
#22, milestone M6, behind a feature flag, and it is deliberately last.

The performance claims come from the implementation, not the protocol. That
ordering is the plan, not an accident of what got built first: the storage
divergence is testable against Synapse today, whereas the protocol divergence
needs a peer that speaks it, and today there isn't one.

Deferred, in order: MSC3995 hub mode (#22, M6), MLS (#23, M6), horizontal
scale-out (#24).

## 8. Rules for adding a divergence

Before writing something the upstreams already do:

1. **Can a peer or client detect it?** If yes, stop — it is a spec change, and
   spec changes go through the MSC process, not through us.
2. **Is it in the core?** If yes, it must not use ruma types (ADR 0002).
   Otherwise our benchmarks against ruma become circular and our core stops
   being testable in isolation.
3. **What is the oracle?** Every divergence needs something to be differentially
   tested against — the reference resolver, a Synapse peer, or a naive
   implementation of the same thing. A divergence with no oracle is a guess.
4. **What is the exit?** Name the condition under which the divergence stops
   being worth it, as §4.2 does for the HAMT. A divergence nobody will ever
   reconsider is a divergence nobody is measuring.

And the inverse: before inheriting something, check it is not one of the four
rows in §3 that we exist to do differently. Reaching for `state_res::resolve`
on an ingest path is the specific mistake to watch for — it is the correct call
in both sibling projects and the wrong one here, everywhere except §9's case 3.
