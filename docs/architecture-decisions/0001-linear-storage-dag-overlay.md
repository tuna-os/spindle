# ADR 0001: Linear storage with a bounded federation-DAG overlay

**Status:** accepted for M0 validation

## Context

Spindle assigns every accepted room event one monotonic linear index. Matrix
federation events nevertheless carry signed `prev_events`, and an incoming event
may name a stale predecessor. Spindle cannot rewrite that field without
invalidating the event.

The original design treated the stale event as the new head and allowed the next
locally authored event to reference only it. That does not merge the Matrix DAG:
the former head remains a forward extremity and can have different state.

## Decision

Storage order and federation ancestry are separate:

- `li` is the stable storage, pagination, and client timeline order.
- Every entry retains its real signed `prev_events`.
- L/H/P rooms have exactly one forward extremity.
- A class-D stale event may temporarily create several forward extremities.
- The next local event references every current extremity (up to Matrix's limit
  of 20), collapsing the DAG back to one head.
- If the parent states are identical or differ only on disjoint state slots,
  their materialized snapshots merge without full state resolution.
- Competing values for one state slot must use the room-version-specific Matrix
  state resolver. The M0 core returns `NeedsStateResolution` until the
  `ruma-state-res` adapter lands.

The bounded fork window must be defined by ancestry from an actual common
ancestor, not merely by nearby linear indices. Linear position is not proof of
DAG ancestry.

## Consequences

The common path remains a one-parent linear append. Class D retains minimal
forward-extremity and parent-state metadata, but that cost is isolated from
fork-free rooms. The design no longer claims that all Spindle-authored class-D
events have exactly one predecessor; it claims that the internal storage order
is always linear and the federation overlay is normally a chain.

