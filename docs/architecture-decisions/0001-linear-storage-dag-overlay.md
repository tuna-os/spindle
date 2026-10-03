# ADR 0001: Linear storage with a bounded federation-DAG overlay

**Status:** accepted for M0 validation

## Context

Spindle gives an index to each room event that it accepts. The index is
monotonic and linear, and each event gets exactly one.
But each Matrix event from federation carries signed `prev_events`, and an
inbound event may name a stale predecessor. If Spindle rewrites that field, the
event becomes invalid.

The original design treated the stale event as the new head and allowed the next
locally authored event to reference only it. That does not merge the Matrix DAG:
the former head remains a forward extremity and can have different state.

## Decision

Storage order and federation ancestry are separate:

- `li` is the stable storage, pagination, and client timeline order.
- Every entry retains its real signed `prev_events`.
- L/H/P rooms have exactly one extremity at the forward edge.
- A class-D stale event may temporarily create several forward extremities.
- The next local event references every current extremity (up to Matrix's limit
  of 20). This collapses the DAG back to one head.
- The parent states can be identical, or differ only on disjoint state slots.
  Then their materialized snapshots merge without full state resolution.
- Two or more values that compete for one state slot must use the Matrix
  state resolver for the room version. The M0 core returns `NeedsStateResolution` until the
  `ruma-state-res` adapter lands.

Ancestry from an actual common ancestor must define the bounded fork window.
It must not come only from nearby linear indices. Linear position is not proof of
DAG ancestry.

## Consequences

The common path remains a one-parent linear append. For class D, Spindle keeps
minimal metadata about forward extremities and parent states. That cost does
not touch fork-free rooms. The design no longer claims that all Spindle-authored
class-D events have exactly one predecessor. It claims that the internal
storage order is always linear, and the federation overlay is normally a chain.

