# ADR 0002: Ruma dependency policy and the ruma-free core

**Status:** proposed

## Context

Spindle depends on [`ruma`](https://github.com/ruma/ruma) for Matrix's fiddly,
spec-tracking parts: canonical JSON, event schemas, room-version rules,
redaction algorithms, reference hashing and Ed25519 signing.

Today that dependency is `ruma = "0.16"` from crates.io, and the surface is
tiny — ruma appears in exactly two files, `pdu.rs` and its test.

Two questions have come up: whether to depend on ruma at all, and whether the
current pinning is right. Both get materially more expensive to revisit once M1
starts pulling in `ruma-client-api` and M3 pulls in `ruma-federation-api`.

### What the rest of the ecosystem does

Every serious Rust Matrix project depends on ruma by **git revision**, not from
crates.io:

| Project | ruma source |
|---|---|
| Tuwunel | `matrix-construct/ruma` — their own fork, rev-pinned |
| Continuwuity | `ruma/ruma` upstream, rev-pinned |
| matrix-rust-sdk | `ruma/ruma` upstream, rev-pinned |
| Spindle | `ruma = "0.16"`, crates.io |

Three independent teams — including Element's own SDK — all bypass the published
releases. That is strong evidence the release cadence lags what a Matrix
implementation actually needs. We have not felt it because we use almost none of
ruma yet.

## Decision

**1. Keep ruma.** Reimplementing event schemas, room-version rules, redaction
algorithms, canonical JSON and signatures would be a permanent spec-tracking
liability — precisely the risk SPEC §21/R5 names. It would also cost us
`ruma-state-res`, which is both our correctness oracle (SPEC §19.2, #34) and the
fallback resolver for the §9 case-3 path. A from-scratch implementation would
have to be verified against something, and ruma is that something.

**2. Move to an upstream git revision pin when M1 requires it,** not before.
`ruma = "0.16"` is adequate while our surface is `pdu.rs`. The moment we need
endpoint types the release does not expose, pin a revision of `ruma/ruma` and
record why in the commit. Pin a revision, never a branch: a floating dependency
makes builds unreproducible and turns an upstream push into a surprise CI
failure.

**3. Do not fork ruma.** Tuwunel maintains one; we should not inherit that cost
without being forced. The same reasoning already applied to their Complement
fork in `docs/conformance-testing.md` — a fork is a standing maintenance
liability, justified only by a concrete blocker with no upstream path. If we
ever need one, it is an ADR of its own, and the first move is an upstream PR.

**4. Keep the core ruma-free.** `log.rs` and `state.rs` contain no ruma today —
the linear log and the state trie are dependency-free. That boundary holds:

- `spindle-core`'s log and state modules depend on nothing but `std` and the
  hash function.
- Matrix's spec-defined encoding, hashing, signing and version rules live behind
  `pdu.rs` and whatever later replaces it.
- Higher layers may use ruma types freely; they must not leak into the log or
  the state trie.

## Consequences

The parts that are genuinely ours — the linear index, the persistent state
trie, the bounded fork search — stay independently testable, independently
benchmarkable, and unaffected by a ruma version bump. #33's benchmark and #34's
comparative harness both depend on that: comparing our state handling against
`ruma-state-res` is only meaningful if our side is not itself built on ruma.

It also bounds the blast radius of the risk this ADR accepts. A ruma breaking
change is an M1-and-above problem, never an M0 one. #27 already spent three CI
runs on a ruma-driven MSRV bump to 1.89; that is the shape of cost we are
choosing to keep paying, and keeping it out of the core is what makes it
tolerable.

The cost of the boundary is some duplication: `EventId` and `StateKey` are ours
rather than ruma's, and conversions are needed at the seam. That is deliberate.
The alternative — ruma types threaded through the log — would make the core
untestable in isolation and the benchmarks circular.
