# Licensing

Spindle is dual-licensed under **[MIT](LICENSE-MIT) OR
[Apache-2.0](LICENSE-APACHE)**, at your option. Contributions are accepted
under the same terms.

This is the Rust ecosystem's convention rather than a novel choice: 205 of the
336 crates in Spindle's own dependency graph carry exactly this pair. Apache-2.0
supplies an explicit patent grant, which matters for an implementation of a
protocol; MIT is the simplest thing a downstream can comply with; and which to
take is the licensee's decision, not ours.

## Why not AGPL

Worth recording, because the obvious reasoning points the other way: Synapse —
the reference homeserver, and the one Spindle imports from — is AGPL-3.0, and
Element relicensed it *to* AGPL deliberately.

The concrete argument for matching it was that #20's importer wanted Synapse's
schema, and vendoring AGPL SQL into a permissively-licensed repository is not
something to do by inference. That turned out to be an argument for a different
design rather than for a different license: `scripts/synapse-fixture.py` reads
the schema from a checkout the caller points at, which is better regardless —
it keeps the fixture honest about tracking upstream instead of freezing a copy
that silently ages. Nothing is vendored, so nothing needs AGPL to be vendored
legally.

With that gone, AGPL bought nothing Spindle needed, and cost the thing a
homeserver most wants: being easy to embed, fork, package and borrow from.

## What was checked before choosing

Picking a license for code you did not write all of is a way to be wrong
quietly, so:

- **No copyleft dependency forces the choice.** Of 336 crates, one
  (`self_cell`) is `Apache-2.0 OR GPL-2.0-only` — dual, so Apache-2.0 applies.
  Four (`im`, `bitmaps`, `sized-chunks`, `as_variant`) are MPL-2.0, which is
  *file-level* copyleft: it obliges sharing modifications to those files, and
  §3.3 expressly permits distributing the larger work under other terms. We do
  not modify them.
- **No third-party source is vendored.** No `vendor/`, `third_party/` or
  equivalent tree exists.
- **No sibling homeserver's code was taken.** `docs/divergence.md` §5 draws
  this line explicitly and in advance: *"Reading their code to learn what the
  spec really demands is not divergence debt. Vendoring it would be."* What was
  taken from Tuwunel and continuwuity is operational findings — a CI workaround,
  a testing posture — not expression.
- **The copyright is effectively unshared.** One human author, plus commits
  made under their direction and two mechanical dependency bumps. Applying a
  first license is clean; there is no prior grant to change and no contributor
  whose terms are being altered underneath them.

Dependencies keep their own licenses. `cargo metadata` is the authority on
what they are, and the MPL-2.0 crates above are the only ones carrying an
obligation beyond attribution.

## The copyright line

`LICENSE-MIT` says **The Spindle Authors** rather than naming an individual or
`tuna-os`. That is accurate today and stays accurate as contributors arrive; if
the owner wants their own name or the organisation's, it is a one-line change
in that file.
