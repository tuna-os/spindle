# Licensing

Spindle is dual-licensed under **[MIT](LICENSE-MIT) OR
[Apache-2.0](LICENSE-APACHE)**, at your option. Contributions are accepted
under the same terms.

This is the Rust ecosystem's convention rather than a novel choice: 205 of the
Almost every crate in Spindle's own dependency graph carries exactly this
pair; `deny.toml` records the full allowed set and CI enforces it. Apache-2.0
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

- **No copyleft dependency forces the choice.** One (`self_cell`) is
  `Apache-2.0 OR GPL-2.0-only` — dual, so Apache-2.0 applies. Three
  (`imbl`, `bitmaps`, `as_variant`) are MPL-2.0, which is *file-level*
  copyleft: it obliges sharing modifications to those files, and §3.3
  expressly permits distributing the larger work under other terms. We do
  not modify them. Two of the three (`imbl`, `bitmaps`) are dev-only, so
  they are not in a shipped binary at all.

  This list is no longer maintained by hand. `deny.toml` holds the allowed
  set and `cargo deny check licenses` runs in CI, so a dependency that
  arrives under a licence nobody has argued for fails the build rather than
  waiting for somebody to re-read this file. #266 is why: the count below
  was checked once, by hand, and nothing re-checked it — it read 336 while
  the graph had moved to 498.
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

`LICENSE-MIT` says **`Copyright (c) 2026 The Spindle Authors`**. Every part of
that line is a decision, and this section exists so it stops being re-opened.

### Why not a person's name, or `tuna-os`

Because neither would be true. Spindle has no CLA and no copyright assignment,
and wants neither — so every contributor keeps the copyright in what they
wrote. A notice naming one human, or the organisation, would assert that party
holds copyright in contributions they do not hold. The collective name is the
only one of the three that is accurate the moment a second person commits.

It is also the ecosystem's convention rather than an invention: Rust ships *The
Rust Project Developers*, Go ships *The Go Authors*. This document already
leans on the Rust convention one section up, for the dual license itself; this
is the same convention, applied consistently.

The practical argument is smaller but points the same way: a collective holder
never needs editing, and a notice that needs editing is a notice that goes
stale.

If the project ever does adopt a CLA, that is the moment to revisit this — and
the CLA, not the notice, would be the thing doing the work.

### Why 2026, and why not a range

2026 is the year of first publication: the first commit is dated 2026-08-26.

Not `2026-2027`, and not a year bumped on each release. Under Berne the
copyright exists whether or not a notice does, so the year in the notice is
informational — a maintained range buys nothing, and a stale one costs nothing.
What a range does reliably produce is a diff every January that no one can
review on its merits.

### Why `LICENSE-APACHE` still ends in `[yyyy] [name of copyright owner]`

That block is not an unfilled field in our notice. It is the appendix Apache
addresses to licensees — *"How to apply the Apache License to your work"* —
and its brackets are instructions to a reader applying the license to something
else. Filling them in would mean editing the text of a standard license, which
is the one thing not to do to one: a modified Apache-2.0 is no longer
Apache-2.0, and tooling that identifies licenses by hashing their text stops
recognising it.

So `LICENSE-APACHE` keeps the appendix. The file is the copy the Rust project
ships, which differs from apache.org's only in whitespace — a leading blank
line and a uniform three-space dedent — and not by one word. (Checked, because
"it's the standard text" is exactly the kind of claim that is repeated rather
than verified: `diff -w` against
`https://www.apache.org/licenses/LICENSE-2.0.txt` reports the blank line and
nothing else.)

The copyright statement lives in `LICENSE-MIT` and in the per-crate `license`
field, which is where anything reads it from.
