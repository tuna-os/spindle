# Contributing

Spindle is a Matrix homeserver whose rooms are append-only logs with
materialized state, written in Rust. The README says what it is and where
it stands; ROADMAP.md says what is next; SPEC.md is the design. This page
is how to work on it.

## Build and test

`rust-toolchain.toml` pins the compiler and rustup fetches it on its own.
Storage is embedded, so there is nothing to provision.

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

Those three are the pull-request gate, with a few checks that keep
generated and hand-copied things honest:

```sh
python3 scripts/coverage-dashboard.py --check   # docs/dashboard.md matches the router
python3 scripts/readme-numbers.py --check       # the README's headline numbers are the gated ones
python3 scripts/actions-pinned.py               # every action is pinned to a commit
```

The slower suites run on pushes to main and nightly, not on pull requests:
the Complement ratchet (`scripts/complement.sh`, needs Docker), Element
Web and Element Call end to end, the full-mesh peer-to-peer call, the
Neutrino mesh seam, a real bridge through the appservice API, release-mode
performance budgets, and weekly fuzzing and coverage. `.github/workflows/`
is the list; each job's comment says why it runs where it runs.

## What a change is expected to carry

- **A test that would have failed before it.** For a bug, the test
  reproduces the bug; for a feature, the test is the claim. Performance
  work arrives with a counting assertion (allocations, bytes, comparisons)
  rather than a timing, because timings do not fail deterministically.
- **No stubs.** An endpoint that is routed works; one that is not answers
  404. `tests/surface.rs` enforces that `/versions` advertises only what
  is built. A placeholder that returns `{}` is worse than a 404, because
  a client cannot tell it from success.
- **Honest numbers.** The dashboard, the README's counts and the
  Complement allowlist are generated or gated. A claim about performance
  links the benchmark that made it; a retracted claim stays retracted in
  the text.
- **Comments that say why.** The code says what; a comment earns its place
  by recording the reason, the alternative that was rejected, or the
  failure that motivated it.

## Finding something to do

Issues labelled `good first issue` are self-contained with a design in the
issue; `help wanted` marks work that needs something this repository does
not have (a client, a bridge, a second homeserver). The milestone table in
the README is the roadmap in prose, and ROADMAP.md has the entry points
for each track.

## Pull requests

One change per pull request, with the commit message saying what changed
and why in plain prose. Pushes to your branch re-run the gate; the
Complement ratchet runs its protected subset on pull requests and the
whole suite on main. A red check is yours to read before a reviewer does.

## Security

Not an issue. `SECURITY.md` has the route.
