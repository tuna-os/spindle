# Contributing

Spindle is a Matrix homeserver whose rooms are append-only logs with
materialized state, written in Rust. The README says what it is and where
it stands; ROADMAP.md says what is next; SPEC.md is the design. This page
is how to work on it.

## Build and test

`rust-toolchain.toml` pins the compiler and rustup fetches it on its own.
Spindle embeds its storage, so there is nothing to provision.

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

`just lint` and `just test` run the same commands. `just --list` names the
rest: the generated pages (`just docs`) and a competitive benchmark run from a
bare checkout. That run is `just bench <group>`, or its three steps
`bench-field`, `bench-build`, `bench-sitting`. docs/benchmarks.md says what
each step does and lists the pins for the field.

Those three are the pull-request gate, with a few checks that keep
generated and hand-copied things honest:

```sh
python3 scripts/coverage-dashboard.py --check   # docs/dashboard.md matches the router
python3 scripts/readme-numbers.py --check       # the README's headline numbers are the gated ones
python3 scripts/actions-pinned.py               # every action is pinned to a commit
```

The slower suites run on pushes to main and nightly, not on pull requests.
They are the Complement ratchet (`scripts/complement.sh`, needs Docker), and
Element Web and Element Call end to end. They also include the full-mesh
peer-to-peer call, the Neutrino mesh seam and a real bridge through the
appservice API. Release-mode performance budgets run there too, with weekly
fuzz tests and coverage. `.github/workflows/`
is the list; each job's comment says why it runs where it runs.

## What a change is expected to carry

- **A test that would have failed before it.** For a bug, the test
  reproduces the bug. For a feature, the test is the claim. Performance
  work arrives with an assertion that counts something: allocations, bytes
  or comparisons. It does not use a timing, because timings do not fail
  deterministically.
- **No stubs.** If the router serves an endpoint, the endpoint works.
  Otherwise it answers 404. `tests/surface.rs` enforces that `/versions` advertises only what
  is built. A placeholder that returns `{}` is worse than a 404, because
  a client cannot tell it from success.
- **Honest numbers.** A generator or a CI gate stands behind the
  dashboard, the README's counts and the Complement allowlist. A claim about performance
  links the benchmark that made it; a retracted claim stays retracted in
  the text.
- **Comments that say why.** The code says what. A comment earns its
  place when it records the reason, the alternative we rejected, or the
  failure that motivated it.

## Adding an endpoint or an MSC

Both have a generated page CI holds to the code. A new route must
appear in `docs/dashboard.md` and leave `docs/spec-gaps.md` (run `just
regen`). A new MSC surface needs an entry in `contrib/msc/ledger.toml`.
The entry names the test that proves it, and the flag it advertises. The whole
procedure, with the spec-release and pin-bump cases, is in
[docs/maintenance.md](docs/maintenance.md).

## Finding something to do

Issues labelled `good first issue` are self-contained with a design in the
issue. The `help wanted` label marks work that needs something this
repository does not have (a client, a bridge, a second homeserver). The milestone table in
the README is the roadmap in prose, and ROADMAP.md has the entry points
for each track.

## Pull requests

One change per pull request, with the commit message saying what changed
and why in plain prose. Pushes to your branch re-run the gate; the
Complement ratchet runs its protected subset on pull requests and the
whole suite on main. A red check is yours to read before a reviewer does.

## Security

Not an issue. `SECURITY.md` has the route.

<!-- hive-contribute-plea: donated-compute appeal, keep in sync across repos -->
## Contribute compute — no code needed

No time to write code? You can still push this project's backlog forward. A TunaOS AI-agent hive works on this repository. Lend the hive your AI subscription or API tokens, and your machine runs contributor tasks from this project's backlog.

- 🪸 [Contribute compute to the reef hive](https://reef.tunaos.org/contribute)
