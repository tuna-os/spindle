# Contributing

Spindle is a Matrix homeserver whose rooms are append-only logs with
materialized state, written in Rust. The README says what it is and where
it stands; ROADMAP.md says what is next; SPEC.md is the design. This page
is how to work on it.

<!-- hive-contribute-plea: donated-compute appeal, keep in sync across repos -->
## Contribute compute — no code needed

**[Donate time with your AI CLI](https://hub.tunaos.org/#contribute).**

Your machine runs one task at a time using your signed-in AI coding CLI.
The relay alternates between eligible **School** (OS) and **Reef** (apps)
hives after each task. If one hive has no work, the other can continue.

The guide covers prerequisites, verified `just` setup, credentials, provider
costs, and how to stop with Ctrl+C. Your subscription quota or API charges apply.
Never post account credentials or API keys in issues or pull requests.

## Build and test

`rust-toolchain.toml` pins the compiler and rustup fetches it on its own.
Storage is embedded, so there is nothing to provision.

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

`just lint` and `just test` run the same commands, and `just --list` names
the rest: the generated pages (`just docs`) and the competitive benchmark
sitting from a bare checkout (`just bench <group>`, or its three steps
`bench-field`, `bench-build`, `bench-sitting`; docs/benchmarks.md says what
each does and what the field is pinned to).

Those three are the pull-request gate, with a few checks that keep
generated and hand-copied things honest:

```sh
python3 scripts/coverage-dashboard.py --check   # docs/dashboard.md matches the router
python3 scripts/readme-numbers.py --check       # the README's headline numbers are the gated ones
python3 scripts/actions-pinned.py               # actions and images are pinned; workflows grant the least
```

Pull requests also run the Complement protected subset
(`scripts/complement.sh`, needs Docker) with the state-resolution interop
rooms. They run Element Web end to end, synadm, the protocol fixtures and
the release-mode performance budgets too. A change to prose only
(Markdown, `docs/`) skips them.

Pushes to main run the whole Complement suite, the bridges and the
full-mesh peer-to-peer call. Each push to main also runs one suite in
rotation: Element Call end to end, the Neutrino mesh seam or
matrix-rust-sdk's suite. All of them run every night. Fuzz tests and
coverage run weekly.
`.github/workflows/` is the list; each job's comment says why it runs
where it runs.

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

## Adding an endpoint or an MSC

Both have a generated page CI holds to the code. A new route must
appear in `docs/dashboard.md` and leave `docs/spec-gaps.md` (run `just
regen`); a new MSC surface needs an entry in `contrib/msc/ledger.toml`
naming the test that proves it, and the flag it advertises. The whole
procedure, with the spec-release and pin-bump cases, is in
[docs/maintenance.md](docs/maintenance.md).

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
