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
Spindle includes storage, so you do not need a database.

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

`just lint` and `just test` run the same commands. `just --list` names the
other tasks. These tasks generate pages (`just docs`) and run competitive
benchmark trials from a bare checkout (`just bench <group>`). Its three steps
are `bench-field`, `bench-build`, and `bench-sitting`. The benchmark notes in
`docs/benchmarks.md` explain each step and identify the field's pinned versions.

Those three are the pull-request gate, with a few checks that keep
generated and hand-copied things honest:

```sh
python3 scripts/coverage-dashboard.py --check   # docs/dashboard.md matches the router
python3 scripts/readme-numbers.py --check       # the README's headline numbers are the gated ones
python3 scripts/actions-pinned.py               # every action is pinned to a commit
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

- **A test that fails before the change.** A bug test reproduces the bug. A
  feature test states the claim. Performance work includes an assertion about
  deterministic counts, such as allocations, bytes, or comparisons. Tests of
  elapsed time do not fail deterministically.
- **No stubs.** Every routed endpoint works; any other endpoint answers 404.
  `tests/surface.rs` enforces that `/versions` advertises only built features.
  A placeholder that returns `{}` is worse than a 404. A client cannot
  distinguish that placeholder from success.
- **Honest numbers.** Generators or gates control the dashboard, README counts,
  and Complement allowlist. A performance claim links to its benchmark. The
  text preserves a retracted claim as retracted.
- **Comments that explain why.** The code says what it does. A comment records
  a reason, a rejected alternative, or the failure that required the change.

## Adding an endpoint or an MSC

CI holds generated pages to the code. Add each new route to
`docs/dashboard.md` and remove it from `docs/spec-gaps.md`. Run `just regen`.
Add each new MSC surface to `contrib/msc/ledger.toml`. Name the test that proves
the surface and the flag it advertises. The procedure for spec releases and pin
updates is in [docs/maintenance.md](docs/maintenance.md).

## Finding something to do

Issues with the `good first issue` label include a design. The `help wanted`
label identifies work that needs an unavailable client, bridge, or second
homeserver. The README milestone table gives the roadmap in prose. ROADMAP.md
has the entry points for each track.

## Pull requests

One change per pull request, with the commit message saying what changed
and why in plain prose. Pushes to your branch re-run the gate; the
Complement ratchet runs its protected subset on pull requests and the
whole suite on main. A red check is yours to read before a reviewer does.

## Security

Not an issue. `SECURITY.md` has the route.
