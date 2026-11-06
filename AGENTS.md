# Agent guide

This page is for agents and people who change Spindle. The rules for a
change are in the [contributor guide](CONTRIBUTING.md). Read it too.

## What Spindle is

Spindle is a Matrix homeserver in Rust. Each room is an append-only log
with materialized state. The server keeps its data in an embedded store,
so a test needs no database. [README.md](README.md) gives the status,
[ROADMAP.md](ROADMAP.md) gives the next work and [SPEC.md](SPEC.md) gives
the design.

## Where the code is

| Crate | Contents |
|---|---|
| `crates/spindle-core` | The log, the persistent state and the store keys (`keys.rs`). |
| `crates/spindle-store` | The ordered-key store on fjall. |
| `crates/spindle-server` | The HTTP surface, federation and the binary (`main.rs`). |
| `crates/spindle-operator` | The operator service. |

In `spindle-server/src`, `lib.rs` builds the app, `routes.rs` is the
router and `config.rs` has every setting. `rooms/` holds room state and
the sync stream. `sync_routes.rs` serves `/sync` and MSC4186 sync, and
`metrics.rs` has the Prometheus series. Integration tests are in
`crates/spindle-server/tests/`, one file for each area.

## Build and test

`rust-toolchain.toml` sets the compiler. The full gate is:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

`just lint` and `just test` run the same commands. A full workspace test
build is large. For one change, build the test files that change touches:

```sh
cargo test -p spindle-server --test sliding_sync
cargo test -p spindle-server --lib sliding
```

Clippy uses the pedantic lints, and a warning is an error.

## Gates beside the Rust build

The `Rust quality gate` job in `.github/workflows/ci.yml` runs these
scripts. Run the ones that your change can affect:

```sh
python3 scripts/coverage-dashboard.py --check   # docs/dashboard.md and the router
python3 scripts/spec-drift.py --check           # docs/spec-gaps.md
python3 scripts/msc-ledger.py --check           # contrib/msc/ledger.toml and docs/mscs.md
python3 scripts/config-drift.py                 # spindle.example.toml and config.rs
python3 scripts/readme-numbers.py --check       # the numbers in the README
python3 scripts/check-observability-pack.py     # metric names in deploy/ and docs/metrics.md
```

`just regen` writes the generated pages again. A new route or MSC needs
the steps in [docs/maintenance.md](docs/maintenance.md).

Pull requests also run the Complement subset (`complement-suite`) and
the debug rigs (`debug-rigs`). Branch protection needs those two and the
quality gate. Complement needs Docker.

The `Prose` workflow lints all Markdown for Simplified Technical English.
The `.ste-budget` file holds the highest count of findings that it
accepts. Never increase that number. To check a page, get the linter
from `tuna-os/.github` and run it from the repository root:

```sh
node <path-to-tuna-os/.github>/.github/actions/ste-lint/ste-lint.mjs --summary
```

## What a change must have

- A test that fails before the fix. Show the failure on the old code.
- For a performance claim, an assertion that counts (bytes, reads or
  allocations). Do not use a time measurement, because it is not stable.
- No stubs. A route that the router has must work.
- Comments that tell why, not what.
- A commit message in plain prose. It tells what changed and why, and
  it ends with `Closes #N`.

## Pitfalls with parallel work

Some agents work in parallel in a set of git worktrees from one clone.
These problems occurred:

- **All worktrees of a clone use one `git stash` list.** An agent can
  take a stash entry that is not its own. Do not use `git stash`. To run
  the old code, save `git diff` to a file and check out the old files.
  Then use `git apply` to put the change back.
- **Relative paths go to the wrong checkout.** A tool can resolve a
  relative path against a different directory. Use absolute paths in
  your worktree for all reads and edits.
- **One target directory for each worktree.** Set `CARGO_TARGET_DIR` to
  a `target` directory in your worktree. If two worktrees use one target
  directory, they wait for its lock and overwrite the builds of the other.
- **Disk space.** One debug build of the workspace tests uses many
  gigabytes. Set `CARGO_PROFILE_DEV_DEBUG=0` and
  `CARGO_PROFILE_TEST_DEBUG=0`, and remove `target` at the end.
- **Shared hosts.** The time of a test changes with the load on the
  host. Use counts, not times, when you compare two runs.
- **The default storage path is `./data`.** A test that sets no
  `[storage] path` writes its media into the source tree. Set the
  path to the `TempDir` of the test.
