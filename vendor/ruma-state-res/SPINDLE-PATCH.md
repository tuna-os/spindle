# Spindle's local Ruma patch

Base: ruma-state-res 0.18.0, from crates.io. Registry checksum:

```text
08294aac3a4cc6b20e29c7822a2cd13c13541b1175ec260065503ac37c8207ed
```

Upstream: https://github.com/ruma/ruma. License: MIT; see LICENSE.

Upstream commit: `13e95d7c5857928331d241290f112a4595ff268b`

The crate's `.cargo_vcs_info.json` names this commit: ruma made the 0.18.0
package from `crates/ruma-state-res` at it.

The extension adds `resolve_with_candidate_policy`.
Its predicate can skip a candidate during iterative auth checks.
The patch preserves the event order and the rules for auth dependencies.
The usual `resolve` function uses a predicate that always returns true.

A second change (#626) concerns the iterative auth checks. A candidate that fails
the authentication check is logged at DEBUG instead of WARN. Such a failure is an
expected part of resolution, not a fault. The patch also counts each failure in a
per-thread counter. `take_auth_rejections` reads the count and resets it. A
resolution runs on the thread that asked for it, so Spindle reads the counter
after each resolution and exports it as `spindle_state_res_rejections_total`.

Spindle uses the extension to preserve Synapse's rejection decisions for
imported history. The operator chose this policy.
For new events, the resolver keeps Ruma's usual behavior.
The policy is explicit: Synapse keeps old rejections where the Matrix
algorithm can reconsider an event that failed at a former state.

We keep the source and upstream tests here so a reviewer can compare the
change with the release. Run them with:

```sh
cargo test --manifest-path vendor/ruma-state-res/Cargo.toml
```

## The patch surface

ADR 0006 gives this fork no end date, so the list below sets its size.
`scripts/ruma-drift.py --check` runs in CI. It downloads the base crate and
refuses it unless the checksum above matches.

It compares the crate with this directory. It fails on a hunk or file that
the table does not list, and on a listed one that is gone. The script names
a hunk by its header and the first 16 hex digits of the sha256 of its
lines. An edit to a hunk thus changes its row too.

A larger patch thus needs a reviewed edit to this table. Run
`scripts/ruma-drift.py --hunks` for the current rows; a row with an empty
reason is new and needs one. For the rebase onto a newer release, see
docs/maintenance.md, "Rebase vendor/ruma-state-res".

| File | Hunk | Digest | Why |
|---|---|---|---|
| `.cargo_vcs_info.json` | removed | | Packaging metadata of the published crate; the commit it names is recorded above. |
| `.clippy.toml` | removed | | Ruma's workspace lint settings; nothing lints this directory, which sits outside Spindle's workspace. |
| `.rustfmt.toml` | added | | The stable subset of Ruma's formatting settings, so formatting an edit here does not reflow upstream's code. |
| `CHANGELOG.md` | removed | | Upstream's release notes, read upstream. |
| `Cargo.toml` | `@@ -142,3 +142,5 @@` | `cb7d8e939bd36a9b` | An empty `[workspace]`, so `cargo test --manifest-path` builds the crate on its own rather than as a stray member of Spindle's workspace. |
| `LICENSE` | added | | Ruma's MIT licence, which the crate does not ship and the copy must carry. |
| `SPINDLE-PATCH.md` | added | | This file. |
| `src/lib.rs` | `@@ -83,5 +83,8 @@` | `9925576413f54ec4` | Exports `resolve_with_candidate_policy` and `take_auth_rejections`. |
| `src/state_res.rs` | `@@ -36,6 +36,19 @@` | `2b5a1f3733190f22` | The per-thread rejection counter and `take_auth_rejections` (#626). |
| `src/state_res.rs` | `@@ -81,6 +94,38 @@` | `4b261933b86ce205` | `resolve` becomes `resolve_with_candidate_policy` with an always-true predicate; the new function takes the predicate. |
| `src/state_res.rs` | `@@ -148,8 +193,13 @@` | `629b6f5f89966862` | Passes the predicate to the iterative auth checks over the power events. |
| `src/state_res.rs` | `@@ -178,11 +228,12 @@` | `5c5e5c7881d9e31f` | Passes it to the iterative auth checks over the remaining events. |
| `src/state_res.rs` | `@@ -607,11 +658,22 @@` | `9427f98df42ad784` | `iterative_auth_checks` keeps its signature for upstream's tests and delegates to the variant taking the predicate. |
| `src/state_res.rs` | `@@ -620,6 +682,9 @@` | `31e96a770577e58c` | The predicate itself: a candidate it refuses is skipped before its auth check. |
| `src/state_res.rs` | `@@ -688,8 +753,11 @@` | `7fceb7bb2b566697` | A failed auth check is counted and logged at DEBUG, not WARN (#626). |
| `Cargo.lock` | regenerated | | The lock for this crate's own test build; Spindle builds it through the workspace lock, so this is tooling output, not source. |
