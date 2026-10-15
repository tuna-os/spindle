# Agent Development Guide

A file for [guiding coding agents](https://agents.md/).

## What this repository is

Spindle is a Matrix homeserver written in Rust, implementing the Matrix
Client-Server API and Server-Server API with rooms stored as append-only logs.

## Build and test

All build and test commands are listed in `CONTRIBUTING.md`. The primary
commands are:

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
just lint  # equivalent to above
just test  # equivalent to cargo test
```

Generated checks that must pass:
```bash
python3 scripts/coverage-dashboard.py --check
python3 scripts/readme-numbers.py --check
python3 scripts/actions-pinned.py
```

## Contributing rules that CI enforces

- Every commit carries a DCO sign-off: `git commit -s`.
- PRs target `main`.
- A test is required: for bugs, reproduce the bug; for features, the test is
  the claim.
- Generated files (`docs/dashboard.md`, `docs/spec-gaps.md`) are regenerated
  with `just regen` when you add or change endpoints or MSCs.
- Performance claims link the benchmark that supports them.

## Repository-specific notes

- `rust-toolchain.toml` pins the Rust compiler version — rustup fetches it
  automatically.
- Storage is embedded (RocksDB); nothing external needs to be provisioned.
- The Complement test suite (`.github/workflows/`) validates end-to-end
  Matrix compliance; see `docs/maintenance.md` for details on adding new
  endpoints or Matrix Spec Change (MSC) implementations.

For issues and PRs, see [CONTRIBUTING.md](CONTRIBUTING.md).
