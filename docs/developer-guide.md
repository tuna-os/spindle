# Developer Guide

## Architecture

Spindle has three crates:

1. **spindle-core** — State machine and algorithms
2. **spindle-store** — Data storage 
3. **spindle-server** — HTTP endpoints

See [SPEC.md](../SPEC.md) for design details.

## spindle-core

Location: `crates/spindle-core/src/`

**Modules:**
- `log.rs` — Append-only event log with index
- `state.rs` — Room state storage
- `pdu.rs` — Event type
- `keys.rs` — Ed25519 signing
- `version.rs` — Room versions

## spindle-store

Location: `crates/spindle-store/src/`

Durable storage. Provides APIs for reading and writing logs and state.

## spindle-server

Location: `crates/spindle-server/src/`

HTTP endpoints. Main modules:

- `rooms/` — Room operations
- `federation.rs` — Federation
- `accounts.rs` — Accounts
- `authorize.rs` — Access control
- `devices.rs` — Device tracking
- `media.rs` — File operations
- `push.rs` — Notifications
- `presence.rs` — Presence
- `profiles.rs` — Profiles
- `routes.rs` — HTTP routes
- `config.rs` — Configuration
- `errors.rs` — Error handling
- `metrics.rs` — Metrics

## AppState

All handlers receive `AppState`. It contains all subsystems:

```rust
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<FjallStore>,
    pub rooms: Arc<rooms::Rooms>,
    pub devices: Arc<devices::Devices>,
}
```

## Tasks

### Test

```sh
cargo test --workspace
cargo test --workspace -- --test-threads=1
cargo test --lib rooms
```

### Lint

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

### Find Code

```sh
grep -n "POST /sync" crates/spindle-server/src/routes.rs
```

### Add Endpoint

1. Create handler in the module
2. Add route to `routes.rs`
3. Write test
4. Run tests

### State Changes

1. `inbound.rs` receives event
2. Handler checks access
3. Store appends to log
4. `spindle-core` updates state
5. Subscribers are notified

### Debug

Use `tracing`:

```rust
tracing::debug!("message");
```

Run with:

```sh
RUST_LOG=debug cargo run
```

## Performance

Add `debug_assert!()` for counting operations. Do not use timing tests.

Add metrics to `metrics.rs`. View at `/metrics`.

## Build Release

```sh
cargo build --release -p spindle-server --bin spindle
```

Binary: `target/release/spindle`

## License

MIT OR Apache-2.0.
