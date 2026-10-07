# Developer Guide

## Architecture Overview

Spindle has three crates:

1. **spindle-core**: State machine and algorithms
2. **spindle-store**: Data storage using fjall
3. **spindle-server**: HTTP endpoints

Read [SPEC.md](../SPEC.md) for design details.

## spindle-core

Location: `crates/spindle-core/src/`

### Modules

- `log.rs`: Append-only log of events. Each event has an index.
- `state.rs`: Room state using content-addressed storage.
- `pdu.rs`: Matrix event type for internal use.
- `keys.rs`: Signing keys and Ed25519 operations.
- `version.rs`: Room version handling.

## spindle-store

Location: `crates/spindle-store/src/`

This crate handles data storage. It provides transaction APIs for reading and writing logs and state.

## spindle-server

Location: `crates/spindle-server/src/`

This crate has all HTTP endpoints.

### Main Modules

- `rooms/`: Room operations
- `federation.rs`: Server federation
- `accounts.rs`: User accounts
- `authorize.rs`: Access control
- `devices.rs`: Device tracking
- `media.rs`: File upload and download
- `push.rs`: Push notifications
- `presence.rs`: User presence
- `profiles.rs`: User profiles
- `routes.rs`: HTTP route table
- `config.rs`: Configuration
- `errors.rs`: Error handling
- `metrics.rs`: Metrics

## AppState

All HTTP handlers receive `AppState`. This struct has access to all subsystems:

```rust
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<FjallStore>,
    pub rooms: Arc<rooms::Rooms>,
    pub devices: Arc<devices::Devices>,
    // ... more subsystems
}
```

## Common Tasks

### Running Tests

```sh
cargo test --workspace
cargo test --workspace -- --test-threads=1
cargo test --lib rooms
```

### Code Quality

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

### Finding Code

Use grep to find where code lives:

```sh
grep -n "POST /sync" crates/spindle-server/src/routes.rs
```

### Adding an Endpoint

1. Find or create the handler in the appropriate module
2. Add the route to `routes.rs`
3. Write a test
4. Run `cargo test`

### Understanding State Changes

The flow is:

1. `inbound.rs` receives an event
2. Handler checks access
3. Store appends to log
4. `spindle-core` updates state
5. Subscribers get notified

### Debug Output

Use the `tracing` crate:

```rust
tracing::debug!("message here");
```

Run with:

```sh
RUST_LOG=debug cargo run
```

## Performance

When adding performance-critical code, add a `debug_assert!()` that counts operations. Do not rely on timing tests.

Add metrics to `metrics.rs` and check them at `/metrics`.

## Building for Production

```sh
cargo build --release -p spindle-server --bin spindle
```

The binary is `target/release/spindle`.

## License

Contributions are licensed under MIT OR Apache-2.0.
