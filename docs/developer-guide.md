# Developer Guide: Code Structure and Architecture

This guide explains how the Spindle codebase is organized and how it implements the concepts described in [SPEC.md](../SPEC.md). If you are new to Spindle or trying to understand where a particular feature lives in the code, start here.

## Overview: The Three-Crate Architecture

Spindle is organized as a Rust workspace with three crates, each with a distinct responsibility:

| Crate | Purpose | Key Exports |
|---|---|---|
| **spindle-core** | Linear-log and persistent-state primitives — the heart of Spindle's design | `Log`, `State`, `StateHamt`, `Pdu`, `Fork` |
| **spindle-store** | Embedded durable storage using fjall (ordered-key B+ tree) | `FjallStore`, transaction APIs, persistence |
| **spindle-server** | HTTP surface and all endpoint handlers — the Matrix homeserver implementation | `AppState`, handlers, routes, subsystems |

### Dependency Flow

```
spindle-server (HTTP surface)
    ↓
spindle-core (state machine & algorithms)
spindle-store (storage backend)
```

The server depends on both core and store; core and store have no circular dependencies.

## Crate Deep Dive

### 1. spindle-core: The State Machine

**File:** `crates/spindle-core/src/`

This crate implements the core architectural innovation: **linear-log rooms with materialized state and bounded-window state resolution** (SPEC §9).

#### Key Modules

- **`log.rs`** — The append-only log: `Log<T>` is the ordered sequence of events in a room, keyed by `i64` index. This is where SPEC §3 (linear ordering) lives.

- **`state.rs`** — Materialized state as a content-addressed HAMT (Hash Array Mapped Trie). The `State` struct holds the room state at a point in time. When an event arrives, state advances from the prior state via structural sharing. This is where SPEC §4 (materialized state) lives.

- **`pdu.rs`** — Protocol Data Unit: the Matrix event type that Spindle works with internally. This is separate from ruma's event types (ruma handles the wire format; this is the internal representation).

- **`keys.rs`** — Server signing keys and Ed25519 operations.

- **`version.rs`** — Room version handling.

#### Where to look for...

- **State resolution logic:** `state.rs` and the comparison operators. See also SPEC §9.3 (equivalence theorem).
- **Event ordering:** `log.rs`. Every event has an `i64` index that is both the topological order and the unique identifier.
- **Fork detection and handling:** `state.rs` contains the fork-case logic (SPEC §9.2). The test file `crates/spindle-store/tests/backend_compatibility.rs` exercises fork cases.
- **Authorization checks:** These are in the server crate, not core. Core is state-agnostic; the server crate layers auth on top.

### 2. spindle-store: Persistence

**File:** `crates/spindle-store/src/`

This crate abstracts durable storage using **fjall** (an embedded ordered-key B+ tree). It provides transactional operations for reading and writing the log and state.

#### Key Types

- **`FjallStore`** — The main store type that wraps fjall and provides Spindle-specific operations.
- **Transaction API** — Atomic reads/writes for a room.

#### Where to look for...

- **Reading/writing events:** `FjallStore` methods for log operations.
- **State persistence:** How the HAMT is serialized and read back.
- **Storage format:** The fjall layer handles durability; Spindle concerns itself with what goes into the key-value pairs.
- **Recovery:** Tear-write recovery is tested but most of the machinery is in fjall itself.

### 3. spindle-server: The HTTP Surface

**File:** `crates/spindle-server/src/`

This is the largest crate — it implements the full Matrix client-server and server-server APIs, built on top of spindle-core and spindle-store. It's organized by feature area rather than by HTTP method.

#### High-Level Organization

**Core subsystems:**
- **`rooms/`** — Room-level operations: join, leave, send event, fetch state, timelines, relations, threads, redaction
- **`federation.rs`** — Server-to-server federation: signed requests, join/invite/leave handshakes, backfill, state reads
- **`accounts.rs`** — User account management
- **`auth.rs` / `authorize.rs`** — Authentication and authorization checks (SPEC §7-8)
- **`state_res_v1.rs`** — Full state resolution for fork cases and legacy peers (fallback to ruma's algorithm)

**Feature modules:**
- **`devices.rs`** — E2EE device tracking
- **`e2ee_federation.rs`** — Cross-server E2EE key exchange (MSC4242, Hydra phase 2)
- **`media.rs`** — Media upload/download and thumbnailing
- **`push.rs` / `push_rules.rs` / `pushers.rs`** — Push notification logic
- **`presence.rs` / `presence_routes.rs`** — User presence
- **`profiles.rs`** — User profiles (displayname, avatar)
- **`filters.rs`** — `/sync` filters
- **`backups.rs`** — E2EE key backup
- **`appservices.rs`** — Application Service protocol (MSC2409)
- **`delegated.rs` / `oidc.rs` / `openid.rs`** — MSC3861 delegated auth and built-in OIDC provider
- **`livekit.rs`** — LiveKit JWT token issuance for calls
- **`delayed.rs`** — MSC4140 delayed events (dead-man's switch for call ghosting)
- **`account_data.rs`** — Per-user account data (e.g., push rules, filters)

**Supporting modules:**
- **`config.rs`** — Configuration loading and validation
- **`errors.rs`** — Error types
- **`routes.rs`** — The route table (422 KB!) that maps HTTP requests to handlers
- **`surface.rs`** — The `/versions` endpoint and what it advertises
- **`telemetry.rs`** — OpenTelemetry instrumentation
- **`metrics.rs`** — Prometheus metrics (SPEC §19: the metric that falsifies the architecture)
- **`ratelimit.rs`** — Rate limiting
- **`netguard.rs`** — IP reputation and spam mitigation
- **`signing.rs`** — Server key pair and signing
- **`inbound.rs`** — Inbound event processing: the path from wire to state change
- **`import.rs`** — Data import (migrations from Synapse)
- **`tokens.rs`** — Registration and other tokens
- **`typing.rs`** — Typing indicators
- **`rendezvous.rs`** — Device rendezvous
- **`mas.rs`** — Synapse MAS (`/_synapse/admin/v1`) compatibility
- **`admin.rs`** — Admin endpoints (18 of them)
- **`directory.rs`** — Room directory and aliases
- **`previews.rs`** — URL previews

#### The AppState Struct

```rust
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<FjallStore>,
    pub rooms: Arc<rooms::Rooms>,
    pub devices: Arc<devices::Devices>,
    // ... 20+ subsystems
}
```

Every HTTP handler receives `AppState`, which gives it access to all subsystems. This is how handlers coordinate — through the shared subsystems.

#### Where to look for...

- **Client-server routes:** `routes.rs` (routes that start with `/_matrix/client/`)
- **Server-to-server routes:** `routes.rs` (routes that start with `/_matrix/federation/`)
- **Admin routes:** `admin.rs`
- **A specific endpoint:** Use `grep` on `routes.rs` for the route pattern, then follow the handler function reference
- **State change flow:** `inbound.rs` (receives event → calls store → updates state) → `rooms/` (broadcast to subscribers)
- **Authorization for an endpoint:** `authorize.rs` or the handler itself
- **Adding a new endpoint:** See [docs/maintenance.md](maintenance.md) for the procedure; you'll likely touch `routes.rs` (add the route), write a handler (in the appropriate feature module), and add a test

### Working with the Code: Common Tasks

#### Adding a new endpoint

1. **Decide where it belongs:** Is it a room operation? User operation? Admin operation? Find the feature module.
2. **Write a handler function** in the appropriate module (e.g., `rooms/mod.rs` for a room endpoint).
3. **Add the route** to `routes.rs`.
4. **Write a test** to prove it works. If it's a spec endpoint, add it to the appropriate test file. If it's a new feature, add the test to the feature module.
5. **Run the gates:** `just lint`, `just test`. If this is a new spec endpoint, `just regen` will update `docs/dashboard.md`.

#### Understanding how an event flows through the system

1. **Inbound:** `inbound.rs` receives the event (either from a client or from federation)
2. **Validation:** The handler checks auth (via `authorize.rs`) and signs it
3. **Store:** The event is appended to the log via `spindle-store`
4. **State:** `spindle-core` updates the state HAMT
5. **Broadcast:** `rooms.rs` notifies subscribers (sync clients, etc.)

#### Finding where state resolution happens

- **No fork:** State advances by copying ~3 HAMT nodes. This is fast.
- **Fork detected:** `spindle-core` enters the fork case. Check `state.rs` for the logic.
- **Legacy peer:** If a peer sends a non-linear event, `state_res_v1.rs` falls back to ruma's full state resolution (SPEC §9.3).

#### Understanding the test structure

- **`tests/surface.rs`** — Proves `/versions` advertises only what is built
- **`crates/spindle-store/tests/backend_compatibility.rs`** — Exercises fork cases differentially against ruma
- **Per-crate tests:** Most Rust files have `#[cfg(test)]` blocks at the end. Run `cargo test` to execute them all.
- **External suites:** `scripts/complement.sh` (Complement ratchet), `contrib/rust-sdk/run.sh` (SDK tests), etc.

## The Design ↔ Code Mapping

Here's how SPEC.md concepts map to code:

| SPEC Concept | Code Location | Evidence |
|---|---|---|
| §3: Linear ordering via `i64` index | `spindle-core/src/log.rs` | `Log<T>::append()` and indexed storage |
| §4: Materialized state (HAMT) | `spindle-core/src/state.rs` | `State` struct and `StateHamt` |
| §7-8: Authorization (≤6 trie lookups) | `spindle-server/src/authorize.rs` | `can_user_do()` and related checks |
| §9: Fork handling (bounded window) | `spindle-core/src/state.rs` | Fork case logic and window bounds |
| §18.3: State resolution (on exception path) | `spindle-server/src/state_res_v1.rs` | Fallback to ruma, only when needed |
| §19: Metrics (fork-case counter) | `spindle-server/src/metrics.rs` | `Metrics::fork_case_count` |
| Room version 11 support | Multiple modules | Ruma types + core SPEC validation |

## Debugging and Development Tips

### Running tests locally

```bash
cargo test --workspace                  # All tests
cargo test --workspace -- --test-threads=1  # Serial (slower, but more predictable)
cargo test --lib rooms                  # Just the rooms module tests
cargo test --doc                        # Doc tests
```

### Checking an endpoint in the code

```bash
# Find where GET /sync is routed:
grep -n "POST /sync\|GET /sync" crates/spindle-server/src/routes.rs
# Then find the handler (follow the function reference)
```

### Adding debug output

Use the `tracing` crate (already a dependency). Add `tracing::debug!()` or `tracing::info!()` calls; they are gated by the `RUST_LOG` environment variable at runtime.

### Performance profiling

- **Counting assertions:** When adding performance-critical code, add a `debug_assert!()` that counts an operation (e.g., `debug_assert_eq!(trie_lookups, 6)` for auth). This gates on behavior, not timing. See [docs/benchmarks.md](benchmarks.md) for why.
- **Metrics:** Add metrics to `spindle-server/src/metrics.rs` and export them at `/metrics`. See [docs/metrics.md](metrics.md).

## Next Steps

- **Read SPEC.md** for the architectural rationale
- **Skim CONTRIBUTING.md** for the PR process
- **Explore `docs/`** — each file covers a specific area (federation, calls, appservices, etc.)
- **Read the `Cargo.toml` dependencies** to understand the tech stack (ruma for Matrix types, axum for HTTP, fjall for storage)
- **Pick an issue** labeled `good first issue` and trace the code

## Questions?

If something is unclear, open an issue with the `documentation` label and mention what you were trying to understand. The codebase is complex, and gaps in this guide are also documentation bugs.
