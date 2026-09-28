# Routes.rs Extraction Refactor Plan

## Objective
Split `crates/spindle-server/src/routes.rs` (10.8k LOC, 308 handlers) into domain-specific modules following the established pattern of `admin.rs`, `oidc.rs`, `mas.rs`, `openid.rs`, `livekit.rs`, and `dehydrated.rs`.

## Current State
- **routes.rs**: 10,822 lines, 11 builder functions, 308 async handlers
- Router assembly: Already split into named builders (`account_routes()`, `push_routes()`, etc.)
- Handler bodies: Monolithic in same file
- Peer modules: Six established modules each export `pub fn routes() -> Router<AppState>`

## Extraction Priority (by LOC and coupling)

### Phase 1 (Critical — High Coupling)
1. **Presence** (`presence.rs`)
   - Handlers: `put_presence`, `get_presence` (~60 LOC)
   - Dependencies: `crate::presence::State`
   - Router builder: Inlined in `profile_routes()`

2. **Moderation** (`moderation.rs`)
   - Handlers: `post_report_event`, `get_report` (~200 LOC)
   - Dependencies: `MatrixError`, audit logging
   - Router builder: `report_and_hold_routes()`

3. **Push** (`push/mod.rs`)
   - Handlers: All push-related (rules, settings, pushers) (~150 LOC estimated)
   - Dependencies: Push service state
   - Router builder: `push_routes()`

### Phase 2 (Medium — Active Development)
4. **Appservice** (`appservice.rs`)
   - Handlers: Appservice endpoints (~100 LOC)
   - Dependencies: Appservice service
   - Router builder: `appservice_routes()`

5. **Devices** (`devices.rs`)
   - Handlers: Device management (~100 LOC)
   - Dependencies: Device service
   - Router builder: `device_routes()`

### Phase 3 (Lower Priority)
6. **Profile** → Already has isolated handlers; consider micro-optimization
7. **Account** → User registration, login logic (substantial, ~100 LOC)
8. **Room** → Membership, creation logic (substantial, ~150 LOC)
9. **Timeline** → Event sending, history (substantial, ~200 LOC)
10. **Media** → Upload, download (substantial, ~150 LOC)
11. **Federation** → Read/write/state/backfill (substantial, ~250 LOC)
12. **Discovery** → Well-known, discovery (small, ~50 LOC)

## Extraction Pattern

Each extracted module follows the admin.rs template:

```rust
//! Module description with spec context.

use axum::extract::{...};
use axum::routing::{...};
use axum::{Json, Router};

/// Handler docstrings as present in routes.rs

async fn handler_name(...) -> Result<...> {
    // Handler implementation from routes.rs
}

// ... all handler functions ...

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("path", method(handler))
        // ... all routes for this concern ...
}
```

## Integration Points

1. **lib.rs**: Add `pub mod presence;`, `pub mod moderation;`, etc.
2. **routes.rs**: Replace builder functions with calls to extracted modules:
   ```rust
   fn router(state: Arc<AppState>) -> Router {
       let routes = Router::new()
           .merge(account_routes())
           .merge(crate::presence::routes())  // Extracted
           .merge(crate::moderation::routes()) // Extracted
           // ... remaining builders ...
   }
   ```
3. **Tests**: Move handler unit tests into extracted modules

## Benefits

- Single-responsibility modules per concern
- Easier to understand handler context
- Simpler to test (no need to import 308 handlers)
- Clear dependency boundaries
- Incremental extraction (no big-bang refactor)
- Preserves existing router assembly logic

## Implementation Strategy

1. Start with Phase 1 (presence, moderation, push) — small, isolated, proven pattern
2. One module per PR to keep reviews manageable
3. Keep routes.rs in working state throughout extraction
4. Preserve all existing tests and add module-level tests
5. No behavior changes — pure structural refactor

## Rollout Timeline

- **PR 1**: Presence module extraction
- **PR 2**: Moderation module extraction
- **PR 3**: Push module extraction
- **PR 4-12**: Remaining Phase 2 & 3 modules (or defer to future sessions)

Each PR closes the corresponding extracted-module task and leaves routes.rs tracked as the remaining work.

## References
- Issue: #482
- Pattern: admin.rs, oidc.rs, mas.rs, openid.rs, livekit.rs, dehydrated.rs
- Related: architecturally similar refactors in mariner, finupdate, protota
