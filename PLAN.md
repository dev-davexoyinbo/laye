# laye — Implementation Plan

## Context

`laye` is a standalone Rust library crate for role and permission based access control (RBAC). The reference design comes from an actix-web starter template that implements a layered access control system: a global auth middleware that loads roles and permissions from the database, a flexible `AccessControl` enum, and a composable `AccessControlCondition` builder for AND/OR logic at the route level.

`laye` extracts and generalises this pattern into a framework-agnostic library. The core (traits + policy system) has zero framework dependencies. Optional framework integrations are gated behind feature flags so users only pull in what they need.

---

## Stage 1 — Crate Setup ✓ DONE

**Goal:** Convert the binary stub into a library.

**What was done:**
- Deleted `src/main.rs`
- Created `src/lib.rs` with module declarations for `error`, `principal`, `policy`
- Created empty stub files: `src/error.rs`, `src/principal.rs`, `src/policy.rs`
- Added `description` and `license` fields to `Cargo.toml`
- No optional dependencies or feature flags added (deferred to their respective stages)

**`cargo check` passes.**

**Note:** Feature flags (`actix-web`, `tower`) and all optional/dev dependencies are added in Stages 4 and 5 when the code that requires them is written.

---

## Stage 2 — Core Traits and Types

**Goal:** Define the `Principal` trait and the `AccessError` type. No framework dependencies.

**Files:** `src/error.rs`, `src/principal.rs`

### `src/error.rs`
```rust
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum AccessError {
    /// No identity — maps to HTTP 401.
    #[error("Unauthorized")]
    Unauthorized,
    /// Authenticated but insufficient rights — maps to HTTP 403.
    #[error("Forbidden")]
    Forbidden,
}
```

### `src/principal.rs`
```rust
pub trait Principal {
    fn roles(&self) -> &[String];
    fn permissions(&self) -> &[String];
    /// Returns true if this represents an authenticated identity.
    fn is_authenticated(&self) -> bool;

    fn has_role(&self, role: &str) -> bool {
        self.roles().iter().any(|r| r == role)
    }
    fn has_permission(&self, permission: &str) -> bool {
        self.permissions().iter().any(|p| p == permission)
    }
}
```

**Notes:**
- `Principal` is object-safe (no `Self` in non-default signatures, no generics). This is required for `AccessRule::Custom`.
- `is_authenticated` is explicit — a principal can be authenticated with zero roles.

### Stage 2 Tests

**File:** `tests/principal.rs`

```rust
// Minimal concrete impl used across all tests
struct TestUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
impl Principal for TestUser { ... }

#[test] fn has_role_returns_true_for_matching_role()
#[test] fn has_role_returns_false_for_missing_role()
#[test] fn has_permission_returns_true_for_matching_permission()
#[test] fn has_permission_returns_false_for_missing_permission()
#[test] fn is_authenticated_reflects_field()
#[test] fn dyn_principal_coercion_compiles()  // &user as &dyn Principal — verifies object safety
```

---

## Stage 3 — Policy / Condition System

**Goal:** Composable AND/OR access rules with support for nesting. No framework dependencies.

**File:** `src/policy.rs`

### `AccessRule`
```rust
pub type CustomFn = Arc<dyn Fn(Option<&dyn Principal>) -> bool + Send + Sync>;

#[derive(Clone)]
pub enum AccessRule {
    Role(String),
    Permission(String),
    Authenticated,
    Guest,          // passes for None OR principal.is_authenticated() == false
    Custom(CustomFn),
}
```

### `AccessPolicy`
```rust
#[derive(Clone)]
pub struct AccessPolicy {
    checks: Vec<PolicyCheck>,   // Rule | Nested(AccessPolicy)
    mode: PolicyMode,           // All (AND) | Any (OR)
}

impl AccessPolicy {
    pub fn require_all() -> Self { ... }     // AND
    pub fn require_any() -> Self { ... }     // OR
    pub fn add_rule(self, rule: AccessRule) -> Self { ... }
    pub fn add_policy(self, policy: AccessPolicy) -> Self { ... }

    /// Returns Ok(()) on pass.
    /// Returns Err(Unauthorized) when principal is None and auth is needed.
    /// Returns Err(Forbidden) when principal exists but check fails.
    pub fn check(&self, principal: Option<&dyn Principal>) -> Result<(), AccessError> { ... }
}
```

**`check` 401/403 split:** if the policy fails and `principal.is_none()`, return `Unauthorized`; otherwise `Forbidden`.

**Ergonomic helpers on `AccessPolicy`** (gated, live in `src/policy.rs`):
```rust
#[cfg(feature = "actix-web")]
pub fn into_actix_middleware<P: Principal + Clone + 'static>(self) -> actix::PolicyMiddlewareFactory<P>

#[cfg(feature = "tower")]
pub fn into_tower_layer<P: Principal + Clone + Send + Sync + 'static>(self) -> tower_middleware::AccessControlLayer<P>
```

### Stage 3 Tests

**File:** `tests/policy.rs`

```rust
// Uses the same TestUser helper from Stage 2

// AccessRule::Role
#[test] fn role_rule_passes_for_matching_role()
#[test] fn role_rule_fails_for_wrong_role()
#[test] fn role_rule_fails_for_unauthenticated_returns_unauthorized()

// AccessRule::Permission
#[test] fn permission_rule_passes_for_matching_permission()
#[test] fn permission_rule_fails_for_wrong_permission()

// AccessRule::Authenticated
#[test] fn authenticated_rule_passes_for_authenticated_principal()
#[test] fn authenticated_rule_fails_returning_unauthorized_for_none()
#[test] fn authenticated_rule_fails_returning_forbidden_for_unauthenticated_principal()

// AccessRule::Guest
#[test] fn guest_rule_passes_for_none()
#[test] fn guest_rule_passes_for_unauthenticated_principal()
#[test] fn guest_rule_fails_for_authenticated_principal()

// AccessRule::Custom
#[test] fn custom_rule_delegates_to_closure()
#[test] fn custom_rule_receives_none_for_missing_principal()

// AccessPolicy AND mode
#[test] fn require_all_passes_when_all_rules_pass()
#[test] fn require_all_fails_when_any_rule_fails()

// AccessPolicy OR mode
#[test] fn require_any_passes_when_one_rule_passes()
#[test] fn require_any_fails_when_all_rules_fail()

// Nesting
#[test] fn nested_policy_and_of_or_passes()
#[test] fn nested_policy_or_of_and_fails_correctly()

// 401 vs 403 distinction
#[test] fn unauthenticated_request_yields_unauthorized_not_forbidden()
#[test] fn authenticated_without_role_yields_forbidden_not_unauthorized()
```

---

## Stage 4 — actix-web Middleware Helper (`feature = "actix-web"`)

**Goal:** A `Transform` + `Service` middleware that reads a `P: Principal` from request extensions and enforces an `AccessPolicy`.

**Files:** `src/actix/mod.rs`, `src/actix/layer.rs`, `src/actix/extractor.rs`

### Middleware (`src/actix/layer.rs`)
```rust
pub struct PolicyMiddlewareFactory<P> {
    policy: AccessPolicy,
    _marker: PhantomData<P>,
}

// Implements actix_web::dev::Transform<S, ServiceRequest>
// Produces PolicyMiddleware<S, P>

pub struct PolicyMiddleware<S, P> {
    service: S,
    policy: AccessPolicy,
    _marker: PhantomData<P>,
}

// Service::call:
//   1. reads req.extensions().get::<P>()
//   2. calls policy.check(principal.as_deref())
//   3. Ok  → forwards to inner service
//   4. Unauthorized → ErrorUnauthorized
//   5. Forbidden    → ErrorForbidden
```

`Future` type: `LocalBoxFuture<'static, ...>` (actix is single-threaded).

### Extractors (`src/actix/extractor.rs`)
```rust
pub struct AuthPrincipal<P>(pub P);        // 401 if missing from extensions
pub struct MaybeAuthPrincipal<P>(pub Option<P>);  // never fails

// Both implement FromRequest, reading P from extensions
```

**Design notes:**
- Users insert `P` into extensions via their own global auth middleware. `laye` only reads it — no opinion on token format or DB.
- `ErrorUnauthorized` / `ErrorForbidden` use actix's built-in helpers; users can override via a custom `ResponseError` impl.

### Stage 4 Tests

**File:** `tests/actix_middleware.rs` (requires `#[cfg(feature = "actix-web")]`)

Uses `actix_web::test` utilities to spin up a minimal `App`.

```rust
// Helper: build App with a fake "set extensions" middleware that inserts TestUser,
// then wraps a dummy handler with PolicyMiddlewareFactory.

#[actix_web::test]
async fn middleware_allows_request_when_policy_passes()
// → inserts admin TestUser, wraps with Role("admin") policy, expects 200

#[actix_web::test]
async fn middleware_returns_403_when_role_missing()
// → inserts TestUser with no roles, expects 403

#[actix_web::test]
async fn middleware_returns_401_when_no_principal_in_extensions()
// → no extension inserted, policy requires Authenticated, expects 401

#[actix_web::test]
async fn auth_principal_extractor_injects_principal_into_handler()
// → extension present, AuthPrincipal<TestUser> received correctly

#[actix_web::test]
async fn auth_principal_extractor_returns_401_when_missing()

#[actix_web::test]
async fn maybe_auth_principal_returns_some_when_present()

#[actix_web::test]
async fn maybe_auth_principal_returns_none_when_absent()

#[actix_web::test]
async fn and_policy_blocks_when_one_condition_fails()

#[actix_web::test]
async fn or_policy_allows_when_one_condition_passes()
```

---

## Stage 5 — tower Middleware Helper (`feature = "tower"`)

**Goal:** A `tower::Layer` + `tower::Service` that enforces an `AccessPolicy`, compatible with axum and any tower-based framework.

**Files:** `src/tower_middleware/mod.rs`, `src/tower_middleware/layer.rs`

### `AccessControlLayer<P>` + `AccessControlService<S, P>`
```rust
#[derive(Clone)]
pub struct AccessControlLayer<P> {
    policy: AccessPolicy,
    _marker: PhantomData<fn(P)>,   // fn(P) = covariant + Send+Sync without P bound on struct
}

impl<S, P> Layer<S> for AccessControlLayer<P> {
    type Service = AccessControlService<S, P>;
    fn layer(&self, inner: S) -> Self::Service { ... }
}
```

### `Service::call` flow
1. Extract `P` from `req.extensions()` (axum inserts into `http::Request` extensions)
2. Call `policy.check(principal.as_deref())`
3. `Ok` → pin the inner service future
4. `Err` → short-circuit with `Response` at `StatusCode::UNAUTHORIZED` or `FORBIDDEN`

### Future type
```rust
pin_project! {
    pub enum AccessControlFuture<F, B> {
        Inner   { #[pin] future: F },
        Rejected { status: StatusCode, _body: PhantomData<B> },
    }
}
```

`ResBody: Default` is required to construct the rejection response body (`axum::body::Body` satisfies this).

**Design notes:**
- No `axum` dep in this stage — tower `Layer`/`Service` + `http` crate are sufficient. An optional `axum` feature for `FromRequestParts` extractors can be added later.
- `fn(P)` in PhantomData makes the layer `Send + Sync` without constraining `P`.
- actix and tower implementations are independent — do not attempt to unify them.

### Stage 5 Tests

**File:** `tests/tower_middleware.rs` (requires `#[cfg(feature = "tower")]`)

Uses `tower::ServiceExt` + `tower_test` / hand-rolled mock service to drive requests.

```rust
// Helper: build a tower ServiceBuilder stack with AccessControlLayer + a mock inner service
// that returns 200 OK with an empty body.
// Requests carry http::Extensions with an optional TestUser inserted.

#[tokio::test]
async fn layer_allows_request_when_policy_passes()
// → extension has admin, Role("admin") policy, inner service called, 200

#[tokio::test]
async fn layer_returns_403_when_role_missing()
// → extension has non-admin user, 403, inner service NOT called

#[tokio::test]
async fn layer_returns_401_when_no_principal_in_extensions()
// → no extension, Authenticated policy, 401

#[tokio::test]
async fn layer_short_circuits_without_calling_inner_service_on_rejection()
// → verify inner service call count stays at 0 when rejected

#[tokio::test]
async fn and_policy_blocks_when_one_condition_fails()

#[tokio::test]
async fn or_policy_allows_when_one_condition_passes()

#[tokio::test]
async fn layer_is_clone_and_send()
// compile-time: fn assert_send<T: Send>(_: T) {} called on the layer
```

---

## Stage 6 — Documentation and Examples

**Goal:** Rustdoc on all public items; runnable examples for each integration.

**Files:**
- `src/lib.rs` — crate-level doc with feature flag table
- All public types and methods — `///` doc comments with `# Examples` snippets
- `examples/basic.rs` — core policy system, no framework dep
- `examples/actix_web_example.rs` — `required-features = ["actix-web"]`
- `examples/axum_example.rs` — `required-features = ["tower"]`

Each example demonstrates:
1. Implementing `Principal` on a custom auth info type
2. Building an `AccessPolicy` with AND/OR rules
3. Wiring the middleware into the framework's routing system
4. Using the extractor in a handler

### Stage 6 Tests

- `cargo doc --no-deps --all-features` — no warnings (`RUSTDOCFLAGS=-D warnings`)
- All `# Examples` blocks in rustdoc are compiled via `cargo test --doc --all-features`
- `cargo run --example basic` exits with code 0
- `cargo run --example actix_web_example --features actix-web` compiles and starts without panic
- `cargo run --example axum_example --features tower` compiles and starts without panic

---

## Implementation Order

```
Stage 1 (Cargo.toml + lib.rs)
    │
    ▼
Stage 2 (error.rs + principal.rs)       ← no intra-crate deps
    │
    ▼
Stage 3 (policy.rs)                     ← depends on Stage 2
    │
    ├────────────────────┐
    ▼                    ▼
Stage 4 (actix)      Stage 5 (tower)    ← independent of each other
    │                    │
    └────────────────────┘
                │
                ▼
           Stage 6 (docs + examples)
```

## Verification

After each stage, verify by running:

```sh
# Stages 1–3: core compiles with no features
cargo check

# Stage 4: actix integration compiles
cargo check --features actix-web

# Stage 5: tower integration compiles
cargo check --features tower

# All features together
cargo check --all-features

# Run examples
cargo run --example basic
cargo run --example actix_web_example --features actix-web
cargo run --example axum_example --features tower

# Tests
cargo test
cargo test --all-features
```

## Known Challenges

1. **Object safety**: verify `&dyn Principal` coercion works in tests before Stage 3 is complete.
2. **`ResBody: Default` for tower rejections**: `axum::body::Body` satisfies this; document the constraint clearly. A `with_rejection_fn` builder can be added later for full control.
3. **actix `LocalBoxFuture` is `!Send`**: expected — do not attempt to make actix types `Send`.
4. **Turbofish on `.into_actix_middleware::<MyUser>()`**: users must specify `P`. Consider also exposing `AccessRule::role("admin").into_actix_middleware::<MyUser>()` as a convenience shorthand.
