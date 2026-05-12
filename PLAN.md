# laye — Implementation Plan

## Context

`laye` is a standalone Rust library crate for role and permission based access control (RBAC). The reference design comes from an actix-web starter template that implements a layered access control system: a global auth middleware that loads roles and permissions from the database, a flexible `AccessControl` enum, and a composable `AccessControlCondition` builder for AND/OR logic at the route level.

`laye` extracts and generalises this pattern into a framework-agnostic library. The core (traits + policy system) has zero framework dependencies. Optional framework integrations are gated behind feature flags so users only pull in what they need.

---

## Stage 1 — Crate Setup ✓ DONE

**Goal:** Convert the binary stub into a library.

**What was done:**
- Deleted `src/main.rs`
- Deleted `src/main.rs`
- Created `src/lib.rs` with module declarations for `result`, `principal`, `policy` (originally `error`; renamed to `result` in Stage 3)
- Created stub files: `src/result.rs`, `src/principal.rs`, `src/policy.rs`
- Added `description` and `license` fields to `Cargo.toml`
- No optional dependencies or feature flags added (deferred to their respective stages)

**`cargo check` passes.**

**Note:** Feature flags (`actix-web`, `tower`) and all optional/dev dependencies are added in Stages 4 and 5 when the code that requires them is written.

---

## Stage 2 — Core Traits and Types ✓ DONE

**Goal:** Define the `Principal` trait and the `LayeCheckResult` type. No framework dependencies.

**Files:** `src/result.rs`, `src/principal.rs`

**What was done:**
- Implemented `LayeCheckResult` enum in `src/result.rs` (originally `LayeError` in `src/error.rs`; renamed and restructured in Stage 3)
- Implemented `Principal` trait in `src/principal.rs` — object-safe, no generics
- Created `tests/principal.rs` with 8 passing tests, all asserts include failure messages

### `src/result.rs`
```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayeCheckResult {
    Authorized,
    Unauthorized,
    Forbidden,
}
```

### `src/principal.rs`
```rust
pub trait Principal {
    fn roles(&self) -> &[String];
    fn permissions(&self) -> &[String];
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

**File:** `tests/principal.rs` — 8 tests, all passing

```
has_role_returns_true_for_matching_role
has_role_returns_false_for_missing_role
has_role_returns_false_for_empty_roles
has_permission_returns_true_for_matching_permission
has_permission_returns_false_for_missing_permission
has_permission_returns_false_for_empty_permissions
is_authenticated_reflects_field
dyn_principal_coercion_compiles   // &user as &dyn Principal — verifies object safety
```

**`cargo check` and `cargo test` pass.**

---

## Stage 3 — Policy / Condition System ✓ DONE

**Goal:** Composable AND/OR access rules with support for nesting. No framework dependencies.

**Files:** `src/result.rs`, `src/policy.rs`

**What was done:**
- Replaced `LayeError` with `LayeCheckResult` in `src/result.rs` — a plain enum (no `thiserror`) with three variants; `src/error.rs` was renamed to `src/result.rs` and the module updated accordingly
- Implemented `AccessRule`, `AccessPolicy`, and internal `PolicyCheck`/`PolicyMode` types in `src/policy.rs`
- `check()` returns `LayeCheckResult` directly, not `Result<(), _>`
- Created `tests/policy.rs` with 21 passing tests
- `thiserror` dependency removed from `Cargo.toml` (zero dependencies in core)

### `src/result.rs`
```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayeCheckResult {
    Authorized,
    Unauthorized,
    Forbidden,
}
```

### `src/policy.rs`
```rust
pub type CustomFn = Arc<dyn Fn(Option<&dyn Principal>) -> bool + Send + Sync>;

#[derive(Clone)]
pub enum AccessRule {
    Role(String),
    NotRole(String),        // passes when principal lacks the role
    Permission(String),
    NotPermission(String),  // passes when principal lacks the permission
    Authenticated,
    Guest,   // passes for None OR is_authenticated() == false
    Custom(CustomFn),
}

#[derive(Clone)]
pub struct AccessPolicy {
    checks: Vec<PolicyCheck>,   // Rule | Nested(AccessPolicy)
    mode: PolicyMode,           // All (AND) | Any (OR)
}

impl AccessPolicy {
    pub fn require_all() -> Self { ... }
    pub fn require_any() -> Self { ... }
    pub fn add_rule(self, rule: AccessRule) -> Self { ... }
    pub fn add_policy(self, policy: AccessPolicy) -> Self { ... }
    pub fn check(&self, principal: Option<&dyn Principal>) -> LayeCheckResult { ... }
}
```

**`check` result rules:**
| Situation | Result |
|-----------|--------|
| Rule passes | `Authorized` |
| `principal` is `None` and auth needed | `Unauthorized` |
| Principal present but lacks role/permission | `Forbidden` |
| `Authenticated` rule, principal exists but `is_authenticated()` is false | `Unauthorized` |
| `Guest` rule, principal is authenticated | `Forbidden` |
| `NotRole`/`NotPermission`, principal is `None` | `Unauthorized` |
| `NotRole`/`NotPermission`, principal has the named role/permission | `Forbidden` |
| `NotRole`/`NotPermission`, principal lacks the named role/permission | `Authorized` |
| `require_any`, all checks fail, principal present | `Forbidden` |
| `require_any`, all checks fail, no principal | `Unauthorized` |

**Ergonomic helpers on `AccessPolicy`** (gated, live in `src/policy.rs`):
```rust
#[cfg(feature = "actix-web")]
pub fn into_actix_middleware<P: Principal + Clone + 'static>(self) -> actix::PolicyMiddlewareFactory<P>

#[cfg(feature = "tower")]
pub fn into_tower_layer<P: Principal + Clone + Send + Sync + 'static>(self) -> tower_middleware::AccessControlLayer<P>
```

### Stage 3 Tests

**File:** `tests/policy.rs` — 27 tests, all passing

```
// AccessRule::Role
role_rule_passes_for_matching_role
role_rule_fails_for_wrong_role
role_rule_fails_for_unauthenticated_returns_unauthorized

// AccessRule::Permission
permission_rule_passes_for_matching_permission
permission_rule_fails_for_wrong_permission

// AccessRule::Authenticated
authenticated_rule_passes_for_authenticated_principal
authenticated_rule_fails_returning_unauthorized_for_none
authenticated_rule_fails_returning_unauthenticated_for_unauthenticated_principal

// AccessRule::Guest
guest_rule_passes_for_none
guest_rule_passes_for_unauthenticated_principal
guest_rule_fails_for_authenticated_principal

// AccessRule::Custom
custom_rule_delegates_to_closure
custom_rule_receives_none_for_missing_principal

// AccessRule::NotRole / NotPermission
not_role_passes_when_principal_lacks_role
not_role_fails_when_principal_has_role
not_role_fails_for_missing_principal
not_permission_passes_when_principal_lacks_permission
not_permission_fails_when_principal_has_permission
absence_check_composes_with_presence_check

// AccessPolicy AND mode
require_all_passes_when_all_rules_pass
require_all_fails_when_any_rule_fails

// AccessPolicy OR mode
require_any_passes_when_one_rule_passes
require_any_fails_when_all_rules_fail

// Nesting
nested_policy_and_of_or_passes
nested_policy_or_of_and_fails_correctly

// Unauthorized vs Forbidden distinction
unauthenticated_request_yields_unauthorized_not_forbidden
authenticated_without_role_yields_forbidden_not_unauthorized
```

**`cargo check` and `cargo test` pass. 35 total tests (8 + 27).**

---

## Stage 4 — actix-web Middleware Helper (`feature = "actix-web"`) ✓ DONE

**Goal:** A `Transform` + `Service` middleware that reads a `P: Principal` from request extensions and enforces an `AccessPolicy`.

**Files:** `src/actix/mod.rs`, `src/actix/layer.rs`, `src/actix/extractor.rs`

**What was done:**
- Implemented `PolicyMiddlewareFactory<P>` and `PolicyMiddleware<S, P>` in `src/actix/layer.rs`
- Implemented `AuthPrincipal<P>` and `MaybeAuthPrincipal<P>` extractors in `src/actix/extractor.rs`
- Re-exported everything from `src/actix/mod.rs`
- Added `into_actix_middleware<P>()` convenience method on `AccessPolicy` (gated on `#[cfg(feature = "actix-web")]`)
- Created `tests/actix_middleware.rs` with 13 passing tests

### Middleware (`src/actix/layer.rs`)
```rust
pub struct PolicyMiddlewareFactory<P> {
    policy: AccessPolicy,
    _marker: PhantomData<P>,
}

// Implements actix_web::dev::Transform<S, ServiceRequest>
// Produces PolicyMiddleware<S, P>

pub struct PolicyMiddleware<S, P> {
    service: Rc<S>,
    policy: AccessPolicy,
    _marker: PhantomData<P>,
}

// Service::call:
//   1. reads req.extensions().get::<P>().cloned()
//   2. calls policy.check(principal.as_ref().map(|p| p as &dyn Principal))
//   3. Authorized    → forwards to inner service
//   4. Unauthorized  → ErrorUnauthorized ("Unauthorized")
//   5. Forbidden     → ErrorForbidden ("Forbidden")
```

`Future` type: `LocalBoxFuture<'static, ...>` (actix is single-threaded). Inner service wrapped in `Rc` to satisfy `'static` requirement in the future.

### Extractors (`src/actix/extractor.rs`)
```rust
pub struct AuthPrincipal<P>(pub P);              // 401 if missing from extensions
pub struct MaybeAuthPrincipal<P>(pub Option<P>); // never fails

// Both implement FromRequest, cloning P out of request extensions
```

**Design notes:**
- Users insert `P` into extensions via their own global auth middleware (e.g. a JWT decode layer). `laye` only reads it — no opinion on token format or DB.
- `ErrorUnauthorized` / `ErrorForbidden` use actix's built-in helpers; body is a plain string.
- `P: Clone` is required so the extractor can hand ownership to the handler without consuming the extension map.

### Stage 4 Tests

**File:** `tests/actix_middleware.rs` — 13 tests, all passing (requires `#[cfg(feature = "actix-web")]`)

Uses `actix_web::test::{init_service, call_service, TestRequest}` to spin up a minimal `App`. Extensions are inserted via `wrap_fn`.

```
middleware_allows_request_when_policy_passes
// → admin TestUser in extensions, Role("admin") policy → 200

middleware_returns_403_when_role_missing
// → TestUser with no roles, Role("admin") policy → 403

middleware_returns_401_when_no_principal_in_extensions
// → no extension, Authenticated policy → 401

auth_principal_extractor_injects_principal_into_handler
// → AuthPrincipal<TestUser> received in handler, asserts has_role("user") → 200

auth_principal_extractor_returns_401_when_missing
// → no extension, AuthPrincipal extractor used → 401

maybe_auth_principal_returns_some_when_present
// → extension present, MaybeAuthPrincipal is Some → 200

maybe_auth_principal_returns_none_when_absent
// → no extension, Guest policy, MaybeAuthPrincipal is None → 200

and_policy_blocks_when_one_condition_fails
// → Authenticated + Role("admin"), user only has "user" role → 403

or_policy_allows_when_one_condition_passes
// → Role("admin") | Role("editor"), user has "editor" → 200

not_role_allows_user_without_banned_role
// → Authenticated + NotRole("banned"), user has "editor" only → 200

not_role_blocks_user_with_banned_role
// → Authenticated + NotRole("banned"), user has "editor" + "banned" → 403

not_permission_allows_user_without_restricted_permission
// → Authenticated + NotPermission("delete"), user has "read" only → 200

not_permission_blocks_user_with_restricted_permission
// → Authenticated + NotPermission("delete"), user has "read" + "delete" → 403
```

**`cargo test --features actix-web` passes. 48 total tests (8 + 27 + 13).**

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
