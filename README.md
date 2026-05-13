[![Crates.io](https://img.shields.io/crates/v/laye)](https://crates.io/crates/laye)
[![docs.rs](https://img.shields.io/docsrs/laye)](https://docs.rs/laye)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# laye

A framework-agnostic role- and permission-based access control (RBAC) library for Rust.

Build composable `AccessPolicy` rules, implement `Principal` on your auth type, and wire
the provided middleware into actix-web or axum (tower). Authentication — decoding tokens,
querying the database — is entirely outside `laye`'s scope.

## Feature flags

| Feature | What it adds |
|---------|-------------|
| `actix-web` | `laye::actix` module: `PolicyMiddlewareFactory`, `AuthPrincipal`, `MaybeAuthPrincipal` |
| `tower` | `laye::tower_middleware` module: `AccessControlLayer` |

```toml
# Core only
laye = "0.1"

# With actix-web support
laye = { version = "0.1", features = ["actix-web"] }

# With axum / tower support
laye = { version = "0.1", features = ["tower"] }
```

## How it works

1. **Implement `Principal`** on your auth info struct (decoded JWT payload, session data, etc.).
2. **Build an `AccessPolicy`** with `require_all` (AND) or `require_any` (OR), chaining `AccessRule`s and nested sub-policies.
3. **Insert your principal into request extensions** from your own upstream auth middleware — *before* `laye` runs.
4. **Apply a `laye` middleware / layer.** It reads `P` from extensions and evaluates the policy,
   returning **401 Unauthorized** when no principal is found or **403 Forbidden** when the principal fails the policy.

## Quick start

### Implement `Principal`

```rust
use laye::Principal;

#[derive(Clone)]
struct MyUser {
    roles: Vec<String>,
    permissions: Vec<String>,
    authenticated: bool,
}

impl Principal for MyUser {
    fn roles(&self) -> &[String] { &self.roles }
    fn permissions(&self) -> &[String] { &self.permissions }
    fn is_authenticated(&self) -> bool { self.authenticated }
}
```

### Build and evaluate a policy

```rust
use laye::{AccessPolicy, AccessRule, LayeCheckResult};

// Require authenticated AND (role "admin" OR role "editor")
let policy = AccessPolicy::require_all()
    .add_rule(AccessRule::Authenticated)
    .add_policy(
        AccessPolicy::require_any()
            .add_rule(AccessRule::Role("admin".into()))
            .add_rule(AccessRule::Role("editor".into())),
    );

let editor = MyUser { roles: vec!["editor".into()], permissions: vec![], authenticated: true };
let viewer = MyUser { roles: vec!["viewer".into()], permissions: vec![], authenticated: true };

assert_eq!(policy.check(Some(&editor)), LayeCheckResult::Authorized);
assert_eq!(policy.check(Some(&viewer)), LayeCheckResult::Forbidden);
assert_eq!(policy.check(None),          LayeCheckResult::Unauthorized);
```

## actix-web integration

```toml
laye = { version = "0.1", features = ["actix-web"] }
```

```rust
use actix_web::{web, App, HttpServer, HttpMessage, HttpResponse};
use laye::{AccessPolicy, AccessRule, Principal};
use laye::actix::AuthPrincipal;

#[derive(Clone)]
struct MyUser {
    id: u64,
    roles: Vec<String>,
    permissions: Vec<String>,
}

impl Principal for MyUser {
    fn roles(&self) -> &[String] { &self.roles }
    fn permissions(&self) -> &[String] { &self.permissions }
    fn is_authenticated(&self) -> bool { true }
}

async fn admin_handler(user: AuthPrincipal<MyUser>) -> HttpResponse {
    HttpResponse::Ok().body(format!("id={}", user.0.id))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let admin_policy = AccessPolicy::require_all()
        .add_rule(AccessRule::Authenticated)
        .add_rule(AccessRule::Role("admin".into()));

    HttpServer::new(move || {
        App::new()
            // Step 1: Your auth middleware — decode the token and insert the principal.
            // Without this step every request returns 401, regardless of headers.
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(MyUser {
                    id: 1,
                    roles: vec!["admin".to_string()],
                    permissions: vec![],
                });
                srv.call(req)
            })
            // Step 2: laye checks the policy against the inserted principal.
            .service(
                web::scope("/admin")
                    .wrap(admin_policy.clone().into_actix_middleware::<MyUser>())
                    .route("", web::get().to(admin_handler)),
            )
            .route("/public", web::get().to(|| async { HttpResponse::Ok().body("public") }))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## axum / tower integration

```toml
laye = { version = "0.1", features = ["tower"] }
```

```rust
use axum::{Router, routing::get, middleware, response::IntoResponse};
use laye::{AccessPolicy, AccessRule, Principal};

#[derive(Clone)]
struct MyUser {
    id: u64,
    roles: Vec<String>,
    permissions: Vec<String>,
}

impl Principal for MyUser {
    fn roles(&self) -> &[String] { &self.roles }
    fn permissions(&self) -> &[String] { &self.permissions }
    fn is_authenticated(&self) -> bool { true }
}

// Step 1: Your auth middleware — decode the token and insert the principal.
// Without this step every request to a guarded route returns 401.
async fn load_user(mut req: axum::extract::Request, next: middleware::Next) -> impl IntoResponse {
    req.extensions_mut().insert(MyUser {
        id: 1,
        roles: vec!["admin".to_string()],
        permissions: vec![],
    });
    next.run(req).await
}

async fn admin_handler() -> &'static str { "Hello, admin!" }

#[tokio::main]
async fn main() {
    let policy = AccessPolicy::require_all()
        .add_rule(AccessRule::Authenticated)
        .add_rule(AccessRule::Role("admin".into()));

    let app = Router::new()
        .route(
            "/admin",
            // Step 2: laye checks the policy against the inserted principal.
            get(admin_handler).layer(policy.into_tower_layer::<MyUser>()),
        )
        .route("/public", get(|| async { "public" }))
        .layer(middleware::from_fn(load_user));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## License

MIT — see [LICENSE](LICENSE).
