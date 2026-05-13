//! tower / axum middleware for `laye`.
//!
//! ## Setup
//!
//! `laye`'s layer reads a `P: Principal` from request extensions. It **does not** insert it.
//! You must run your own upstream middleware that decodes the token (or loads the session) and
//! calls `req.extensions_mut().insert(my_user)` **before** the `laye` layer runs. Without this
//! step every guarded request returns **401 Unauthorized** regardless of what the client sends.
//!
//! In axum, apply `middleware::from_fn(load_user)` at the `Router` level so it runs around all
//! routes, and apply the `laye` layer only on the routes that need protection:
//!
//! ```no_run
//! use axum::{Router, routing::get, middleware, response::IntoResponse};
//! use laye::{AccessPolicy, AccessRule, Principal};
//!
//! #[derive(Clone)]
//! struct MyUser { roles: Vec<String>, permissions: Vec<String> }
//!
//! impl Principal for MyUser {
//!     fn roles(&self) -> &[String] { &self.roles }
//!     fn permissions(&self) -> &[String] { &self.permissions }
//!     fn is_authenticated(&self) -> bool { true }
//! }
//!
//! // Step 1: Your auth middleware — decode the token and insert the principal.
//! async fn load_user(
//!     mut req: axum::extract::Request,
//!     next: middleware::Next,
//! ) -> impl IntoResponse {
//!     req.extensions_mut().insert(MyUser {
//!         roles: vec!["admin".to_string()],
//!         permissions: vec![],
//!     });
//!     next.run(req).await
//! }
//!
//! async fn admin_handler() -> &'static str { "Hello, admin!" }
//!
//! # #[tokio::main]
//! # async fn main() {
//! let policy = AccessPolicy::require_all()
//!     .add_rule(AccessRule::Role("admin".into()));
//!
//! let app = Router::new()
//!     .route(
//!         "/admin",
//!         // Step 2: laye checks the policy against the inserted principal.
//!         get(admin_handler).layer(policy.into_tower_layer::<MyUser>()),
//!     )
//!     .layer(middleware::from_fn(load_user));
//!
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
//! axum::serve(listener, app).await.unwrap();
//! # }
//! ```
//!
//! ## `ResBody: Default` requirement
//!
//! [`AccessControlService`]'s `Service` impl requires `ResBody: Default` to construct rejection
//! responses (401 / 403) without calling the inner service. `axum::body::Body` satisfies this.
//! If you use a custom body type, implement `Default` for it or open an issue.

mod layer;
pub use layer::{AccessControlLayer, AccessControlService};
