//! actix-web middleware and extractors for `laye`.
//!
//! ## Setup
//!
//! `laye`'s middleware reads a `P: Principal` from request extensions. It **does not** insert it.
//! You must run your own upstream auth middleware that decodes the token (or loads the session)
//! and calls `req.extensions_mut().insert(my_user)` **before** the `laye` middleware runs.
//! Without this step every guarded request returns **401 Unauthorized** regardless of what the
//! client sends.
//!
//! ## Extractors
//!
//! Once the principal is in extensions, handlers can receive it directly as a function argument
//! without going through extensions manually.
//!
//! ### [`AuthPrincipal<P>`](AuthPrincipal)
//!
//! Resolves `P` from extensions and injects it into the handler. Returns **401** automatically
//! if `P` is absent — no manual check needed.
//!
//! ```no_run
//! use actix_web::HttpResponse;
//! use laye::actix::AuthPrincipal;
//! use laye::Principal;
//!
//! #[derive(Clone)]
//! struct MyUser { id: u64, roles: Vec<String>, permissions: Vec<String> }
//! impl Principal for MyUser {
//!     fn roles(&self) -> &[String] { &self.roles }
//!     fn permissions(&self) -> &[String] { &self.permissions }
//!     fn is_authenticated(&self) -> bool { true }
//! }
//!
//! async fn profile(user: AuthPrincipal<MyUser>) -> HttpResponse {
//!     // user.0 is your MyUser value; user.into_inner() does the same.
//!     HttpResponse::Ok().body(format!("id={}", user.0.id))
//! }
//! ```
//!
//! ### [`MaybeAuthPrincipal<P>`](MaybeAuthPrincipal)
//!
//! Like [`AuthPrincipal`] but never fails — yields `None` when `P` is absent. Use this on
//! routes that serve both authenticated and anonymous users and branch on presence.
//!
//! ```no_run
//! use actix_web::HttpResponse;
//! use laye::actix::MaybeAuthPrincipal;
//! use laye::Principal;
//!
//! #[derive(Clone)]
//! struct MyUser { name: String, roles: Vec<String>, permissions: Vec<String> }
//! impl Principal for MyUser {
//!     fn roles(&self) -> &[String] { &self.roles }
//!     fn permissions(&self) -> &[String] { &self.permissions }
//!     fn is_authenticated(&self) -> bool { true }
//! }
//!
//! async fn home(user: MaybeAuthPrincipal<MyUser>) -> HttpResponse {
//!     match user.into_inner() {
//!         Some(u) => HttpResponse::Ok().body(format!("Welcome back, {}!", u.name)),
//!         None    => HttpResponse::Ok().body("Hello, guest!"),
//!     }
//! }
//! ```
//!
//! Both extractors clone `P` out of extensions (`P: Clone` is required and enforced by the
//! `FromRequest` bound). The extractor works independently of the `laye` middleware — you can
//! use it on any route as long as your upstream auth middleware has inserted the principal.
//!
//! ## Middleware ordering
//!
//! In actix-web, a middleware added with `.wrap()` **later** in the builder wraps around the
//! previous layers, meaning it runs **first** on incoming requests. The auth `wrap_fn` should
//! therefore be added **after** the laye middleware:
//!
//! ```no_run
//! use actix_web::dev::Service;
//! use actix_web::{web, App, HttpServer, HttpMessage, HttpResponse};
//! use laye::{AccessPolicy, AccessRule, Principal};
//! use laye::actix::AuthPrincipal;
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
//! async fn handler(user: AuthPrincipal<MyUser>) -> HttpResponse {
//!     HttpResponse::Ok().body(format!("roles: {:?}", user.0.roles))
//! }
//!
//! # #[actix_web::main]
//! # async fn main() -> std::io::Result<()> {
//! let policy = AccessPolicy::require_all()
//!     .add_rule(AccessRule::Role("admin".into()));
//!
//! HttpServer::new(move || {
//!     App::new()
//!         // Step 2 in code = step 1 at runtime: laye checks the policy.
//!         .service(
//!             web::scope("/admin")
//!                 .wrap(policy.clone().into_actix_middleware::<MyUser>())
//!                 .route("", web::get().to(handler)),
//!         )
//!         // Step 1 in code = last to wrap = first to run: insert the principal.
//!         .wrap_fn(|req, srv| {
//!             req.extensions_mut().insert(MyUser {
//!                 roles: vec!["admin".to_string()],
//!                 permissions: vec![],
//!             });
//!             srv.call(req)
//!         })
//! })
//! .bind("127.0.0.1:8080")?
//! .run()
//! .await
//! # }
//! ```

mod extractor;
mod middleware;

pub use extractor::{AuthPrincipal, MaybeAuthPrincipal};
pub use middleware::PolicyMiddlewareFactory;
