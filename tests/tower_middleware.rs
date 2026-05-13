#![cfg(feature = "tower")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{body::Body, routing::get, Router};
use http::{Request, StatusCode};
use tower::ServiceExt;

use laye::principal::Principal;
use laye::{AccessPolicy, AccessRule};

#[derive(Clone)]
struct TestUser {
    roles: Vec<String>,
    permissions: Vec<String>,
    authenticated: bool,
}

impl TestUser {
    fn new(roles: &[&str]) -> Self {
        Self {
            roles: roles.iter().map(|s| s.to_string()).collect(),
            permissions: vec![],
            authenticated: true,
        }
    }
}

impl Principal for TestUser {
    fn roles(&self) -> &[String] {
        &self.roles
    }
    fn permissions(&self) -> &[String] {
        &self.permissions
    }
    fn is_authenticated(&self) -> bool {
        self.authenticated
    }
}

fn make_app(policy: AccessPolicy) -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(policy.into_tower_layer::<TestUser>())
}

fn make_req(user: Option<TestUser>) -> Request<Body> {
    let mut req = Request::builder()
        .uri("/")
        .body(Body::empty())
        .unwrap();
    if let Some(u) = user {
        req.extensions_mut().insert(u);
    }
    req
}

#[tokio::test]
async fn layer_allows_request_when_policy_passes() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Role("admin".into()));
    let res = make_app(policy)
        .oneshot(make_req(Some(TestUser::new(&["admin"]))))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "admin should get 200");
}

#[tokio::test]
async fn layer_returns_403_when_role_missing() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Role("admin".into()));
    let res = make_app(policy)
        .oneshot(make_req(Some(TestUser::new(&[]))))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "missing role should get 403");
}

#[tokio::test]
async fn layer_returns_401_when_no_principal_in_extensions() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Authenticated);
    let res = make_app(policy)
        .oneshot(make_req(None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no principal should get 401");
}

#[tokio::test]
async fn layer_short_circuits_without_calling_inner_service_on_rejection() {
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();

    let policy = AccessPolicy::require_all().add_rule(AccessRule::Authenticated);
    let app = Router::new()
        .route(
            "/",
            get(move || {
                called_clone.store(true, Ordering::SeqCst);
                async { "ok" }
            }),
        )
        .layer(policy.into_tower_layer::<TestUser>());

    let res = app.oneshot(make_req(None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no principal should get 401");
    assert!(!called.load(Ordering::SeqCst), "handler should not have been called");
}

#[tokio::test]
async fn and_policy_blocks_when_one_condition_fails() {
    let policy = AccessPolicy::require_all()
        .add_rule(AccessRule::Authenticated)
        .add_rule(AccessRule::Role("admin".into()));
    let res = make_app(policy)
        .oneshot(make_req(Some(TestUser::new(&["user"]))))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "AND policy should block when role fails");
}

#[tokio::test]
async fn or_policy_allows_when_one_condition_passes() {
    let policy = AccessPolicy::require_any()
        .add_rule(AccessRule::Role("admin".into()))
        .add_rule(AccessRule::Role("editor".into()));
    let res = make_app(policy)
        .oneshot(make_req(Some(TestUser::new(&["editor"]))))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "OR policy should allow when one role matches");
}

#[tokio::test]
async fn layer_is_clone_and_send() {
    fn assert_send<T: Send>(_: T) {}
    fn assert_clone<T: Clone>(_: T) {}

    let policy = AccessPolicy::require_all().add_rule(AccessRule::Authenticated);
    let layer = policy.into_tower_layer::<TestUser>();
    assert_send(layer.clone());
    assert_clone(layer);
}
