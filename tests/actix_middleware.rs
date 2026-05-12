#![cfg(feature = "actix-web")]

use actix_web::dev::Service;
use actix_web::test::{call_service, init_service, TestRequest};
use actix_web::{web, App, HttpMessage, HttpResponse};

use laye::actix::{AuthPrincipal, MaybeAuthPrincipal};
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

#[actix_web::test]
async fn middleware_allows_request_when_policy_passes() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Role("admin".into()));
    let user = TestUser::new(&["admin"]);
    let app = init_service(
        App::new()
            .wrap(policy.into_actix_middleware::<TestUser>())
            .wrap_fn(move |req, srv| {
                req.extensions_mut().insert(user.clone());
                srv.call(req)
            })
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;
    let res = call_service(&app, TestRequest::get().uri("/").to_request()).await;
    assert_eq!(res.status(), 200, "admin should get 200");
}

#[actix_web::test]
async fn middleware_returns_403_when_role_missing() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Role("admin".into()));
    let user = TestUser::new(&[]);
    let app = init_service(
        App::new()
            .wrap(policy.into_actix_middleware::<TestUser>())
            .wrap_fn(move |req, srv| {
                req.extensions_mut().insert(user.clone());
                srv.call(req)
            })
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;
    let res = call_service(&app, TestRequest::get().uri("/").to_request()).await;
    assert_eq!(res.status(), 403, "missing role should get 403");
}

#[actix_web::test]
async fn middleware_returns_401_when_no_principal_in_extensions() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Authenticated);
    let app = init_service(
        App::new()
            .wrap(policy.into_actix_middleware::<TestUser>())
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;
    let res = call_service(&app, TestRequest::get().uri("/").to_request()).await;
    assert_eq!(res.status(), 401, "no principal should get 401");
}

#[actix_web::test]
async fn auth_principal_extractor_injects_principal_into_handler() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Authenticated);
    let user = TestUser::new(&["user"]);
    let app = init_service(
        App::new()
            .wrap(policy.into_actix_middleware::<TestUser>())
            .wrap_fn(move |req, srv| {
                req.extensions_mut().insert(user.clone());
                srv.call(req)
            })
            .route(
                "/",
                web::get().to(|p: AuthPrincipal<TestUser>| async move {
                    assert!(p.0.has_role("user"), "extracted user should have 'user' role");
                    HttpResponse::Ok().finish()
                }),
            ),
    )
    .await;
    let res = call_service(&app, TestRequest::get().uri("/").to_request()).await;
    assert_eq!(res.status(), 200, "handler should receive principal and return 200");
}

#[actix_web::test]
async fn auth_principal_extractor_returns_401_when_missing() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Guest);
    let app = init_service(
        App::new()
            .wrap(policy.into_actix_middleware::<TestUser>())
            .route(
                "/",
                web::get()
                    .to(|_: AuthPrincipal<TestUser>| async { HttpResponse::Ok().finish() }),
            ),
    )
    .await;
    let res = call_service(&app, TestRequest::get().uri("/").to_request()).await;
    assert_eq!(res.status(), 401, "missing principal in extractor should return 401");
}

#[actix_web::test]
async fn maybe_auth_principal_returns_some_when_present() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Authenticated);
    let user = TestUser::new(&[]);
    let app = init_service(
        App::new()
            .wrap(policy.into_actix_middleware::<TestUser>())
            .wrap_fn(move |req, srv| {
                req.extensions_mut().insert(user.clone());
                srv.call(req)
            })
            .route(
                "/",
                web::get().to(|m: MaybeAuthPrincipal<TestUser>| async move {
                    assert!(m.0.is_some(), "MaybeAuthPrincipal should be Some when extension present");
                    HttpResponse::Ok().finish()
                }),
            ),
    )
    .await;
    let res = call_service(&app, TestRequest::get().uri("/").to_request()).await;
    assert_eq!(res.status(), 200, "should succeed");
}

#[actix_web::test]
async fn maybe_auth_principal_returns_none_when_absent() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Guest);
    let app = init_service(
        App::new()
            .wrap(policy.into_actix_middleware::<TestUser>())
            .route(
                "/",
                web::get().to(|m: MaybeAuthPrincipal<TestUser>| async move {
                    assert!(m.0.is_none(), "MaybeAuthPrincipal should be None when no extension");
                    HttpResponse::Ok().finish()
                }),
            ),
    )
    .await;
    let res = call_service(&app, TestRequest::get().uri("/").to_request()).await;
    assert_eq!(res.status(), 200, "guest route with no principal should succeed");
}

#[actix_web::test]
async fn and_policy_blocks_when_one_condition_fails() {
    let policy = AccessPolicy::require_all()
        .add_rule(AccessRule::Authenticated)
        .add_rule(AccessRule::Role("admin".into()));
    let user = TestUser::new(&["user"]);
    let app = init_service(
        App::new()
            .wrap(policy.into_actix_middleware::<TestUser>())
            .wrap_fn(move |req, srv| {
                req.extensions_mut().insert(user.clone());
                srv.call(req)
            })
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;
    let res = call_service(&app, TestRequest::get().uri("/").to_request()).await;
    assert_eq!(res.status(), 403, "AND policy should block when role condition fails");
}

#[actix_web::test]
async fn or_policy_allows_when_one_condition_passes() {
    let policy = AccessPolicy::require_any()
        .add_rule(AccessRule::Role("admin".into()))
        .add_rule(AccessRule::Role("editor".into()));
    let user = TestUser::new(&["editor"]);
    let app = init_service(
        App::new()
            .wrap(policy.into_actix_middleware::<TestUser>())
            .wrap_fn(move |req, srv| {
                req.extensions_mut().insert(user.clone());
                srv.call(req)
            })
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;
    let res = call_service(&app, TestRequest::get().uri("/").to_request()).await;
    assert_eq!(res.status(), 200, "OR policy should allow when one role matches");
}
