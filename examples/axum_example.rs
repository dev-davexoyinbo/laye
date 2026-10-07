use axum::{Router, middleware, response::IntoResponse, routing::get};
use bytes::Bytes;
use http::{Response, StatusCode, header};
use laye::principal::Principal;
use laye::{AccessPolicy, AccessRule, LayeDenial};

#[derive(Clone, Debug)]
struct MyUser {
    roles: Vec<String>,
    permissions: Vec<String>,
}

impl Principal for MyUser {
    fn roles(&self) -> &[String] {
        &self.roles
    }
    fn permissions(&self) -> &[String] {
        &self.permissions
    }
    fn is_authenticated(&self) -> bool {
        true
    }
}

// Step 1: Your auth middleware — decode the token and insert the principal.
// Without this step every guarded request returns 401, regardless of headers sent.
async fn load_user(mut req: axum::extract::Request, next: middleware::Next) -> impl IntoResponse {
    req.extensions_mut().insert(MyUser {
        roles: vec!["admin".to_string()],
        permissions: vec!["posts:write".to_string()],
    });
    next.run(req).await
}

async fn admin_handler() -> &'static str {
    "Hello, admin!"
}

async fn public_handler() -> &'static str {
    "Public page — no auth required"
}

#[tokio::main]
async fn main() {
    let admin_policy = AccessPolicy::require_all()
        .add_rule(AccessRule::Authenticated)
        .add_rule(AccessRule::Role("admin".to_string()));

    let app = Router::new()
        .route("/public", get(public_handler))
        // Step 2: laye checks the policy against the inserted principal.
        .route(
            "/admin",
            get(admin_handler).layer(
                admin_policy
                    .into_tower_layer::<MyUser>()
                    // Optional: render denials with your API's own body shape instead of
                    // the default empty 401/403.
                    .error_handler(|denial| {
                        let (status, message) = match denial {
                            LayeDenial::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
                            LayeDenial::Forbidden => (StatusCode::FORBIDDEN, "Forbidden"),
                        };

                        Response::builder()
                            .status(status)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Bytes::from(format!("{{\"message\":\"{message}\"}}")))
                            .expect("valid response")
                    }),
            ),
        )
        .layer(middleware::from_fn(load_user));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    println!("Listening on http://127.0.0.1:3000");
    println!("  GET /public  → 200 (no auth)");
    println!("  GET /admin   → 200 with admin role, 403 otherwise, 401 if no principal");

    axum::serve(listener, app).await.unwrap();
}
