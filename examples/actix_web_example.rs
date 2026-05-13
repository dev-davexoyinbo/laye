use actix_web::dev::Service;
use actix_web::{web, App, HttpMessage, HttpResponse, HttpServer};
use laye::actix::AuthPrincipal;
use laye::principal::Principal;
use laye::{AccessPolicy, AccessRule};

#[derive(Clone, Debug)]
struct MyUser {
    id: u64,
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

async fn admin_handler(user: AuthPrincipal<MyUser>) -> HttpResponse {
    HttpResponse::Ok().body(format!("Hello admin! id={}", user.0.id))
}

async fn public_handler() -> HttpResponse {
    HttpResponse::Ok().body("Public page — no auth required")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let admin_policy = AccessPolicy::require_all()
        .add_rule(AccessRule::Authenticated)
        .add_rule(AccessRule::Role("admin".to_string()));

    println!("Listening on http://127.0.0.1:8080");
    println!("  GET /public  → 200 (no auth)");
    println!("  GET /admin   → 200 with admin role, 403 otherwise, 401 if no principal");

    HttpServer::new(move || {
        App::new()
            // Step 1: Your auth middleware — decode the token and insert the principal.
            // Without this step every guarded request returns 401, regardless of headers sent.
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(MyUser {
                    id: 42,
                    roles: vec!["admin".to_string()],
                    permissions: vec!["posts:write".to_string()],
                });
                srv.call(req)
            })
            .route("/public", web::get().to(public_handler))
            // Step 2: laye checks the policy against the inserted principal.
            .service(
                web::scope("/admin")
                    .wrap(admin_policy.clone().into_actix_middleware::<MyUser>())
                    .route("", web::get().to(admin_handler)),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
