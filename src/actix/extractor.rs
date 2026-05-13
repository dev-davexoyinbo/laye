use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpMessage, HttpRequest};
use std::future::{Ready, ready};

use crate::principal::Principal;

/// actix-web extractor that resolves a `P: Principal` from request extensions.
///
/// Returns **401 Unauthorized** if `P` is not present in extensions. Your own upstream auth
/// middleware must call `req.extensions_mut().insert(p)` before using this extractor —
/// see [`crate::actix`] for the setup guide.
///
/// Access the inner value via `.0` or [`into_inner`](Self::into_inner).
///
/// # Examples
///
/// ```no_run
/// use actix_web::HttpResponse;
/// use laye::actix::AuthPrincipal;
/// use laye::Principal;
///
/// #[derive(Clone)]
/// struct MyUser { name: String, roles: Vec<String>, permissions: Vec<String> }
/// impl Principal for MyUser {
///     fn roles(&self) -> &[String] { &self.roles }
///     fn permissions(&self) -> &[String] { &self.permissions }
///     fn is_authenticated(&self) -> bool { true }
/// }
///
/// async fn handler(user: AuthPrincipal<MyUser>) -> HttpResponse {
///     HttpResponse::Ok().body(format!("Hello, {}", user.0.name))
/// }
/// ```
pub struct AuthPrincipal<P>(
    /// The extracted principal.
    pub P,
);

impl<P> AuthPrincipal<P> {
    /// Unwraps the inner principal.
    pub fn into_inner(self) -> P {
        self.0
    }
}

impl<P> FromRequest for AuthPrincipal<P>
where
    P: Principal + Clone + 'static,
{
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match req.extensions().get::<P>().cloned() {
            Some(p) => ready(Ok(AuthPrincipal(p))),
            None => ready(Err(actix_web::error::ErrorUnauthorized("Unauthorized"))),
        }
    }
}

/// actix-web extractor that resolves an optional `P: Principal` from request extensions.
///
/// Unlike [`AuthPrincipal`], this extractor never fails — it yields `None` when `P` is absent
/// in extensions. Use it on routes that serve both authenticated and anonymous users.
///
/// Access the inner value via `.0` or [`into_inner`](Self::into_inner).
pub struct MaybeAuthPrincipal<P>(
    /// The principal, or `None` if not present in request extensions.
    pub Option<P>,
);

impl<P> MaybeAuthPrincipal<P> {
    /// Unwraps the inner `Option<P>`.
    pub fn into_inner(self) -> Option<P> {
        self.0
    }
}

impl<P> FromRequest for MaybeAuthPrincipal<P>
where
    P: Principal + Clone + 'static,
{
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(Ok(MaybeAuthPrincipal(req.extensions().get::<P>().cloned())))
    }
}
