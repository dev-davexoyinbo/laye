use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpMessage, HttpRequest};
use std::future::{Ready, ready};

use crate::principal::Principal;

pub struct AuthPrincipal<P>(pub P);

impl<P> AuthPrincipal<P> {
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

pub struct MaybeAuthPrincipal<P>(pub Option<P>);

impl<P> MaybeAuthPrincipal<P> {
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
