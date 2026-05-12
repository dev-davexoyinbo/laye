use std::future::{Future, Ready, ready};
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::{HttpMessage, HttpResponse};

use crate::policy::AccessPolicy;
use crate::principal::Principal;
use crate::result::LayeCheckResult;

pub struct PolicyMiddlewareFactory<P> {
    policy: AccessPolicy,
    _marker: PhantomData<P>,
}

impl<P> PolicyMiddlewareFactory<P> {
    pub fn new(policy: AccessPolicy) -> Self {
        Self {
            policy,
            _marker: PhantomData,
        }
    }
}

impl<S, B, P> Transform<S, ServiceRequest> for PolicyMiddlewareFactory<P>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
    P: Principal + Clone + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Transform = PolicyMiddlewareService<S, P>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(PolicyMiddlewareService {
            service: Rc::new(service),
            policy: self.policy.clone(),
            _marker: PhantomData,
        }))
    }
}

pub struct PolicyMiddlewareService<S, P> {
    service: Rc<S>,
    policy: AccessPolicy,
    _marker: PhantomData<P>,
}

impl<S, B, P> Service<ServiceRequest> for PolicyMiddlewareService<S, P>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
    P: Principal + Clone + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let principal = req.extensions().get::<P>().cloned();

        let result = self
            .policy
            .check(principal.as_ref().map(|p| p as &dyn Principal));

        let svc = Rc::clone(&self.service);

        Box::pin(async move {
            match result {
                LayeCheckResult::Authorized => {
                    svc.call(req).await.map(ServiceResponse::map_into_left_body)
                }
                LayeCheckResult::Unauthorized => {
                    let res = HttpResponse::Unauthorized().finish();
                    Ok(req.into_response(res).map_into_right_body())
                }
                LayeCheckResult::Forbidden => {
                    let res = HttpResponse::Forbidden().finish();
                    Ok(req.into_response(res).map_into_right_body())
                }
            }
        })
    }
}
