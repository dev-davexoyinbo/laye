use std::future::ready;
use std::marker::PhantomData;
use std::task::{Context, Poll};

use futures_util::future::Either;
use http::{Request, Response, StatusCode};
use tower::{Layer, Service};

use crate::{policy::AccessPolicy, principal::Principal, result::LayeCheckResult};

/// tower `Layer` that enforces an [`AccessPolicy`](crate::AccessPolicy) on every request.
///
/// Produced by [`AccessPolicy::into_tower_layer`](crate::AccessPolicy::into_tower_layer).
/// Apply it to an axum route or any tower service with `.layer(layer)`.
///
/// Requests are short-circuited with **401** when no principal is found in extensions, or
/// **403** when the principal fails the policy. The inner service is not called in either case.
#[derive(Clone)]
pub struct AccessControlLayer<P> {
    policy: AccessPolicy,
    _marker: PhantomData<fn(P)>,
}

impl<P> AccessControlLayer<P> {
    /// Creates a new layer wrapping `policy`.
    pub fn new(policy: AccessPolicy) -> Self {
        Self {
            policy,
            _marker: PhantomData,
        }
    }
}

impl<S, P> Layer<S> for AccessControlLayer<P> {
    type Service = AccessControlService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        AccessControlService {
            inner,
            policy: self.policy.clone(),
            _marker: PhantomData,
        }
    }
}

/// tower `Service` produced by [`AccessControlLayer`].
///
/// You do not construct this directly — it is returned by [`AccessControlLayer`]'s `Layer` impl.
/// `ResBody: Default` is required so rejection responses can be constructed without invoking
/// the inner service.
#[derive(Clone)]
pub struct AccessControlService<S, P> {
    inner: S,
    policy: AccessPolicy,
    _marker: PhantomData<fn(P)>,
}

impl<S, P, ReqBody, ResBody> Service<Request<ReqBody>> for AccessControlService<S, P>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    P: Principal + Clone + Send + Sync + 'static,
    ResBody: Default,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Either<S::Future, std::future::Ready<Result<Response<ResBody>, S::Error>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let principal = req.extensions().get::<P>().cloned();
        let result = self
            .policy
            .check(principal.as_ref().map(|p| p as &dyn Principal));

        match result {
            LayeCheckResult::Authorized => Either::Left(self.inner.call(req)),
            LayeCheckResult::Unauthorized => {
                let mut res = Response::new(ResBody::default());
                *res.status_mut() = StatusCode::UNAUTHORIZED;
                Either::Right(ready(Ok(res)))
            }
            LayeCheckResult::Forbidden => {
                let mut res = Response::new(ResBody::default());
                *res.status_mut() = StatusCode::FORBIDDEN;
                Either::Right(ready(Ok(res)))
            }
        }
    }
}
