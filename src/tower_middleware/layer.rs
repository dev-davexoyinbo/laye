use std::future::ready;
use std::marker::PhantomData;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::future::Either;
use http::{Request, Response, StatusCode};
use tower::{Layer, Service};

use crate::result::LayeDenial;
use crate::{policy::AccessPolicy, principal::Principal, result::LayeCheckResult};

type ErrorHandler = Arc<dyn Fn(LayeDenial) -> Response<Bytes> + Send + Sync>;

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
    error_handler: Option<ErrorHandler>,
    _marker: PhantomData<fn(P)>,
}

impl<P> AccessControlLayer<P> {
    /// Creates a new layer wrapping `policy`.
    pub fn new(policy: AccessPolicy) -> Self {
        Self {
            policy,
            error_handler: None,
            _marker: PhantomData,
        }
    }

    /// Build denial responses yourself instead of the default empty `401`/`403`, so they carry
    /// the same body shape as the rest of your API. The response's body bytes are converted
    /// into the service's body type through `ResBody: From<Bytes>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use bytes::Bytes;
    /// use http::{Response, StatusCode, header};
    /// use laye::{AccessPolicy, AccessRule, LayeDenial};
    ///
    /// let layer = AccessPolicy::require_all()
    ///     .add_rule(AccessRule::Authenticated)
    ///     .into_tower_layer::<MyUser>()
    ///     .error_handler(|denial| {
    ///         let (status, message) = match denial {
    ///             LayeDenial::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
    ///             LayeDenial::Forbidden => (StatusCode::FORBIDDEN, "Forbidden"),
    ///         };
    ///
    ///         Response::builder()
    ///             .status(status)
    ///             .header(header::CONTENT_TYPE, "application/json")
    ///             .body(Bytes::from(format!("{{\"message\":\"{message}\"}}")))
    ///             .expect("valid response")
    ///     });
    /// # #[derive(Clone)]
    /// # struct MyUser { roles: Vec<String>, permissions: Vec<String> }
    /// # impl laye::Principal for MyUser {
    /// #     fn roles(&self) -> &[String] { &self.roles }
    /// #     fn permissions(&self) -> &[String] { &self.permissions }
    /// #     fn is_authenticated(&self) -> bool { true }
    /// # }
    /// # let _ = layer;
    /// ```
    pub fn error_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(LayeDenial) -> Response<Bytes> + Send + Sync + 'static,
    {
        self.error_handler = Some(Arc::new(handler));
        self
    }
}

impl<S, P> Layer<S> for AccessControlLayer<P> {
    type Service = AccessControlService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        AccessControlService {
            inner,
            policy: self.policy.clone(),
            error_handler: self.error_handler.clone(),
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
    error_handler: Option<ErrorHandler>,
    _marker: PhantomData<fn(P)>,
}

impl<S, P, ReqBody, ResBody> Service<Request<ReqBody>> for AccessControlService<S, P>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    P: Principal + Clone + Send + Sync + 'static,
    ResBody: Default + From<Bytes>,
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

        let denial = match result {
            LayeCheckResult::Authorized => return Either::Left(self.inner.call(req)),
            LayeCheckResult::Unauthorized => LayeDenial::Unauthorized,
            LayeCheckResult::Forbidden => LayeDenial::Forbidden,
        };

        // A registered error handler builds the denial response; only its body bytes are
        // converted into the service's body type.
        if let Some(handler) = &self.error_handler {
            let (parts, body) = handler(denial).into_parts();

            return Either::Right(ready(Ok(Response::from_parts(parts, ResBody::from(body)))));
        }

        let mut res = Response::new(ResBody::default());
        *res.status_mut() = match denial {
            LayeDenial::Unauthorized => StatusCode::UNAUTHORIZED,
            LayeDenial::Forbidden => StatusCode::FORBIDDEN,
        };

        Either::Right(ready(Ok(res)))
    }
}
