use std::sync::Arc;

use actix_web::HttpRequest;

use crate::result::LayeDenial;

pub(crate) type ErrorHandler =
    Arc<dyn Fn(LayeDenial, &HttpRequest) -> actix_web::Error + Send + Sync>;

/// App-wide error handling for laye's middleware and extractors, registered once with
/// `App::app_data` — the same pattern as actix-web's `JsonConfig`.
///
/// Without it, denials are empty `401`/`403` responses. With an
/// [`error_handler`](Self::error_handler), every denial from
/// [`PolicyMiddlewareFactory`](super::PolicyMiddlewareFactory) and
/// [`AuthPrincipal`](super::AuthPrincipal) is converted to your own error type, so laye's
/// responses carry the same body shape as the rest of your API.
///
/// # Examples
///
/// ```
/// use actix_web::{App, error::InternalError, http::StatusCode};
/// use laye::LayeDenial;
/// use laye::actix::LayeConfig;
///
/// // Render denials through your API's own error type (anything implementing
/// // `ResponseError`); `InternalError` stands in for it here.
/// let laye_config = LayeConfig::default().error_handler(|denial, _req| {
///     let (message, status) = match denial {
///         LayeDenial::Unauthorized => ("Who are you?", StatusCode::UNAUTHORIZED),
///         LayeDenial::Forbidden => ("Not for you", StatusCode::FORBIDDEN),
///     };
///
///     InternalError::new(message, status).into()
/// });
///
/// let app = App::new().app_data(laye_config);
/// ```
#[derive(Clone, Default)]
pub struct LayeConfig {
    pub(crate) error_handler: Option<ErrorHandler>,
}

impl LayeConfig {
    /// Convert denials into your own `actix_web::Error`, whose `ResponseError` implementation
    /// renders the response.
    pub fn error_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(LayeDenial, &HttpRequest) -> actix_web::Error + Send + Sync + 'static,
    {
        self.error_handler = Some(Arc::new(handler));
        self
    }
}

/// The configured error handler, when a [`LayeConfig`] with one is registered.
pub(crate) fn error_handler(req: &HttpRequest) -> Option<&ErrorHandler> {
    req.app_data::<LayeConfig>()
        .and_then(|config| config.error_handler.as_ref())
}
