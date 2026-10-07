//! The [`LayeCheckResult`] type returned by every policy evaluation.

/// Why a request was denied, as laye's middleware hands it to an error handler.
///
/// The actix [`LayeConfig`](crate::actix::LayeConfig) and the tower
/// [`AccessControlLayer::error_handler`](crate::tower_middleware::AccessControlLayer::error_handler)
/// receive this to build the response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayeDenial {
    /// No principal was in the request extensions, or the principal's
    /// [`is_authenticated`](crate::Principal::is_authenticated) returned `false`. Rendered as
    /// **401 Unauthorized** by default.
    Unauthorized,

    /// A principal was present but does not meet the policy's requirements. Rendered as
    /// **403 Forbidden** by default.
    Forbidden,
}

/// The outcome of an [`AccessPolicy::check`](crate::AccessPolicy::check) call.
///
/// Distinguishes between a missing principal (unauthenticated request) and a principal that is
/// present but does not satisfy the policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayeCheckResult {
    /// The principal satisfies the policy — allow the request.
    Authorized,

    /// No principal was present, or the principal's [`is_authenticated`](crate::Principal::is_authenticated)
    /// returned `false`.
    ///
    /// Maps to HTTP **401 Unauthorized**.
    Unauthorized,

    /// A principal was present but does not meet the policy's requirements.
    ///
    /// Maps to HTTP **403 Forbidden**.
    Forbidden,
}
