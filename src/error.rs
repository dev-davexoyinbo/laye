use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum LayeError {
    /// Maps to HTTP 401.
    #[error("Unauthorized")]
    Unauthorized,
    /// Maps to HTTP 403.
    #[error("Forbidden")]
    Forbidden,
}
