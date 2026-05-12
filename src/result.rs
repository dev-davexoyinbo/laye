#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayeCheckResult {
    Authorized,
    Unauthorized,
    Forbidden,
}
