//! The [`Principal`] trait that callers implement on their auth type.

/// Represents an authenticated (or guest) caller.
///
/// Implement this trait on your own auth info struct — a decoded JWT payload, a loaded database
/// row, or any other type that carries identity and permission data.
///
/// `Principal` is object-safe: all methods take `&self` with no generics, enabling
/// `&dyn Principal` usage inside [`AccessRule::Custom`](crate::AccessRule::Custom).
///
/// # Examples
///
/// ```
/// use laye::Principal;
///
/// #[derive(Clone)]
/// struct MyUser {
///     roles: Vec<String>,
///     permissions: Vec<String>,
///     authenticated: bool,
/// }
///
/// impl Principal for MyUser {
///     fn roles(&self) -> &[String] { &self.roles }
///     fn permissions(&self) -> &[String] { &self.permissions }
///     fn is_authenticated(&self) -> bool { self.authenticated }
/// }
///
/// let user = MyUser {
///     roles: vec!["editor".to_string()],
///     permissions: vec!["posts:write".to_string()],
///     authenticated: true,
/// };
///
/// assert!(user.has_role("editor"));
/// assert!(!user.has_role("admin"));
/// assert!(user.has_permission("posts:write"));
/// assert!(!user.has_permission("posts:delete"));
/// ```
pub trait Principal {
    /// Returns the roles assigned to this principal.
    fn roles(&self) -> &[String];

    /// Returns the permissions granted to this principal.
    fn permissions(&self) -> &[String];

    /// Returns `true` if this principal is authenticated.
    ///
    /// A principal can be authenticated with zero roles or permissions. Conversely, you can
    /// pass a guest struct as `Some(&guest)` with this returning `false` to satisfy
    /// [`AccessRule::Guest`](crate::AccessRule::Guest) while still providing a principal value.
    fn is_authenticated(&self) -> bool;

    /// Returns `true` if `role` appears in [`roles`](Self::roles).
    fn has_role(&self, role: &str) -> bool {
        self.roles().iter().any(|r| r == role)
    }

    /// Returns `true` if `permission` appears in [`permissions`](Self::permissions).
    fn has_permission(&self, permission: &str) -> bool {
        self.permissions().iter().any(|p| p == permission)
    }
}
