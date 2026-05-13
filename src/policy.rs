//! The [`AccessPolicy`] builder and [`AccessRule`] enum.

use std::sync::Arc;

use crate::{principal::Principal, result::LayeCheckResult};

/// A boxed closure used with [`AccessRule::Custom`].
///
/// The function receives `Option<&dyn Principal>` (the current principal, if any) and returns
/// `true` to allow access or `false` to deny it.
pub type CustomFn = Arc<dyn Fn(Option<&dyn Principal>) -> bool + Send + Sync>;

/// A single access condition tested against a [`Principal`].
///
/// Rules are the atomic building blocks of an [`AccessPolicy`]. Combine them with
/// [`AccessPolicy::require_all`] (AND) or [`AccessPolicy::require_any`] (OR).
#[derive(Clone)]
pub enum AccessRule {
    /// Passes when the principal has the named role.
    ///
    /// Returns [`Unauthorized`](LayeCheckResult::Unauthorized) when no principal is present,
    /// [`Forbidden`](LayeCheckResult::Forbidden) when the principal lacks the role.
    Role(String),

    /// Passes when the principal does *not* have the named role.
    ///
    /// Returns [`Unauthorized`](LayeCheckResult::Unauthorized) when no principal is present,
    /// [`Forbidden`](LayeCheckResult::Forbidden) when the principal has the role.
    NotRole(String),

    /// Passes when the principal has the named permission.
    ///
    /// Returns [`Unauthorized`](LayeCheckResult::Unauthorized) when no principal is present,
    /// [`Forbidden`](LayeCheckResult::Forbidden) when the principal lacks the permission.
    Permission(String),

    /// Passes when the principal does *not* have the named permission.
    ///
    /// Returns [`Unauthorized`](LayeCheckResult::Unauthorized) when no principal is present,
    /// [`Forbidden`](LayeCheckResult::Forbidden) when the principal has the permission.
    NotPermission(String),

    /// Passes when a principal is present and [`Principal::is_authenticated`] returns `true`.
    ///
    /// Returns [`Unauthorized`](LayeCheckResult::Unauthorized) when no principal is present
    /// or when `is_authenticated()` returns `false`.
    Authenticated,

    /// Passes when no principal is present, or when [`Principal::is_authenticated`] returns `false`.
    ///
    /// Returns [`Forbidden`](LayeCheckResult::Forbidden) for authenticated principals.
    /// Use this on login / register routes to redirect users who are already signed in.
    Guest,

    /// Delegates the check to an arbitrary closure.
    ///
    /// The closure receives `Option<&dyn Principal>` and returns `true` to allow, `false` to
    /// deny. When it returns `false`, the result is [`Unauthorized`](LayeCheckResult::Unauthorized)
    /// if no principal was present, or [`Forbidden`](LayeCheckResult::Forbidden) if one was.
    Custom(CustomFn),
}

#[derive(Clone)]
enum PolicyMode {
    All,
    Any,
}

#[derive(Clone)]
enum PolicyCheck {
    Rule(AccessRule),
    Nested(AccessPolicy),
}

/// A composable access policy built from [`AccessRule`]s and nested sub-policies.
///
/// Create a policy with [`require_all`](Self::require_all) (AND semantics) or
/// [`require_any`](Self::require_any) (OR semantics), then chain conditions with
/// [`add_rule`](Self::add_rule) and [`add_policy`](Self::add_policy).
///
/// # Examples
///
/// ```
/// # use laye::{AccessPolicy, AccessRule, LayeCheckResult, Principal};
/// # #[derive(Clone)]
/// # struct MyUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
/// # impl Principal for MyUser {
/// #     fn roles(&self) -> &[String] { &self.roles }
/// #     fn permissions(&self) -> &[String] { &self.permissions }
/// #     fn is_authenticated(&self) -> bool { self.authenticated }
/// # }
/// let user = MyUser { roles: vec!["editor".into()], permissions: vec![], authenticated: true };
///
/// let policy = AccessPolicy::require_all()
///     .add_rule(AccessRule::Authenticated)
///     .add_rule(AccessRule::Role("editor".into()));
///
/// assert_eq!(policy.check(Some(&user)), LayeCheckResult::Authorized);
/// assert_eq!(policy.check(None), LayeCheckResult::Unauthorized);
/// ```
#[derive(Clone)]
pub struct AccessPolicy {
    checks: Vec<PolicyCheck>,
    mode: PolicyMode,
}

impl AccessPolicy {
    /// Creates an AND policy: every rule and sub-policy must pass.
    ///
    /// An empty `require_all` policy always returns [`Authorized`](LayeCheckResult::Authorized).
    ///
    /// # Examples
    ///
    /// ```
    /// # use laye::{AccessPolicy, AccessRule, LayeCheckResult, Principal};
    /// # #[derive(Clone)]
    /// # struct MyUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
    /// # impl Principal for MyUser {
    /// #     fn roles(&self) -> &[String] { &self.roles }
    /// #     fn permissions(&self) -> &[String] { &self.permissions }
    /// #     fn is_authenticated(&self) -> bool { self.authenticated }
    /// # }
    /// let admin = MyUser { roles: vec!["admin".into()], permissions: vec![], authenticated: true };
    ///
    /// let policy = AccessPolicy::require_all()
    ///     .add_rule(AccessRule::Authenticated)
    ///     .add_rule(AccessRule::Role("admin".into()));
    ///
    /// assert_eq!(policy.check(Some(&admin)), LayeCheckResult::Authorized);
    /// ```
    pub fn require_all() -> Self {
        Self {
            checks: vec![],
            mode: PolicyMode::All,
        }
    }

    /// Creates an OR policy: at least one rule or sub-policy must pass.
    ///
    /// An empty `require_any` policy returns [`Unauthorized`](LayeCheckResult::Unauthorized)
    /// for anonymous requests and [`Forbidden`](LayeCheckResult::Forbidden) for authenticated
    /// ones (no condition can ever pass).
    ///
    /// # Examples
    ///
    /// ```
    /// # use laye::{AccessPolicy, AccessRule, LayeCheckResult, Principal};
    /// # #[derive(Clone)]
    /// # struct MyUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
    /// # impl Principal for MyUser {
    /// #     fn roles(&self) -> &[String] { &self.roles }
    /// #     fn permissions(&self) -> &[String] { &self.permissions }
    /// #     fn is_authenticated(&self) -> bool { self.authenticated }
    /// # }
    /// let editor = MyUser { roles: vec!["editor".into()], permissions: vec![], authenticated: true };
    ///
    /// let policy = AccessPolicy::require_any()
    ///     .add_rule(AccessRule::Role("admin".into()))
    ///     .add_rule(AccessRule::Role("editor".into()));
    ///
    /// assert_eq!(policy.check(Some(&editor)), LayeCheckResult::Authorized);
    /// assert_eq!(policy.check(None),          LayeCheckResult::Unauthorized);
    /// ```
    pub fn require_any() -> Self {
        Self {
            checks: vec![],
            mode: PolicyMode::Any,
        }
    }

    /// Appends an [`AccessRule`] to this policy.
    pub fn add_rule(mut self, rule: AccessRule) -> Self {
        self.checks.push(PolicyCheck::Rule(rule));
        self
    }

    /// Appends a nested [`AccessPolicy`] as a single condition in this policy.
    ///
    /// Use this to compose AND-of-OR or OR-of-AND logic:
    ///
    /// ```
    /// # use laye::{AccessPolicy, AccessRule, LayeCheckResult, Principal};
    /// # #[derive(Clone)]
    /// # struct MyUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
    /// # impl Principal for MyUser {
    /// #     fn roles(&self) -> &[String] { &self.roles }
    /// #     fn permissions(&self) -> &[String] { &self.permissions }
    /// #     fn is_authenticated(&self) -> bool { self.authenticated }
    /// # }
    /// let editor = MyUser { roles: vec!["editor".into()], permissions: vec![], authenticated: true };
    ///
    /// // Authenticated AND (admin OR editor)
    /// let policy = AccessPolicy::require_all()
    ///     .add_rule(AccessRule::Authenticated)
    ///     .add_policy(
    ///         AccessPolicy::require_any()
    ///             .add_rule(AccessRule::Role("admin".into()))
    ///             .add_rule(AccessRule::Role("editor".into())),
    ///     );
    ///
    /// assert_eq!(policy.check(Some(&editor)), LayeCheckResult::Authorized);
    /// ```
    pub fn add_policy(mut self, policy: AccessPolicy) -> Self {
        self.checks.push(PolicyCheck::Nested(policy));
        self
    }

    /// Evaluates this policy against an optional principal.
    ///
    /// Pass `Some(&principal)` for authenticated requests and `None` for anonymous requests.
    ///
    /// | Outcome | Returned value |
    /// |---------|---------------|
    /// | All conditions pass | [`Authorized`](LayeCheckResult::Authorized) |
    /// | No principal, auth required | [`Unauthorized`](LayeCheckResult::Unauthorized) |
    /// | Principal present, condition fails | [`Forbidden`](LayeCheckResult::Forbidden) |
    ///
    /// # Examples
    ///
    /// ```
    /// # use laye::{AccessPolicy, AccessRule, LayeCheckResult, Principal};
    /// # #[derive(Clone)]
    /// # struct MyUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
    /// # impl Principal for MyUser {
    /// #     fn roles(&self) -> &[String] { &self.roles }
    /// #     fn permissions(&self) -> &[String] { &self.permissions }
    /// #     fn is_authenticated(&self) -> bool { self.authenticated }
    /// # }
    /// let policy = AccessPolicy::require_all()
    ///     .add_rule(AccessRule::Role("admin".into()));
    ///
    /// let admin  = MyUser { roles: vec!["admin".into()], permissions: vec![], authenticated: true };
    /// let viewer = MyUser { roles: vec![],               permissions: vec![], authenticated: true };
    ///
    /// assert_eq!(policy.check(Some(&admin)),  LayeCheckResult::Authorized);
    /// assert_eq!(policy.check(Some(&viewer)), LayeCheckResult::Forbidden);
    /// assert_eq!(policy.check(None),          LayeCheckResult::Unauthorized);
    /// ```
    pub fn check(&self, principal: Option<&dyn Principal>) -> LayeCheckResult {
        match self.mode {
            PolicyMode::All => {
                for check in &self.checks {
                    let result = eval_check(check, principal);

                    if result != LayeCheckResult::Authorized {
                        return result;
                    }
                }

                LayeCheckResult::Authorized
            }
            PolicyMode::Any => {
                for check in &self.checks {
                    if eval_check(check, principal) == LayeCheckResult::Authorized {
                        return LayeCheckResult::Authorized;
                    }
                }

                if principal.is_none() {
                    LayeCheckResult::Unauthorized
                } else {
                    LayeCheckResult::Forbidden
                }
            }
        }
    }

    /// Converts this policy into a tower [`AccessControlLayer`](crate::tower_middleware::AccessControlLayer).
    ///
    /// Apply the returned layer to an axum `Router` or any tower service. Requests are rejected
    /// with **401** or **403** when the policy fails.
    ///
    /// **Prerequisite:** insert `P` into request extensions from an upstream middleware before
    /// this layer runs. See [`crate::tower_middleware`] for a complete integration guide.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use laye::{AccessPolicy, AccessRule, Principal};
    ///
    /// #[derive(Clone)]
    /// struct MyUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
    /// impl Principal for MyUser {
    ///     fn roles(&self) -> &[String] { &self.roles }
    ///     fn permissions(&self) -> &[String] { &self.permissions }
    ///     fn is_authenticated(&self) -> bool { self.authenticated }
    /// }
    ///
    /// let layer = AccessPolicy::require_all()
    ///     .add_rule(AccessRule::Role("admin".into()))
    ///     .into_tower_layer::<MyUser>();
    /// // router.route("/admin", get(handler).layer(layer))
    /// ```
    #[cfg(feature = "tower")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tower")))]
    pub fn into_tower_layer<P>(self) -> crate::tower_middleware::AccessControlLayer<P>
    where
        P: crate::principal::Principal + Clone + 'static,
    {
        crate::tower_middleware::AccessControlLayer::new(self)
    }

    /// Converts this policy into an actix-web [`PolicyMiddlewareFactory`](crate::actix::PolicyMiddlewareFactory).
    ///
    /// Apply the returned factory via `.wrap()` on an `App` or `Scope`. Requests are rejected
    /// with **401** or **403** when the policy fails.
    ///
    /// **Prerequisite:** insert `P` into request extensions from an upstream middleware before
    /// this middleware runs. See [`crate::actix`] for a complete integration guide.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use laye::{AccessPolicy, AccessRule, Principal};
    ///
    /// #[derive(Clone)]
    /// struct MyUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
    /// impl Principal for MyUser {
    ///     fn roles(&self) -> &[String] { &self.roles }
    ///     fn permissions(&self) -> &[String] { &self.permissions }
    ///     fn is_authenticated(&self) -> bool { self.authenticated }
    /// }
    ///
    /// let factory = AccessPolicy::require_all()
    ///     .add_rule(AccessRule::Role("admin".into()))
    ///     .into_actix_middleware::<MyUser>();
    /// // scope.wrap(factory)
    /// ```
    #[cfg(feature = "actix-web")]
    #[cfg_attr(docsrs, doc(cfg(feature = "actix-web")))]
    pub fn into_actix_middleware<P>(self) -> crate::actix::PolicyMiddlewareFactory<P>
    where
        P: crate::principal::Principal + Clone + 'static,
    {
        crate::actix::PolicyMiddlewareFactory::new(self)
    }
}

fn eval_check(check: &PolicyCheck, principal: Option<&dyn Principal>) -> LayeCheckResult {
    match check {
        PolicyCheck::Rule(rule) => eval_rule(rule, principal),
        PolicyCheck::Nested(policy) => policy.check(principal),
    }
}

fn eval_rule(rule: &AccessRule, principal: Option<&dyn Principal>) -> LayeCheckResult {
    match rule {
        AccessRule::Role(r) => match principal {
            None => LayeCheckResult::Unauthorized,
            Some(p) => {
                if p.has_role(r) {
                    LayeCheckResult::Authorized
                } else {
                    LayeCheckResult::Forbidden
                }
            }
        },
        AccessRule::NotRole(r) => match principal {
            None => LayeCheckResult::Unauthorized,
            Some(p) => {
                if !p.has_role(r) {
                    LayeCheckResult::Authorized
                } else {
                    LayeCheckResult::Forbidden
                }
            }
        },
        AccessRule::Permission(p_str) => match principal {
            None => LayeCheckResult::Unauthorized,
            Some(p) => {
                if p.has_permission(p_str) {
                    LayeCheckResult::Authorized
                } else {
                    LayeCheckResult::Forbidden
                }
            }
        },
        AccessRule::NotPermission(p_str) => match principal {
            None => LayeCheckResult::Unauthorized,
            Some(p) => {
                if !p.has_permission(p_str) {
                    LayeCheckResult::Authorized
                } else {
                    LayeCheckResult::Forbidden
                }
            }
        },
        AccessRule::Authenticated => match principal {
            None => LayeCheckResult::Unauthorized,
            Some(p) => {
                if p.is_authenticated() {
                    LayeCheckResult::Authorized
                } else {
                    LayeCheckResult::Unauthorized
                }
            }
        },
        AccessRule::Guest => match principal {
            None => LayeCheckResult::Authorized,
            Some(p) => {
                if !p.is_authenticated() {
                    LayeCheckResult::Authorized
                } else {
                    LayeCheckResult::Forbidden
                }
            }
        },
        AccessRule::Custom(f) => {
            if f(principal) {
                LayeCheckResult::Authorized
            } else if principal.is_none() {
                LayeCheckResult::Unauthorized
            } else {
                LayeCheckResult::Forbidden
            }
        }
    }
}
