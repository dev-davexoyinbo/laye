use std::sync::Arc;

use crate::{principal::Principal, result::LayeCheckResult};

pub type CustomFn = Arc<dyn Fn(Option<&dyn Principal>) -> bool + Send + Sync>;

#[derive(Clone)]
pub enum AccessRule {
    Role(String),
    NotRole(String),
    Permission(String),
    NotPermission(String),
    Authenticated,
    Guest,
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

#[derive(Clone)]
pub struct AccessPolicy {
    checks: Vec<PolicyCheck>,
    mode: PolicyMode,
}

impl AccessPolicy {
    pub fn require_all() -> Self {
        Self {
            checks: vec![],
            mode: PolicyMode::All,
        }
    }

    pub fn require_any() -> Self {
        Self {
            checks: vec![],
            mode: PolicyMode::Any,
        }
    }

    pub fn add_rule(mut self, rule: AccessRule) -> Self {
        self.checks.push(PolicyCheck::Rule(rule));
        self
    }

    pub fn add_policy(mut self, policy: AccessPolicy) -> Self {
        self.checks.push(PolicyCheck::Nested(policy));
        self
    }

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

    #[cfg(feature = "tower")]
    pub fn into_tower_layer<P>(self) -> crate::tower_middleware::AccessControlLayer<P>
    where
        P: crate::principal::Principal + Clone + 'static,
    {
        crate::tower_middleware::AccessControlLayer::new(self)
    }

    #[cfg(feature = "actix-web")]
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
