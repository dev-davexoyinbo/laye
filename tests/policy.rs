use std::sync::Arc;

use laye::{
    policy::{AccessPolicy, AccessRule},
    principal::Principal,
    result::LayeCheckResult,
};

struct TestUser {
    roles: Vec<String>,
    permissions: Vec<String>,
    authenticated: bool,
}

impl Principal for TestUser {
    fn roles(&self) -> &[String] {
        &self.roles
    }

    fn permissions(&self) -> &[String] {
        &self.permissions
    }

    fn is_authenticated(&self) -> bool {
        self.authenticated
    }
}

fn make_user(roles: &[&str], permissions: &[&str]) -> TestUser {
    TestUser {
        roles: roles.iter().map(|s| s.to_string()).collect(),
        permissions: permissions.iter().map(|s| s.to_string()).collect(),
        authenticated: true,
    }
}

fn make_guest() -> TestUser {
    TestUser {
        roles: vec![],
        permissions: vec![],
        authenticated: false,
    }
}

// ── AccessRule::Role ──────────────────────────────────────────────────────────

#[test]
fn role_rule_passes_for_matching_role() {
    let user = make_user(&["admin"], &[]);
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Role("admin".into()));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Authorized,
        "admin user should pass Role('admin') policy"
    );
}

#[test]
fn role_rule_fails_for_wrong_role() {
    let user = make_user(&["editor"], &[]);
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Role("admin".into()));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Forbidden,
        "editor user should get Forbidden for Role('admin') policy"
    );
}

#[test]
fn role_rule_fails_for_unauthenticated_returns_unauthorized() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Role("admin".into()));
    assert_eq!(
        policy.check(None),
        LayeCheckResult::Unauthorized,
        "missing principal should get Unauthorized for Role policy"
    );
}

// ── AccessRule::Permission ────────────────────────────────────────────────────

#[test]
fn permission_rule_passes_for_matching_permission() {
    let user = make_user(&[], &["write"]);
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Permission("write".into()));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Authorized,
        "user with 'write' should pass Permission('write') policy"
    );
}

#[test]
fn permission_rule_fails_for_wrong_permission() {
    let user = make_user(&[], &["read"]);
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Permission("write".into()));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Forbidden,
        "user with only 'read' should get Forbidden for Permission('write') policy"
    );
}

// ── AccessRule::Authenticated ─────────────────────────────────────────────────

#[test]
fn authenticated_rule_passes_for_authenticated_principal() {
    let user = make_user(&[], &[]);
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Authenticated);
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Authorized,
        "authenticated user should pass Authenticated rule"
    );
}

#[test]
fn authenticated_rule_fails_returning_unauthorized_for_none() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Authenticated);
    assert_eq!(
        policy.check(None),
        LayeCheckResult::Unauthorized,
        "missing principal should get Unauthorized for Authenticated rule"
    );
}

#[test]
fn authenticated_rule_fails_returning_forbidden_for_unauthenticated_principal() {
    let guest = make_guest();
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Authenticated);
    assert_eq!(
        policy.check(Some(&guest)),
        LayeCheckResult::Forbidden,
        "unauthenticated principal should get Forbidden for Authenticated rule"
    );
}

// ── AccessRule::Guest ─────────────────────────────────────────────────────────

#[test]
fn guest_rule_passes_for_none() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Guest);
    assert_eq!(
        policy.check(None),
        LayeCheckResult::Authorized,
        "None principal should pass Guest rule"
    );
}

#[test]
fn guest_rule_passes_for_unauthenticated_principal() {
    let guest = make_guest();
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Guest);
    assert_eq!(
        policy.check(Some(&guest)),
        LayeCheckResult::Authorized,
        "unauthenticated principal should pass Guest rule"
    );
}

#[test]
fn guest_rule_fails_for_authenticated_principal() {
    let user = make_user(&[], &[]);
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Guest);
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Forbidden,
        "authenticated principal should get Forbidden for Guest rule"
    );
}

// ── AccessRule::Custom ────────────────────────────────────────────────────────

#[test]
fn custom_rule_delegates_to_closure() {
    let user = make_user(&[], &[]);
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Custom(Arc::new(|_| true)));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Authorized,
        "custom rule returning true should pass"
    );

    let policy = AccessPolicy::require_all().add_rule(AccessRule::Custom(Arc::new(|_| false)));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Forbidden,
        "custom rule returning false with present principal should give Forbidden"
    );
}

#[test]
fn custom_rule_receives_none_for_missing_principal() {
    let called_with_none = Arc::new(std::sync::Mutex::new(false));
    let flag = called_with_none.clone();
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Custom(Arc::new(move |p| {
        if p.is_none() {
            *flag.lock().unwrap() = true;
        }
        false
    })));
    let _ = policy.check(None);
    assert!(
        *called_with_none.lock().unwrap(),
        "custom closure should receive None when no principal"
    );
}

// ── AccessPolicy AND mode ─────────────────────────────────────────────────────

#[test]
fn require_all_passes_when_all_rules_pass() {
    let user = make_user(&["admin"], &["write"]);
    let policy = AccessPolicy::require_all()
        .add_rule(AccessRule::Authenticated)
        .add_rule(AccessRule::Role("admin".into()))
        .add_rule(AccessRule::Permission("write".into()));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Authorized,
        "user satisfying all rules should pass require_all"
    );
}

#[test]
fn require_all_fails_when_any_rule_fails() {
    let user = make_user(&["admin"], &[]);
    let policy = AccessPolicy::require_all()
        .add_rule(AccessRule::Role("admin".into()))
        .add_rule(AccessRule::Permission("write".into()));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Forbidden,
        "require_all should fail if any single rule fails"
    );
}

// ── AccessPolicy OR mode ──────────────────────────────────────────────────────

#[test]
fn require_any_passes_when_one_rule_passes() {
    let user = make_user(&["editor"], &[]);
    let policy = AccessPolicy::require_any()
        .add_rule(AccessRule::Role("admin".into()))
        .add_rule(AccessRule::Role("editor".into()));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Authorized,
        "require_any should pass when at least one rule passes"
    );
}

#[test]
fn require_any_fails_when_all_rules_fail() {
    let user = make_user(&["viewer"], &[]);
    let policy = AccessPolicy::require_any()
        .add_rule(AccessRule::Role("admin".into()))
        .add_rule(AccessRule::Role("editor".into()));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Forbidden,
        "require_any should fail when all rules fail"
    );
}

// ── Nesting ───────────────────────────────────────────────────────────────────

#[test]
fn nested_policy_and_of_or_passes() {
    // AND( OR(Role(admin), Role(editor)), Permission(publish) )
    let user = make_user(&["editor"], &["publish"]);
    let inner = AccessPolicy::require_any()
        .add_rule(AccessRule::Role("admin".into()))
        .add_rule(AccessRule::Role("editor".into()));
    let policy = AccessPolicy::require_all()
        .add_policy(inner)
        .add_rule(AccessRule::Permission("publish".into()));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Authorized,
        "editor with publish perm should pass AND(OR(admin|editor), publish)"
    );
}

#[test]
fn nested_policy_or_of_and_fails_correctly() {
    // OR( AND(Role(admin), Permission(delete)), AND(Role(superuser), Permission(nuke)) )
    let user = make_user(&["admin"], &[]);
    let first = AccessPolicy::require_all()
        .add_rule(AccessRule::Role("admin".into()))
        .add_rule(AccessRule::Permission("delete".into()));
    let second = AccessPolicy::require_all()
        .add_rule(AccessRule::Role("superuser".into()))
        .add_rule(AccessRule::Permission("nuke".into()));
    let policy = AccessPolicy::require_any()
        .add_policy(first)
        .add_policy(second);
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Forbidden,
        "OR of two failing AND policies should return Forbidden for authenticated user"
    );
}

// ── Unauthorized vs Forbidden distinction ─────────────────────────────────────

#[test]
fn unauthenticated_request_yields_unauthorized_not_forbidden() {
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Role("admin".into()));
    assert_eq!(
        policy.check(None),
        LayeCheckResult::Unauthorized,
        "no principal should yield Unauthorized, not Forbidden"
    );
}

#[test]
fn authenticated_without_role_yields_forbidden_not_unauthorized() {
    let user = make_user(&[], &[]);
    let policy = AccessPolicy::require_all().add_rule(AccessRule::Role("admin".into()));
    assert_eq!(
        policy.check(Some(&user)),
        LayeCheckResult::Forbidden,
        "authenticated user lacking required role should yield Forbidden, not Unauthorized"
    );
}
