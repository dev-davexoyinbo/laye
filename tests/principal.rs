use laye::principal::Principal;

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

fn make_user(roles: &[&str], permissions: &[&str], authenticated: bool) -> TestUser {
    TestUser {
        roles: roles.iter().map(|s| s.to_string()).collect(),
        permissions: permissions.iter().map(|s| s.to_string()).collect(),
        authenticated,
    }
}

#[test]
fn has_role_returns_true_for_matching_role() {
    let user = make_user(&["admin"], &[], true);
    assert!(user.has_role("admin"));
}

#[test]
fn has_role_returns_false_for_missing_role() {
    let user = make_user(&["admin"], &[], true);
    assert!(!user.has_role("editor"));
}

#[test]
fn has_permission_returns_true_for_matching_permission() {
    let user = make_user(&[], &["read"], true);
    assert!(user.has_permission("read"));
}

#[test]
fn has_permission_returns_false_for_missing_permission() {
    let user = make_user(&[], &["read"], true);
    assert!(!user.has_permission("write"));
}

#[test]
fn is_authenticated_reflects_field() {
    let auth = make_user(&[], &[], true);
    let guest = make_user(&[], &[], false);
    assert!(auth.is_authenticated());
    assert!(!guest.is_authenticated());
}

#[test]
fn dyn_principal_coercion_compiles() {
    let user = make_user(&["admin"], &["read"], true);
    let _: &dyn Principal = &user;
}
