use laye::principal::Principal;
use laye::{AccessPolicy, AccessRule, LayeCheckResult};

#[derive(Clone)]
struct MyUser {
    roles: Vec<String>,
    permissions: Vec<String>,
    authenticated: bool,
}

impl Principal for MyUser {
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

fn main() {
    let editor = MyUser {
        roles: vec!["editor".to_string()],
        permissions: vec!["posts:write".to_string()],
        authenticated: true,
    };

    let viewer = MyUser {
        roles: vec!["viewer".to_string()],
        permissions: vec![],
        authenticated: true,
    };

    // AND policy: authenticated AND (admin OR editor)
    let policy = AccessPolicy::require_all()
        .add_rule(AccessRule::Authenticated)
        .add_policy(
            AccessPolicy::require_any()
                .add_rule(AccessRule::Role("admin".to_string()))
                .add_rule(AccessRule::Role("editor".to_string())),
        );

    assert_eq!(
        policy.check(Some(&editor)),
        LayeCheckResult::Authorized,
        "editor should be authorized"
    );

    assert_eq!(
        policy.check(Some(&viewer)),
        LayeCheckResult::Forbidden,
        "viewer should be forbidden"
    );

    assert_eq!(
        policy.check(None),
        LayeCheckResult::Unauthorized,
        "anonymous should be unauthorized"
    );

    // Permission-based rule
    let write_policy =
        AccessPolicy::require_all().add_rule(AccessRule::Permission("posts:write".to_string()));

    assert_eq!(
        write_policy.check(Some(&editor)),
        LayeCheckResult::Authorized
    );
    assert_eq!(
        write_policy.check(Some(&viewer)),
        LayeCheckResult::Forbidden
    );

    // Guest-only route
    let guest_policy = AccessPolicy::require_all().add_rule(AccessRule::Guest);

    assert_eq!(guest_policy.check(None), LayeCheckResult::Authorized);
    assert_eq!(
        guest_policy.check(Some(&editor)),
        LayeCheckResult::Forbidden
    );

    // Custom rule
    let custom_policy =
        AccessPolicy::require_all().add_rule(AccessRule::Custom(std::sync::Arc::new(|p| {
            p.is_some_and(|u| u.has_permission("posts:write"))
        })));

    assert_eq!(
        custom_policy.check(Some(&editor)),
        LayeCheckResult::Authorized
    );
    assert_eq!(
        custom_policy.check(Some(&viewer)),
        LayeCheckResult::Forbidden
    );

    println!("All policy checks passed.");
}
