`laye` is a framework-agnostic role- and permission-based access control (RBAC) library.
Build composable [`AccessPolicy`] rules, implement [`Principal`] on your auth type, and wire
the provided middleware into actix-web or axum (tower). Authentication — decoding tokens,
querying the database — is entirely outside `laye`'s scope.

## Feature flags

| Feature | What it adds |
|---------|-------------|
| `actix-web` | [`actix`](crate::actix) module: `PolicyMiddlewareFactory`, `AuthPrincipal`, `MaybeAuthPrincipal` |
| `tower` | [`tower_middleware`](crate::tower_middleware) module: `AccessControlLayer` |

## How it works

1. **Implement [`Principal`]** on your auth info struct (decoded JWT payload, session data, etc.).
2. **Build an [`AccessPolicy`]** with [`AccessPolicy::require_all`] (AND) or [`AccessPolicy::require_any`] (OR), chaining [`AccessRule`]s and nested sub-policies.
3. **Insert your principal into request extensions** from your own upstream auth middleware — *before* `laye` runs:
   - actix-web: `req.extensions_mut().insert(my_user)`
   - axum / tower: `req.extensions_mut().insert(my_user)`
4. **Apply a `laye` middleware / layer.** It reads `P` from extensions and calls [`AccessPolicy::check`].
   If no principal is found the request is rejected with **401 Unauthorized**; if the principal
   fails the policy it is rejected with **403 Forbidden**.

## Quick start

Implement [`Principal`]:

```rust
use laye::Principal;

#[derive(Clone)]
struct MyUser {
    roles: Vec<String>,
    permissions: Vec<String>,
    authenticated: bool,
}

impl Principal for MyUser {
    fn roles(&self) -> &[String] { &self.roles }
    fn permissions(&self) -> &[String] { &self.permissions }
    fn is_authenticated(&self) -> bool { self.authenticated }
}
```

Build and evaluate a policy:

```rust
# use laye::{AccessPolicy, AccessRule, LayeCheckResult, Principal};
# #[derive(Clone)]
# struct MyUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
# impl Principal for MyUser {
#     fn roles(&self) -> &[String] { &self.roles }
#     fn permissions(&self) -> &[String] { &self.permissions }
#     fn is_authenticated(&self) -> bool { self.authenticated }
# }
let editor = MyUser { roles: vec!["editor".into()], permissions: vec![], authenticated: true };
let viewer = MyUser { roles: vec!["viewer".into()], permissions: vec![], authenticated: true };

// Require authenticated AND (role "admin" OR role "editor")
let policy = AccessPolicy::require_all()
    .add_rule(AccessRule::Authenticated)
    .add_policy(
        AccessPolicy::require_any()
            .add_rule(AccessRule::Role("admin".into()))
            .add_rule(AccessRule::Role("editor".into())),
    );

assert_eq!(policy.check(Some(&editor)), LayeCheckResult::Authorized);
assert_eq!(policy.check(Some(&viewer)), LayeCheckResult::Forbidden);
assert_eq!(policy.check(None),          LayeCheckResult::Unauthorized);
```

Permission-based rules work the same way:

```rust
# use laye::{AccessPolicy, AccessRule, LayeCheckResult, Principal};
# #[derive(Clone)]
# struct MyUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
# impl Principal for MyUser {
#     fn roles(&self) -> &[String] { &self.roles }
#     fn permissions(&self) -> &[String] { &self.permissions }
#     fn is_authenticated(&self) -> bool { self.authenticated }
# }
let writer = MyUser {
    roles: vec![],
    permissions: vec!["posts:write".into()],
    authenticated: true,
};

let policy = AccessPolicy::require_all()
    .add_rule(AccessRule::Authenticated)
    .add_rule(AccessRule::Permission("posts:write".into()));

assert_eq!(policy.check(Some(&writer)), LayeCheckResult::Authorized);
```

Guest-only route (reject already-authenticated users):

```rust
# use laye::{AccessPolicy, AccessRule, LayeCheckResult, Principal};
# #[derive(Clone)]
# struct MyUser { roles: Vec<String>, permissions: Vec<String>, authenticated: bool }
# impl Principal for MyUser {
#     fn roles(&self) -> &[String] { &self.roles }
#     fn permissions(&self) -> &[String] { &self.permissions }
#     fn is_authenticated(&self) -> bool { self.authenticated }
# }
# let editor = MyUser { roles: vec!["editor".into()], permissions: vec![], authenticated: true };
let guest_policy = AccessPolicy::require_all().add_rule(AccessRule::Guest);

assert_eq!(guest_policy.check(None),           LayeCheckResult::Authorized);
assert_eq!(guest_policy.check(Some(&editor)),  LayeCheckResult::Forbidden);
```

## Framework integrations

See [`laye::actix`](crate::actix) for actix-web middleware and extractors.

See [`laye::tower_middleware`](crate::tower_middleware) for the tower / axum layer.
