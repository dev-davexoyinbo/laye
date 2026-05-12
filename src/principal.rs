pub trait Principal {
    fn roles(&self) -> &[String];
    fn permissions(&self) -> &[String];
    fn is_authenticated(&self) -> bool;

    fn has_role(&self, role: &str) -> bool {
        self.roles().iter().any(|r| r == role)
    }

    fn has_permission(&self, permission: &str) -> bool {
        self.permissions().iter().any(|p| p == permission)
    }
}
