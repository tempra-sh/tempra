pub mod apt;

/// Abstraction over package managers (apt, dnf, pacman).
/// All methods are primitives available for modules to compose.
#[allow(dead_code)]
pub trait PackageProvider {
    fn name(&self) -> &'static str;
    fn is_installed(&self, package: &str) -> bool;
    fn install(&self, package: &str) -> Result<(), String>;
    fn remove(&self, package: &str) -> Result<(), String>;
}
