pub mod systemd;

/// Abstraction over service managers (systemd, openrc, runit).
/// All methods are primitives available for modules to compose.
#[allow(dead_code)]
pub trait ServiceProvider {
    fn is_enabled(&self, service: &str) -> bool;
    fn is_active(&self, service: &str) -> bool;
    fn enable(&self, service: &str) -> Result<(), String>;
    fn disable(&self, service: &str) -> Result<(), String>;
    fn start(&self, service: &str) -> Result<(), String>;
    fn stop(&self, service: &str) -> Result<(), String>;
    fn restart(&self, service: &str) -> Result<(), String>;
    fn reload(&self, service: &str) -> Result<(), String>;
}
