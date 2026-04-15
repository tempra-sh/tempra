pub mod ufw;

/// Abstraction over firewall backends (ufw, nftables, iptables, firewalld).
/// All methods are primitives available for modules to compose.
#[allow(dead_code)]
pub trait FirewallProvider {
    fn is_enabled(&self) -> bool;
    fn enable(&self) -> Result<(), String>;
    fn allow_port(&self, port: u16, proto: &str) -> Result<(), String>;
    fn deny_port(&self, port: u16, proto: &str) -> Result<(), String>;
    fn is_port_allowed(&self, port: u16, proto: &str) -> bool;
    fn set_default(&self, direction: &str, policy: &str) -> Result<(), String>;
    fn rate_limit_port(&self, port: u16, proto: &str) -> Result<(), String>;
    fn enable_logging(&self) -> Result<(), String>;
}
