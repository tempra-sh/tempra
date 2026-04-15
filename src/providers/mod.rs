pub mod firewall;
pub mod package;
pub mod service;

use crate::detection::SystemInfo;

/// The set of providers selected for this system.
pub struct ProviderSet {
    pub firewall: Box<dyn firewall::FirewallProvider>,
    pub service: Box<dyn service::ServiceProvider>,
    pub package: Box<dyn package::PackageProvider>,
}

impl ProviderSet {
    /// Auto-detect and select providers based on system info.
    #[must_use]
    pub fn detect(system: &SystemInfo) -> Self {
        // For now, only ufw/systemd/apt are implemented.
        // Future: detect nftables, firewalld, openrc, dnf, pacman.
        let firewall_provider: Box<dyn firewall::FirewallProvider> =
            Box::new(firewall::ufw::UfwProvider);

        let service_provider: Box<dyn service::ServiceProvider> = match system.init_system {
            crate::detection::InitSystem::Systemd | crate::detection::InitSystem::Unknown => {
                Box::new(service::systemd::SystemdProvider)
            }
        };

        let package_provider: Box<dyn package::PackageProvider> = match system.package_manager {
            crate::detection::PackageManager::Apt
            | crate::detection::PackageManager::Dnf
            | crate::detection::PackageManager::Pacman
            | crate::detection::PackageManager::Unknown => Box::new(package::apt::AptProvider),
        };

        Self {
            firewall: firewall_provider,
            service: service_provider,
            package: package_provider,
        }
    }
}
