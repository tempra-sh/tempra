use std::fmt;

use crate::common::error::TempraError;
use crate::common::exec;

/// Detected system information.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub os: String,
    pub distro: String,
    pub version: String,
    pub init_system: InitSystem,
    pub package_manager: PackageManager,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    Systemd,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Pacman,
    Unknown,
}

impl fmt::Display for SystemInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "OS:              {}", self.os)?;
        writeln!(f, "Distribution:    {}", self.distro)?;
        writeln!(f, "Version:         {}", self.version)?;
        writeln!(f, "Init system:     {:?}", self.init_system)?;
        write!(f, "Package manager: {:?}", self.package_manager)
    }
}

/// Detect the current system's properties.
///
/// # Errors
///
/// Returns `TempraError::Detection` if OS identification fails.
pub fn detect_system() -> Result<SystemInfo, TempraError> {
    let os = detect_os()?;
    let (distro, version) = detect_distro()?;
    let init_system = detect_init_system();
    let package_manager = detect_package_manager();

    Ok(SystemInfo {
        os,
        distro,
        version,
        init_system,
        package_manager,
    })
}

fn detect_os() -> Result<String, TempraError> {
    let output = exec::run("uname", &["-s"]).map_err(|e| TempraError::Detection(e.to_string()))?;
    if output.success {
        Ok(output.stdout.trim().to_owned())
    } else {
        Err(TempraError::Detection("uname -s failed".into()))
    }
}

fn detect_distro() -> Result<(String, String), TempraError> {
    let content = std::fs::read_to_string("/etc/os-release")
        .map_err(|e| TempraError::Detection(format!("cannot read /etc/os-release: {e}")))?;

    let mut id = String::from("unknown");
    let mut version = String::from("unknown");

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("ID=") {
            val.trim_matches('"').clone_into(&mut id);
        } else if let Some(val) = line.strip_prefix("VERSION_ID=") {
            val.trim_matches('"').clone_into(&mut version);
        }
    }

    Ok((id, version))
}

fn detect_init_system() -> InitSystem {
    if std::path::Path::new("/run/systemd/system").exists() {
        InitSystem::Systemd
    } else {
        InitSystem::Unknown
    }
}

fn detect_package_manager() -> PackageManager {
    if which_exists("apt") {
        PackageManager::Apt
    } else if which_exists("dnf") {
        PackageManager::Dnf
    } else if which_exists("pacman") {
        PackageManager::Pacman
    } else {
        PackageManager::Unknown
    }
}

fn which_exists(name: &str) -> bool {
    exec::run("which", &[name]).is_ok_and(|o| o.success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_system_returns_linux() {
        let info = detect_system().unwrap();
        assert_eq!(info.os, "Linux");
    }
}
