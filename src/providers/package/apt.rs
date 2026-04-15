use crate::common::exec;

use super::PackageProvider;

pub struct AptProvider;

impl PackageProvider for AptProvider {
    fn name(&self) -> &'static str {
        "apt"
    }

    fn is_installed(&self, package: &str) -> bool {
        exec::run("dpkg", &["-l", package]).is_ok_and(|o| o.success && o.stdout.contains("ii "))
    }

    fn install(&self, package: &str) -> Result<(), String> {
        // Update index first (quiet)
        let _ = exec::run("apt-get", &["update", "-qq"]);

        exec::run("apt-get", &["install", "-y", "-qq", package])
            .map_err(|e| e.to_string())
            .and_then(|o| {
                if o.success {
                    Ok(())
                } else {
                    Err(o.stderr.trim().to_owned())
                }
            })
    }

    fn remove(&self, package: &str) -> Result<(), String> {
        exec::run("apt-get", &["remove", "-y", "-qq", package])
            .map_err(|e| e.to_string())
            .and_then(|o| {
                if o.success {
                    Ok(())
                } else {
                    Err(o.stderr.trim().to_owned())
                }
            })
    }
}
