use crate::common::exec;

use super::FirewallProvider;

pub struct UfwProvider;

impl FirewallProvider for UfwProvider {
    fn is_enabled(&self) -> bool {
        exec::run("ufw", &["status"])
            .is_ok_and(|o| o.success && o.stdout.contains("Status: active"))
    }

    fn enable(&self) -> Result<(), String> {
        exec::run("sh", &["-c", "echo y | ufw enable"])
            .map_err(|e| e.to_string())
            .and_then(|o| {
                if o.success {
                    Ok(())
                } else {
                    Err(o.stderr.trim().to_owned())
                }
            })
    }

    fn allow_port(&self, port: u16, proto: &str) -> Result<(), String> {
        run_ufw(&["allow", &format!("{port}/{proto}")])
    }

    fn deny_port(&self, port: u16, proto: &str) -> Result<(), String> {
        run_ufw(&["deny", &format!("{port}/{proto}")])
    }

    fn is_port_allowed(&self, port: u16, proto: &str) -> bool {
        let needle = format!("{port}/{proto}");
        exec::run("ufw", &["status"]).is_ok_and(|o| o.success && o.stdout.contains(&needle))
    }

    fn set_default(&self, direction: &str, policy: &str) -> Result<(), String> {
        run_ufw(&["default", policy, direction])
    }

    fn rate_limit_port(&self, port: u16, proto: &str) -> Result<(), String> {
        run_ufw(&["limit", &format!("{port}/{proto}")])
    }

    fn enable_logging(&self) -> Result<(), String> {
        run_ufw(&["logging", "on"])
    }
}

fn run_ufw(args: &[&str]) -> Result<(), String> {
    exec::run("ufw", args)
        .map_err(|e| e.to_string())
        .and_then(|o| {
            if o.success {
                Ok(())
            } else {
                Err(o.stderr.trim().to_owned())
            }
        })
}
