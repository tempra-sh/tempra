use crate::common::exec;

use super::ServiceProvider;

pub struct SystemdProvider;

impl ServiceProvider for SystemdProvider {
    fn is_enabled(&self, service: &str) -> bool {
        exec::run("systemctl", &["is-enabled", service]).is_ok_and(|o| o.stdout.trim() == "enabled")
    }

    fn is_active(&self, service: &str) -> bool {
        exec::run("systemctl", &["is-active", service]).is_ok_and(|o| o.stdout.trim() == "active")
    }

    fn enable(&self, service: &str) -> Result<(), String> {
        run_systemctl(&["enable", "--now", service])
    }

    fn disable(&self, service: &str) -> Result<(), String> {
        run_systemctl(&["disable", "--now", service])
    }

    fn start(&self, service: &str) -> Result<(), String> {
        run_systemctl(&["start", service])
    }

    fn stop(&self, service: &str) -> Result<(), String> {
        run_systemctl(&["stop", service])
    }

    fn restart(&self, service: &str) -> Result<(), String> {
        run_systemctl(&["restart", service])
    }

    fn reload(&self, service: &str) -> Result<(), String> {
        run_systemctl(&["reload", service])
    }
}

fn run_systemctl(args: &[&str]) -> Result<(), String> {
    exec::run("systemctl", args)
        .map_err(|e| e.to_string())
        .and_then(|o| {
            if o.success {
                Ok(())
            } else {
                Err(o.stderr.trim().to_owned())
            }
        })
}
