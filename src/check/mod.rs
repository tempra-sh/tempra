use crate::common::exec;
use crate::knowledge::schema::CheckAction;
use crate::providers::ProviderSet;

/// Result of checking a single rule.
#[derive(Debug)]
pub enum CheckResult {
    /// Rule is already satisfied (current state matches desired state).
    Pass,
    /// Rule is NOT satisfied — needs remediation.
    Fail { current: String, expected: String },
    /// Check could not be performed (e.g., file not found).
    Error(String),
}

impl CheckResult {
    #[cfg(test)]
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// Evaluate a check action against the current system state.
pub fn evaluate(action: &CheckAction, providers: &ProviderSet) -> CheckResult {
    match action {
        CheckAction::ConfigLine {
            file,
            key,
            expected,
        } => check_config_line(file, key, expected),
        CheckAction::IniValue {
            file,
            section,
            key,
            expected,
        } => check_ini_value(file, section, key, expected),
        CheckAction::ServiceState { service, expected } => check_service_state(service, *expected),
        CheckAction::Sysctl { key, expected } => check_sysctl(key, expected),
        CheckAction::Package { name, expected } => check_package(name, *expected),
        CheckAction::Command {
            command,
            expected_output,
            expected_exit_code,
        } => check_command(command, expected_output.as_deref(), *expected_exit_code),
        // --- Declarative types (via providers) ---
        CheckAction::FirewallEnabled => {
            if providers.firewall.is_enabled() {
                CheckResult::Pass
            } else {
                CheckResult::Fail {
                    current: "disabled".into(),
                    expected: "enabled".into(),
                }
            }
        }
        CheckAction::FirewallPortAllowed { port, proto } => {
            if providers.firewall.is_port_allowed(*port, proto) {
                CheckResult::Pass
            } else {
                CheckResult::Fail {
                    current: format!("{port}/{proto} not allowed"),
                    expected: format!("{port}/{proto} allowed"),
                }
            }
        }
        CheckAction::PackageInstalled { name } => {
            if providers.package.is_installed(name) {
                CheckResult::Pass
            } else {
                CheckResult::Fail {
                    current: "not installed".into(),
                    expected: "installed".into(),
                }
            }
        }
        CheckAction::ServiceEnabled { service } => {
            if providers.service.is_enabled(service) {
                CheckResult::Pass
            } else {
                CheckResult::Fail {
                    current: "not enabled".into(),
                    expected: "enabled".into(),
                }
            }
        }
        CheckAction::ServiceActive { service } => {
            if providers.service.is_active(service) {
                CheckResult::Pass
            } else {
                CheckResult::Fail {
                    current: "not active".into(),
                    expected: "active".into(),
                }
            }
        }
    }
}

fn check_config_line(file: &str, key: &str, expected: &str) -> CheckResult {
    let Ok(content) = std::fs::read_to_string(file) else {
        // File doesn't exist = key is not set
        return CheckResult::Fail {
            current: "(file missing)".into(),
            expected: expected.to_owned(),
        };
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let (line_key, line_val) = if let Some((k, v)) = trimmed.split_once('=') {
            (k.trim(), v.trim())
        } else if let Some((k, v)) = trimmed.split_once(char::is_whitespace) {
            (k.trim(), v.trim())
        } else {
            continue;
        };

        // Strip trailing tempra marker comment
        let line_val = line_val.split('#').next().unwrap_or(line_val).trim();

        if line_key.eq_ignore_ascii_case(key) {
            return if line_val == expected {
                CheckResult::Pass
            } else {
                CheckResult::Fail {
                    current: line_val.to_owned(),
                    expected: expected.to_owned(),
                }
            };
        }
    }

    CheckResult::Fail {
        current: "(not set)".into(),
        expected: expected.to_owned(),
    }
}

fn check_ini_value(file: &str, section: &str, key: &str, expected: &str) -> CheckResult {
    let Ok(ini) = ini::Ini::load_from_file(file) else {
        return CheckResult::Fail {
            current: "(file missing)".into(),
            expected: expected.to_owned(),
        };
    };

    match ini.get_from(Some(section), key) {
        Some(val) if val == expected => CheckResult::Pass,
        Some(val) => CheckResult::Fail {
            current: val.to_owned(),
            expected: expected.to_owned(),
        },
        None => CheckResult::Fail {
            current: "(not set)".into(),
            expected: expected.to_owned(),
        },
    }
}

fn check_service_state(
    service: &str,
    expected: crate::knowledge::schema::ServiceExpectedState,
) -> CheckResult {
    use crate::knowledge::schema::ServiceExpectedState;

    let (cmd_arg, expected_str) = match expected {
        ServiceExpectedState::Enabled => ("is-enabled", "enabled"),
        ServiceExpectedState::Disabled => ("is-enabled", "disabled"),
        ServiceExpectedState::Running => ("is-active", "active"),
        ServiceExpectedState::Stopped => ("is-active", "inactive"),
    };

    match exec::run("systemctl", &[cmd_arg, service]) {
        Ok(output) => {
            let actual = output.stdout.trim().to_owned();
            if actual == expected_str {
                CheckResult::Pass
            } else {
                CheckResult::Fail {
                    current: actual,
                    expected: expected_str.to_owned(),
                }
            }
        }
        Err(e) => CheckResult::Error(e.to_string()),
    }
}

fn check_sysctl(key: &str, expected: &str) -> CheckResult {
    match exec::run("sysctl", &["-n", key]) {
        Ok(output) if output.success => {
            let actual = output.stdout.trim().to_owned();
            if actual == expected {
                CheckResult::Pass
            } else {
                CheckResult::Fail {
                    current: actual,
                    expected: expected.to_owned(),
                }
            }
        }
        Ok(output) => CheckResult::Error(output.stderr.trim().to_owned()),
        Err(e) => CheckResult::Error(e.to_string()),
    }
}

fn check_package(
    name: &str,
    expected: crate::knowledge::schema::PackageExpectedState,
) -> CheckResult {
    use crate::knowledge::schema::PackageExpectedState;

    let result = exec::run("dpkg", &["-l", name]);
    let installed = result.is_ok_and(|o| o.success && o.stdout.contains("ii "));

    match expected {
        PackageExpectedState::Installed => {
            if installed {
                CheckResult::Pass
            } else {
                CheckResult::Fail {
                    current: "not installed".into(),
                    expected: "installed".into(),
                }
            }
        }
        PackageExpectedState::Absent => {
            if installed {
                CheckResult::Fail {
                    current: "installed".into(),
                    expected: "absent".into(),
                }
            } else {
                CheckResult::Pass
            }
        }
    }
}

fn check_command(
    command: &str,
    expected_output: Option<&str>,
    expected_exit_code: Option<i32>,
) -> CheckResult {
    match exec::run("sh", &["-c", command]) {
        Ok(output) => {
            if let Some(expected_code) = expected_exit_code {
                let actual_success = output.success;
                let expected_success = expected_code == 0;
                if actual_success != expected_success {
                    return CheckResult::Fail {
                        current: if actual_success {
                            "exit 0".into()
                        } else {
                            "exit non-zero".into()
                        },
                        expected: format!("exit {expected_code}"),
                    };
                }
            }

            if let Some(expected) = expected_output {
                let stdout = output.stdout.trim();
                if stdout.contains(expected) {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail {
                        current: stdout.to_owned(),
                        expected: expected.to_owned(),
                    }
                }
            } else if output.success {
                CheckResult::Pass
            } else {
                CheckResult::Fail {
                    current: "command failed".into(),
                    expected: "command succeeds".into(),
                }
            }
        }
        Err(e) => CheckResult::Error(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_line_parses_key_value_with_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.conf");
        std::fs::write(&path, "PermitRootLogin no\nPasswordAuth yes\n").unwrap();

        let result = check_config_line(path.to_str().unwrap(), "PermitRootLogin", "no");
        assert!(result.is_pass());
    }

    #[test]
    fn config_line_ignores_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.conf");
        std::fs::write(&path, "#PermitRootLogin yes\n").unwrap();

        let result = check_config_line(path.to_str().unwrap(), "PermitRootLogin", "no");
        assert!(!result.is_pass());
    }

    #[test]
    fn config_line_fails_on_wrong_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.conf");
        std::fs::write(&path, "MaxAuthTries 6\n").unwrap();

        let result = check_config_line(path.to_str().unwrap(), "MaxAuthTries", "4");
        assert!(!result.is_pass());
    }
}
