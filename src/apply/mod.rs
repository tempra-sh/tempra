use std::collections::HashSet;
use std::path::Path;

use crate::audit::{self, AuditEntry, AuditLog};
use crate::common::exec;
use crate::knowledge::schema::{Handler, RemediateAction};
use crate::plan::PlanStep;
use crate::providers::ProviderSet;

const TEMPRA_HEADER: &str =
    "# Managed by Tempra (https://tempra.sh) — lines marked '# tempra:' may be overwritten";

/// Result of applying a single remediation step.
#[derive(Debug)]
pub enum ApplyResult {
    Success,
    Failed(String),
}

/// Apply all plan steps for a single module, then run notified handlers.
pub fn apply_module_steps(
    steps: &[&PlanStep],
    handlers: &[Handler],
    module_name: &str,
    module_version: &str,
    audit_log: &mut AuditLog,
    providers: &ProviderSet,
) -> (u32, u32) {
    let mut successes = 0u32;
    let mut failures = 0u32;
    let mut notified_handlers: HashSet<String> = HashSet::new();

    // Apply each rule
    for (i, step) in steps.iter().enumerate() {
        print!("  [{}/{}] {} ... ", i + 1, steps.len(), step.description);
        let _ = std::io::Write::flush(&mut std::io::stdout());

        match execute(&step.remediate, providers) {
            ApplyResult::Success => {
                println!("\x1b[32mOK\x1b[0m");
                successes += 1;

                // Record in audit
                audit_log.record(AuditEntry {
                    timestamp: audit::now_timestamp(),
                    rule_id: step.rule_id.clone(),
                    module: module_name.to_owned(),
                    module_version: module_version.to_owned(),
                    description: step.description.clone(),
                    before: step.current.clone(),
                    after: step.expected.clone(),
                    file: extract_file_from_action(&step.remediate),
                });

                // Collect handler notifications
                for handler_id in &step.notify {
                    notified_handlers.insert(handler_id.clone());
                }
            }
            ApplyResult::Failed(msg) => {
                println!("\x1b[31mFAILED\x1b[0m: {msg}");
                failures += 1;
            }
        }
    }

    // Run notified handlers (once each)
    if !notified_handlers.is_empty() {
        for handler in handlers {
            if notified_handlers.contains(&handler.id) {
                run_handler(handler);
            }
        }
    }

    (successes, failures)
}

/// Run a handler (e.g., restart service after config changes).
fn run_handler(handler: &Handler) {
    let service = handler.service.as_deref().unwrap_or("unknown");

    // Run pre-check if specified (e.g., sshd -t)
    if let Some(ref pre_check) = handler.pre_check {
        print!("  [pre-check] {pre_check} ... ");
        let _ = std::io::Write::flush(&mut std::io::stdout());

        match exec::run("sh", &["-c", pre_check]) {
            Ok(output) if output.success => {
                println!("\x1b[32mOK\x1b[0m");
            }
            Ok(output) => {
                println!("\x1b[31mFAILED\x1b[0m");
                eprintln!("  WARNING: {pre_check} failed — skipping restart of {service}");
                eprintln!("  {}", output.stderr.trim());
                return;
            }
            Err(e) => {
                println!("\x1b[31mFAILED\x1b[0m");
                eprintln!("  WARNING: pre-check failed: {e} — skipping restart of {service}");
                return;
            }
        }
    }

    // Execute the handler action
    match handler.kind.as_str() {
        "service_restart" => {
            print!("  [handler] restarting {service} ... ");
            let _ = std::io::Write::flush(&mut std::io::stdout());

            match exec::run("systemctl", &["restart", service]) {
                Ok(output) if output.success => println!("\x1b[32mOK\x1b[0m"),
                Ok(output) => {
                    println!("\x1b[31mFAILED\x1b[0m");
                    eprintln!("  {}", output.stderr.trim());
                }
                Err(e) => {
                    println!("\x1b[31mFAILED\x1b[0m");
                    eprintln!("  {e}");
                }
            }
        }
        "service_reload" => {
            print!("  [handler] reloading {service} ... ");
            let _ = std::io::Write::flush(&mut std::io::stdout());

            match exec::run("systemctl", &["reload", service]) {
                Ok(output) if output.success => println!("\x1b[32mOK\x1b[0m"),
                _ => println!("\x1b[33mreload failed, trying restart\x1b[0m"),
            }
        }
        other => {
            eprintln!("  WARNING: unknown handler type: {other}");
        }
    }
}

/// Execute a single remediation action.
pub fn execute(action: &RemediateAction, providers: &ProviderSet) -> ApplyResult {
    match action {
        RemediateAction::SetConfigLine {
            file,
            key,
            value,
            restart_service: _, // handled by handler now
        } => apply_set_config_line(file, key, value),
        RemediateAction::SetIniValue {
            file,
            section,
            key,
            value,
            section_defaults,
        } => apply_set_ini_value(file, section, key, value, section_defaults),
        RemediateAction::SetServiceState { service, state } => {
            apply_set_service_state(service, *state)
        }
        RemediateAction::SetSysctl {
            key,
            value,
            persist,
        } => apply_set_sysctl(key, value, persist.unwrap_or(true)),
        RemediateAction::InstallPackage { name } => apply_install_package(name),
        RemediateAction::RemovePackage { name } => apply_remove_package(name),
        RemediateAction::Command { command } => apply_command(command),
        // --- Declarative types (via providers) ---
        RemediateAction::FirewallEnable => match providers.firewall.enable() {
            Ok(()) => ApplyResult::Success,
            Err(e) => ApplyResult::Failed(e),
        },
        RemediateAction::FirewallAllowPort { port, proto } => {
            match providers.firewall.allow_port(*port, proto) {
                Ok(()) => ApplyResult::Success,
                Err(e) => ApplyResult::Failed(e),
            }
        }
        RemediateAction::FirewallRateLimitPort { port, proto } => {
            match providers.firewall.rate_limit_port(*port, proto) {
                Ok(()) => ApplyResult::Success,
                Err(e) => ApplyResult::Failed(e),
            }
        }
        RemediateAction::FirewallSetDefault { direction, policy } => {
            match providers.firewall.set_default(direction, policy) {
                Ok(()) => ApplyResult::Success,
                Err(e) => ApplyResult::Failed(e),
            }
        }
        RemediateAction::FirewallEnableLogging => match providers.firewall.enable_logging() {
            Ok(()) => ApplyResult::Success,
            Err(e) => ApplyResult::Failed(e),
        },
        RemediateAction::PackageInstall { name } => match providers.package.install(name) {
            Ok(()) => ApplyResult::Success,
            Err(e) => ApplyResult::Failed(e),
        },
        RemediateAction::ServiceEnable { service } => match providers.service.enable(service) {
            Ok(()) => ApplyResult::Success,
            Err(e) => ApplyResult::Failed(e),
        },
    }
}

fn backup_file(path: &str) {
    let src = Path::new(path);
    if !src.exists() {
        return;
    }

    let backup_dir = Path::new("/var/lib/tempra/backups");
    if !backup_dir.exists() {
        exec::run("mkdir", &["-p", "/var/lib/tempra/backups"]).ok();
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let safe_name = path.replace('/', "_");
    let backup_path = format!("/var/lib/tempra/backups/{safe_name}.{timestamp}");

    exec::run("cp", &["-p", path, &backup_path]).ok();
}

fn ensure_tempra_header(content: &str) -> String {
    if content.contains("Managed by Tempra") {
        return content.to_owned();
    }
    format!("{TEMPRA_HEADER}\n{content}")
}

fn apply_set_config_line(file: &str, key: &str, value: &str) -> ApplyResult {
    backup_file(file);

    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(e) => return ApplyResult::Failed(format!("cannot read {file}: {e}")),
    };

    let new_line = format!("{key} {value}");
    let marker = format!("# tempra:{key}");
    let marked_line = format!("{new_line}    {marker}");
    let mut found = false;
    let mut new_content = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        let is_match = if trimmed.starts_with('#') && !trimmed.contains("tempra:") {
            let uncommented = trimmed.trim_start_matches('#').trim();
            key_matches(uncommented, key)
        } else {
            key_matches(trimmed, key)
        };

        if is_match && !found {
            new_content.push_str(&marked_line);
            found = true;
        } else {
            new_content.push_str(line);
        }
        new_content.push('\n');
    }

    if !found {
        new_content.push_str(&marked_line);
        new_content.push('\n');
    }

    let new_content = ensure_tempra_header(&new_content);

    let escaped = new_content.replace('\'', "'\\''");
    let result = exec::run(
        "sh",
        &["-c", &format!("echo '{escaped}' | tee {file} > /dev/null")],
    );

    match result {
        Ok(output) if output.success => ApplyResult::Success,
        Ok(output) => ApplyResult::Failed(format!("write failed: {}", output.stderr.trim())),
        Err(e) => ApplyResult::Failed(format!("write failed: {e}")),
    }
}

fn apply_set_ini_value(
    file: &str,
    section: &str,
    key: &str,
    value: &str,
    section_defaults: &std::collections::HashMap<String, String>,
) -> ApplyResult {
    backup_file(file);

    let mut ini = ini::Ini::load_from_file(file).unwrap_or_default();

    // If section doesn't exist and we have defaults, write them first
    if ini.section(Some(section)).is_none() && !section_defaults.is_empty() {
        for (k, v) in section_defaults {
            ini.set_to(Some(section), k.clone(), v.clone());
        }
    }

    // Set the target key
    ini.set_to(Some(section), key.to_owned(), value.to_owned());

    match ini.write_to_file(file) {
        Ok(()) => ApplyResult::Success,
        Err(e) => ApplyResult::Failed(format!("write failed: {e}")),
    }
}

fn key_matches(line: &str, key: &str) -> bool {
    line.split_once(char::is_whitespace)
        .is_some_and(|(k, _)| k.eq_ignore_ascii_case(key))
        || line
            .split_once('=')
            .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(key))
}

fn apply_set_service_state(
    service: &str,
    state: crate::knowledge::schema::ServiceExpectedState,
) -> ApplyResult {
    use crate::knowledge::schema::ServiceExpectedState;

    let args: &[&str] = match state {
        ServiceExpectedState::Enabled => &["enable", "--now", service],
        ServiceExpectedState::Disabled => &["disable", "--now", service],
        ServiceExpectedState::Running => &["start", service],
        ServiceExpectedState::Stopped => &["stop", service],
    };

    match exec::run("systemctl", args) {
        Ok(output) if output.success => ApplyResult::Success,
        Ok(output) => ApplyResult::Failed(output.stderr.trim().to_owned()),
        Err(e) => ApplyResult::Failed(e.to_string()),
    }
}

fn apply_sysctl(key: &str, value: &str) -> ApplyResult {
    match exec::run("sysctl", &["-w", &format!("{key}={value}")]) {
        Ok(output) if output.success => ApplyResult::Success,
        Ok(output) => ApplyResult::Failed(output.stderr.trim().to_owned()),
        Err(e) => ApplyResult::Failed(e.to_string()),
    }
}

fn apply_set_sysctl(key: &str, value: &str, persist: bool) -> ApplyResult {
    let result = apply_sysctl(key, value);
    if !matches!(result, ApplyResult::Success) {
        return result;
    }

    if persist {
        let line = format!("{key} = {value}");
        let cmd = format!("echo '{line}' | tee -a /etc/sysctl.d/99-tempra.conf > /dev/null");
        match exec::run("sh", &["-c", &cmd]) {
            Ok(output) if output.success => ApplyResult::Success,
            Ok(output) => ApplyResult::Failed(output.stderr.trim().to_owned()),
            Err(e) => ApplyResult::Failed(e.to_string()),
        }
    } else {
        ApplyResult::Success
    }
}

fn apply_install_package(name: &str) -> ApplyResult {
    let _ = exec::run("apt-get", &["update", "-qq"]);

    match exec::run("apt-get", &["install", "-y", "-qq", name]) {
        Ok(output) if output.success => ApplyResult::Success,
        Ok(output) => ApplyResult::Failed(output.stderr.trim().to_owned()),
        Err(e) => ApplyResult::Failed(e.to_string()),
    }
}

fn apply_remove_package(name: &str) -> ApplyResult {
    match exec::run("apt-get", &["remove", "-y", "-qq", name]) {
        Ok(output) if output.success => ApplyResult::Success,
        Ok(output) => ApplyResult::Failed(output.stderr.trim().to_owned()),
        Err(e) => ApplyResult::Failed(e.to_string()),
    }
}

fn apply_command(command: &str) -> ApplyResult {
    match exec::run("sh", &["-c", command]) {
        Ok(output) if output.success => ApplyResult::Success,
        Ok(output) => ApplyResult::Failed(output.stderr.trim().to_owned()),
        Err(e) => ApplyResult::Failed(e.to_string()),
    }
}

fn extract_file_from_action(action: &RemediateAction) -> Option<String> {
    match action {
        RemediateAction::SetConfigLine { file, .. } => Some(file.clone()),
        _ => None,
    }
}
