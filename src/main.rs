use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;

mod apply;
mod audit;
mod check;
mod cli;
mod common;
mod config;
mod detection;
mod knowledge;
mod plan;
mod providers;
mod template;

const DEFAULT_MODULES_DIR: &str = "/var/lib/tempra/modules";
const HUB_REPO: &str = "https://github.com/tempra-sh/hub.git";

fn load_modules(modules_dir: Option<&str>) -> Result<Vec<knowledge::schema::HardeningModule>> {
    let dir = modules_dir.unwrap_or(DEFAULT_MODULES_DIR);
    let path = Path::new(dir);

    if !path.exists() {
        anyhow::bail!(
            "No modules found at {dir}.\nRun `sudo tempra init` to download modules, or `sudo tempra modules update`."
        );
    }

    knowledge::load_modules_from_dir(path).context("failed to load modules")
}

fn download_modules() -> Result<()> {
    let modules_path = Path::new(DEFAULT_MODULES_DIR);

    if modules_path.exists() {
        println!("Updating modules from hub...");
        let result = common::exec::run("git", &["-C", DEFAULT_MODULES_DIR, "pull", "--ff-only"]);
        match result {
            Ok(output) if output.success => {
                println!("Modules updated.");
                return Ok(());
            }
            _ => {
                // Pull failed (diverged history, corruption, etc.) — fresh clone
                eprintln!("Pull failed, re-downloading modules...");
                let _ = std::fs::remove_dir_all(modules_path);
            }
        }
    }

    {
        println!("Downloading modules from hub...");
        let parent = Path::new("/var/lib/tempra");
        if !parent.exists() {
            common::exec::run("mkdir", &["-p", "/var/lib/tempra"])
                .context("failed to create /var/lib/tempra")?;
        }

        let result = common::exec::run("git", &["clone", HUB_REPO, DEFAULT_MODULES_DIR]);
        match result {
            Ok(output) if output.success => {
                println!("Modules downloaded to {DEFAULT_MODULES_DIR}");
                Ok(())
            }
            Ok(output) => anyhow::bail!("git clone failed: {}", output.stderr.trim()),
            Err(e) => anyhow::bail!("git clone failed: {e}"),
        }
    }
}

fn list_modules() -> Result<()> {
    let modules = load_modules(None)?;
    println!("Available modules:\n");
    for m in &modules {
        println!(
            "  {} v{} ({} rules) — {}",
            m.module.name,
            m.module.version,
            m.rules.len(),
            m.module.description
        );
    }
    Ok(())
}

fn run_apply(
    the_plan: &plan::Plan,
    modules: &[knowledge::schema::HardeningModule],
    yes: bool,
    providers: &providers::ProviderSet,
) -> Result<()> {
    if the_plan.is_empty() {
        println!("System is already hardened. No changes needed.");
        return Ok(());
    }

    plan::display_plan(the_plan);

    if !yes {
        print!("{} change(s) to apply. Continue? [y/N] ", the_plan.len());
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();
    let mut audit_log = audit::AuditLog::load();
    let mut total_success = 0u32;
    let mut total_fail = 0u32;

    // Group steps by module and apply with handlers
    let module_names: Vec<String> = {
        let mut names = Vec::new();
        for step in &the_plan.steps {
            if !names.contains(&step.module_name) {
                names.push(step.module_name.clone());
            }
        }
        names
    };

    for module_name in &module_names {
        let module_steps: Vec<&plan::PlanStep> = the_plan
            .steps
            .iter()
            .filter(|s| &s.module_name == module_name)
            .collect();

        if module_steps.is_empty() {
            continue;
        }

        let version = &module_steps[0].module_version;
        println!("\x1b[1m[{module_name}]\x1b[0m");

        // Find handlers for this module
        let handlers = modules
            .iter()
            .find(|m| m.module.name == *module_name)
            .map_or(&[][..], |m| m.handlers.as_slice());

        let (s, f) = apply::apply_module_steps(
            &module_steps,
            handlers,
            module_name,
            version,
            &mut audit_log,
            providers,
        );
        total_success += s;
        total_fail += f;
        println!();
    }

    if total_fail > 0 {
        println!("{total_success} applied, \x1b[31m{total_fail} failed\x1b[0m.");
        std::process::exit(1);
    }
    println!("\x1b[32m{total_success} changes applied successfully.\x1b[0m");
    Ok(())
}

fn run_status(providers: &providers::ProviderSet) {
    let audit_log = audit::AuditLog::load();

    if audit_log.entries.is_empty() {
        println!("No apply history found. Run `tempra apply` first.");
        return;
    }

    // Load modules to re-run checks
    let modules = load_modules(None).unwrap_or_default();
    let all_rules: std::collections::HashMap<String, &knowledge::schema::Rule> = modules
        .iter()
        .flat_map(|m| m.rules.iter().map(|r| (r.id.clone(), r)))
        .collect();

    println!("\nTempra status:\n");
    let header = format!("  {:<35} {:<15} {}", "Rule", "Expected", "Status");
    println!("{header}");
    println!("  {}", "-".repeat(65));

    let mut ok_count = 0u32;
    let mut changed_count = 0u32;

    for entry in &audit_log.entries {
        // Re-run the check for this rule
        let status = if let Some(rule) = all_rules.get(&entry.rule_id) {
            match check::evaluate(&rule.check, providers) {
                check::CheckResult::Pass => {
                    ok_count += 1;
                    "\x1b[32m✓ holding\x1b[0m".to_owned()
                }
                check::CheckResult::Fail { current, .. } => {
                    changed_count += 1;
                    format!("\x1b[33m⚠ changed\x1b[0m ({current})")
                }
                check::CheckResult::Error(msg) => {
                    changed_count += 1;
                    format!("\x1b[31m✗ error\x1b[0m ({msg})")
                }
            }
        } else {
            changed_count += 1;
            "\x1b[33m? rule not found in modules\x1b[0m".to_owned()
        };

        println!(
            "  {:<35} {:<15} {}",
            truncate(&entry.rule_id, 33),
            truncate(&entry.after, 13),
            status
        );
    }

    println!();
    if changed_count > 0 {
        println!("  {ok_count} holding, \x1b[33m{changed_count} changed manually\x1b[0m.");
        println!("  Run `tempra plan` to see if re-hardening is needed.");
    } else {
        println!("  \x1b[32mAll {ok_count} rules holding.\x1b[0m");
    }
    println!();
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn run_init(interactive: bool, show: bool) -> Result<()> {
    let info = detection::detect_system()?;
    println!("Tempra setup\n");
    println!("{info}\n");

    if show {
        println!("Default config for this system:\n");
        let config = generate_default_config(&info);
        println!("{config}");
        return Ok(());
    }

    let config = if interactive {
        run_interactive_init(&info)?
    } else {
        generate_default_config(&info)
    };

    config::TempraConfig::write_system_config(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("Saved to /etc/tempra/tempra.toml\n");

    // Download modules from hub
    download_modules()?;

    println!("\nRun `tempra plan` to see what would change.");
    Ok(())
}

fn generate_default_config(info: &detection::SystemInfo) -> String {
    let firewall = match info.distro.as_str() {
        "alma" | "rhel" | "fedora" => "firewalld",
        _ => "ufw",
    };

    format!(
        r#"# Generated by `tempra init` — edit or re-run to change.

[tempra]
channel = "stable"

[ssh]
port = 22
permit_root = "no"
password_auth = "no"

[firewall]
backend = "{firewall}"
allow_tcp_ports = [22]
rate_limit_ssh = true

[fail2ban]
enabled = true
max_retry = 5
ban_time = 3600
find_time = 600
"#
    )
}

fn run_interactive_init(info: &detection::SystemInfo) -> Result<String> {
    let default_fw = match info.distro.as_str() {
        "ubuntu" | "debian" => "ufw",
        _ => "nftables",
    };

    // Firewall backend
    println!("Firewall backend [{default_fw}]: ");
    let _ = std::io::stdout().flush();
    let mut fw_input = String::new();
    std::io::stdin().read_line(&mut fw_input)?;
    let firewall = fw_input.trim();
    let firewall = if firewall.is_empty() {
        default_fw
    } else {
        firewall
    };

    // Ports
    print!("TCP ports to allow [22]: ");
    let _ = std::io::stdout().flush();
    let mut ports_input = String::new();
    std::io::stdin().read_line(&mut ports_input)?;
    let ports_str = ports_input.trim();
    let ports = if ports_str.is_empty() {
        "22".to_owned()
    } else {
        ports_str.to_owned()
    };
    let ports_array: Vec<&str> = ports.split(',').map(str::trim).collect();
    let ports_toml = format!(
        "[{}]",
        ports_array
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Fail2ban
    print!("Enable fail2ban? [Y/n]: ");
    let _ = std::io::stdout().flush();
    let mut f2b_input = String::new();
    std::io::stdin().read_line(&mut f2b_input)?;
    let f2b_enabled = !f2b_input.trim().eq_ignore_ascii_case("n");

    Ok(format!(
        r#"# Generated by `tempra init` — edit or re-run to change.

[tempra]
channel = "stable"

[ssh]
port = 22
permit_root = "no"
password_auth = "no"

[firewall]
backend = "{firewall}"
allow_tcp_ports = {ports_toml}
rate_limit_ssh = true

[fail2ban]
enabled = {f2b_enabled}
max_retry = 5
ban_time = 3600
find_time = 600
"#
    ))
}

fn require_root(command: &str) {
    if !common::exec::is_root() {
        eprintln!("Error: `tempra {command}` must be run as root.");
        eprintln!("Try: sudo tempra {command}");
        std::process::exit(1);
    }
}

fn main() -> Result<()> {
    let args = cli::Cli::parse();

    match args.command {
        cli::Command::Init { interactive, show } => {
            if !show {
                require_root("init");
            }
            run_init(interactive, show)?;
        }
        cli::Command::Scan => {
            let info = detection::detect_system()?;
            println!("{info}");
        }
        cli::Command::Plan { modules_dir } => {
            require_root("plan");
            let system = detection::detect_system()?;
            let prov = providers::ProviderSet::detect(&system);
            let cfg = config::TempraConfig::load();
            let modules = load_modules(modules_dir.as_deref())?;
            let the_plan = plan::generate_plan(&modules, &system, &prov, &cfg);
            plan::display_plan(&the_plan);

            if !the_plan.is_empty() {
                std::process::exit(3);
            }
        }
        cli::Command::Apply { yes, modules_dir } => {
            require_root("apply");
            let system = detection::detect_system()?;
            let prov = providers::ProviderSet::detect(&system);
            let cfg = config::TempraConfig::load();
            let modules = load_modules(modules_dir.as_deref())?;
            let the_plan = plan::generate_plan(&modules, &system, &prov, &cfg);
            run_apply(&the_plan, &modules, yes, &prov)?;
        }
        cli::Command::Status => {
            require_root("status");
            let system = detection::detect_system()?;
            let prov = providers::ProviderSet::detect(&system);
            run_status(&prov);
        }
        cli::Command::Modules { action } => match action {
            Some(cli::ModulesAction::List) | None => {
                list_modules()?;
            }
            Some(cli::ModulesAction::Update) => {
                require_root("modules update");
                download_modules()?;
            }
            Some(cli::ModulesAction::Info { name }) => {
                let modules = load_modules(None)?;
                if let Some(m) = modules.iter().find(|m| m.module.name == name) {
                    println!("{} v{}", m.module.name, m.module.version);
                    println!("  {}", m.module.description);
                    println!("  Distros: {}", m.module.supported.distros.join(", "));
                    if let Some(ref svc) = m.module.supported.requires_service {
                        println!("  Requires: {svc}");
                    }
                    if !m.handlers.is_empty() {
                        println!(
                            "  Handlers: {}",
                            m.handlers
                                .iter()
                                .map(|h| h.id.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                    println!("\n  Rules ({}):", m.rules.len());
                    for r in &m.rules {
                        println!(
                            "    [{:?}] {} — {} ({})",
                            r.severity, r.id, r.description, r.reference
                        );
                    }
                } else {
                    eprintln!("Module '{name}' not found.");
                    std::process::exit(1);
                }
            }
            Some(cli::ModulesAction::Enable { name }) => {
                eprintln!("tempra modules enable {name}: not yet implemented");
            }
            Some(cli::ModulesAction::Disable { name }) => {
                eprintln!("tempra modules disable {name}: not yet implemented");
            }
            Some(cli::ModulesAction::Add { path }) => {
                eprintln!("tempra modules add {path}: not yet implemented");
            }
        },
    }

    Ok(())
}
