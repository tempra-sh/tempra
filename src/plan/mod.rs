use std::collections::HashMap;

use crate::check;
use crate::config::TempraConfig;
use crate::detection::SystemInfo;
use crate::knowledge::schema::{CheckAction, HardeningModule, RemediateAction, Rule, Severity};
use crate::providers::ProviderSet;
use crate::template;

/// A hardening plan: an ordered list of steps to apply.
#[derive(Debug)]
pub struct Plan {
    pub steps: Vec<PlanStep>,
}

/// A single step in a hardening plan.
#[derive(Debug)]
pub struct PlanStep {
    pub module_name: String,
    pub module_version: String,
    pub rule_id: String,
    pub description: String,
    pub severity: Severity,
    pub reference: String,
    pub current: String,
    pub expected: String,
    pub remediate: RemediateAction,
    pub notify: Vec<String>,
}

impl Plan {
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Generate a plan by checking each rule against current system state.
#[must_use]
pub fn generate_plan(
    modules: &[HardeningModule],
    system: &SystemInfo,
    providers: &ProviderSet,
    config: &TempraConfig,
) -> Plan {
    let mut steps = Vec::new();

    for module in modules {
        if !module_applies(module, system) {
            continue;
        }

        // Resolve params for this module
        let user_overrides = config.module_params(&module.module.name);
        let params = template::resolve_params(&module.module.params, &user_overrides);

        // Custom pre hooks
        let (pre_hooks, post_hooks) = config.custom_hooks(&module.module.name);
        for hook in pre_hooks {
            let rule = hook.into_rule();
            if let Some(step) = check_rule(module, &rule, providers, "") {
                steps.push(step);
            }
        }

        // Module rules
        for rule in &module.rules {
            let rendered_rule = render_rule(rule, &params);

            if let Some(ref for_each) = rule.for_each {
                let param_name = for_each.strip_prefix("params.").unwrap_or(for_each);
                let items = template::resolve_list_param(
                    param_name,
                    &module.module.params,
                    &user_overrides,
                );

                for item in &items {
                    let mut item_params = params.clone();
                    item_params.insert("item".into(), item.clone());
                    let item_rule = render_rule(rule, &item_params);
                    if let Some(step) = check_rule(module, &item_rule, providers, item) {
                        steps.push(step);
                    }
                }
            } else if let Some(step) = check_rule(module, &rendered_rule, providers, "") {
                steps.push(step);
            }
        }

        // Custom post hooks
        for hook in post_hooks {
            let rule = hook.into_rule();
            if let Some(step) = check_rule(module, &rule, providers, "") {
                steps.push(step);
            }
        }
    }

    // Preserve module order — the order in the TOML is intentional
    Plan { steps }
}

/// Render template variables in a rule's check and remediate actions.
fn render_rule(rule: &Rule, params: &HashMap<String, String>) -> Rule {
    Rule {
        id: rule.id.clone(),
        description: template::render(&rule.description, params),
        severity: rule.severity,
        reference: rule.reference.clone(),
        check: render_check(&rule.check, params),
        remediate: render_remediate(&rule.remediate, params),
        verify: rule.verify.clone(),
        notify: rule.notify.clone(),
        for_each: rule.for_each.clone(),
    }
}

fn render_check(action: &CheckAction, params: &HashMap<String, String>) -> CheckAction {
    match action {
        CheckAction::ConfigLine {
            file,
            key,
            expected,
        } => CheckAction::ConfigLine {
            file: template::render(file, params),
            key: template::render(key, params),
            expected: template::render(expected, params),
        },
        CheckAction::IniValue {
            file,
            section,
            key,
            expected,
        } => CheckAction::IniValue {
            file: template::render(file, params),
            section: template::render(section, params),
            key: template::render(key, params),
            expected: template::render(expected, params),
        },
        CheckAction::Command {
            command,
            expected_output,
            expected_exit_code,
        } => CheckAction::Command {
            command: template::render(command, params),
            expected_output: expected_output
                .as_ref()
                .map(|o| template::render(o, params)),
            expected_exit_code: *expected_exit_code,
        },
        // Types without string fields — pass through
        other => other.clone(),
    }
}

fn render_remediate(action: &RemediateAction, params: &HashMap<String, String>) -> RemediateAction {
    match action {
        RemediateAction::SetConfigLine {
            file,
            key,
            value,
            restart_service,
        } => RemediateAction::SetConfigLine {
            file: template::render(file, params),
            key: template::render(key, params),
            value: template::render(value, params),
            restart_service: restart_service.clone(),
        },
        RemediateAction::SetIniValue {
            file,
            section,
            key,
            value,
            section_defaults,
        } => RemediateAction::SetIniValue {
            file: template::render(file, params),
            section: template::render(section, params),
            key: template::render(key, params),
            value: template::render(value, params),
            section_defaults: section_defaults.clone(),
        },
        RemediateAction::Command { command } => RemediateAction::Command {
            command: template::render(command, params),
        },
        // Types without template-able string fields — pass through
        other => other.clone(),
    }
}

fn module_applies(module: &HardeningModule, system: &SystemInfo) -> bool {
    let distro_match = module
        .module
        .supported
        .distros
        .iter()
        .any(|d| d.eq_ignore_ascii_case(&system.distro));

    if !distro_match {
        return false;
    }

    if let Some(min_ver) = module.module.supported.min_versions.get(&system.distro) {
        if version_less_than(&system.version, min_ver) {
            return false;
        }
    }

    if let Some(ref svc) = module.module.supported.requires_service {
        let result = crate::common::exec::run("systemctl", &["cat", svc]);
        if !result.is_ok_and(|o| o.success) {
            return false;
        }
    }

    true
}

fn version_less_than(actual: &str, minimum: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse().ok()).collect() };
    let a = parse(actual);
    let m = parse(minimum);
    a < m
}

fn check_rule(
    module: &HardeningModule,
    rule: &Rule,
    providers: &ProviderSet,
    item_suffix: &str,
) -> Option<PlanStep> {
    let result = check::evaluate(&rule.check, providers);

    match result {
        check::CheckResult::Pass => None,
        check::CheckResult::Fail { current, expected } => {
            let rule_id = if item_suffix.is_empty() {
                rule.id.clone()
            } else {
                format!("{}:{item_suffix}", rule.id)
            };
            Some(PlanStep {
                module_name: module.module.name.clone(),
                module_version: module.module.version.clone(),
                rule_id,
                description: rule.description.clone(),
                severity: rule.severity,
                reference: rule.reference.clone(),
                current,
                expected,
                remediate: rule.remediate.clone(),
                notify: rule.notify.clone(),
            })
        }
        check::CheckResult::Error(msg) => {
            eprintln!("  warning: check failed for {}: {msg}", rule.id);
            None
        }
    }
}

/// Display a plan to stdout with colors.
pub fn display_plan(plan: &Plan) {
    if plan.is_empty() {
        println!("System is already hardened. No changes needed.");
        return;
    }

    println!("\n{} change(s) to apply:\n", plan.len());

    for step in &plan.steps {
        let severity_tag = match step.severity {
            Severity::Critical => "\x1b[31mCRIT\x1b[0m",
            Severity::High => "\x1b[33mHIGH\x1b[0m",
            Severity::Medium => "\x1b[36mMED \x1b[0m",
            Severity::Low => "\x1b[34mLOW \x1b[0m",
        };

        println!(
            "  [{severity_tag}] \x1b[1m{}\x1b[0m ({})",
            step.description, step.reference
        );
        println!("         {} → {}", step.current, step.expected);
    }

    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison_works() {
        assert!(version_less_than("20.04", "22.04"));
        assert!(!version_less_than("24.04", "22.04"));
        assert!(!version_less_than("22.04", "22.04"));
    }
}
