use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::knowledge::schema::{CheckAction, RemediateAction, Rule, Severity};

const SYSTEM_CONFIG: &str = "/etc/tempra/tempra.toml";
const USER_CONFIG: &str = ".config/tempra/tempra.toml";

/// A custom hook rule defined in tempra.toml.
#[derive(Debug, Deserialize)]
pub struct CustomHook {
    pub id: String,
    #[serde(default = "default_hook_description")]
    pub description: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    pub check: CheckAction,
    pub remediate: RemediateAction,
    #[serde(default)]
    pub notify: Vec<String>,
}

fn default_hook_description() -> String {
    "custom hook".into()
}

fn default_severity() -> Severity {
    Severity::Medium
}

impl CustomHook {
    /// Convert to a Rule for the plan engine.
    pub fn into_rule(self) -> Rule {
        Rule {
            id: self.id,
            description: self.description,
            severity: self.severity,
            reference: "custom".into(),
            check: self.check,
            remediate: self.remediate,
            verify: None,
            notify: self.notify,
            for_each: None,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct TempraConfig {
    #[allow(dead_code)] // used in future features
    #[serde(default)]
    pub tempra: GlobalConfig,
    /// Module-specific params: key = module name, value = param overrides
    #[serde(flatten)]
    pub modules: HashMap<String, toml::Value>,
}

#[allow(dead_code)] // fields read via serde, used in future features
#[derive(Debug, Deserialize, Default)]
pub struct GlobalConfig {
    pub modules_dir: Option<String>,
    #[serde(default = "default_channel")]
    pub channel: String,
}

fn default_channel() -> String {
    "stable".into()
}

impl TempraConfig {
    /// Load config from standard paths. Returns default if no config file exists.
    pub fn load() -> Self {
        // Try system config first
        let system_path = Path::new(SYSTEM_CONFIG);
        if system_path.exists() {
            if let Ok(content) = std::fs::read_to_string(system_path) {
                if let Ok(config) = toml::from_str(&content) {
                    return config;
                }
            }
        }

        // Fall back to user config
        if let Some(home) = std::env::var_os("HOME") {
            let user_path = Path::new(&home).join(USER_CONFIG);
            if user_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&user_path) {
                    if let Ok(config) = toml::from_str(&content) {
                        return config;
                    }
                }
            }
        }

        Self::default()
    }

    /// Get custom hooks for a module (`custom_pre` and `custom_post`).
    pub fn custom_hooks(&self, module_name: &str) -> (Vec<CustomHook>, Vec<CustomHook>) {
        let mut pre = Vec::new();
        let mut post = Vec::new();

        if let Some(toml::Value::Table(table)) = self.modules.get(module_name) {
            if let Some(toml::Value::Array(arr)) = table.get("custom_pre") {
                for item in arr {
                    if let Ok(hook) = item.clone().try_into() {
                        pre.push(hook);
                    }
                }
            }
            if let Some(toml::Value::Array(arr)) = table.get("custom_post") {
                for item in arr {
                    if let Ok(hook) = item.clone().try_into() {
                        post.push(hook);
                    }
                }
            }
        }

        (pre, post)
    }

    /// Get param overrides for a specific module.
    pub fn module_params(&self, module_name: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();

        if let Some(toml::Value::Table(table)) = self.modules.get(module_name) {
            for (k, v) in table {
                let val = match v {
                    toml::Value::String(s) => s.clone(),
                    toml::Value::Integer(i) => i.to_string(),
                    toml::Value::Boolean(b) => b.to_string(),
                    other => other.to_string(),
                };
                params.insert(k.clone(), val);
            }
        }

        params
    }

    /// Write config to /etc/tempra/tempra.toml. Returns error message on failure.
    pub fn write_system_config(content: &str) -> Result<(), String> {
        let dir = Path::new("/etc/tempra");
        if !dir.exists() {
            crate::common::exec::run("mkdir", &["-p", "/etc/tempra"])
                .map_err(|e| format!("failed to create /etc/tempra: {e}"))?;
        }

        let escaped = content.replace('\'', "'\\''");
        crate::common::exec::run(
            "sh",
            &[
                "-c",
                &format!("echo '{escaped}' | tee {SYSTEM_CONFIG} > /dev/null"),
            ],
        )
        .map_err(|e| format!("failed to write config: {e}"))?;

        Ok(())
    }
}
