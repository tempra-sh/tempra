use std::collections::HashMap;

use serde::Deserialize;

/// A complete hardening module loaded from a TOML file.
#[derive(Debug, Deserialize)]
pub struct HardeningModule {
    pub module: ModuleMeta,
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub handlers: Vec<Handler>,
}

/// Module metadata — deserialized from TOML, fields used for display and filtering.
#[allow(dead_code)] // fields populated by serde, used in modules info + future features
#[derive(Debug, Deserialize)]
pub struct ModuleMeta {
    pub name: String,
    pub description: String,
    pub version: String,
    pub category: String,
    pub severity: Severity,
    #[serde(default)]
    pub opinionated: bool,
    #[serde(default)]
    pub references: Vec<String>,
    pub supported: SupportedSystems,
    #[serde(default)]
    pub params: HashMap<String, ParamDef>,
}

/// A parameter definition for a module.
#[allow(dead_code)] // fields populated by serde, used in template resolution + future validation
#[derive(Debug, Deserialize)]
pub struct ParamDef {
    #[serde(rename = "type")]
    pub param_type: String,
    pub default: Option<toml::Value>,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "enum")]
    pub enum_values: Vec<String>,
}

/// Which systems this module supports.
#[derive(Debug, Deserialize)]
pub struct SupportedSystems {
    pub distros: Vec<String>,
    #[serde(default)]
    pub min_versions: HashMap<String, String>,
    pub requires_service: Option<String>,
}

/// A single hardening rule within a module.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub reference: String,
    pub check: CheckAction,
    pub remediate: RemediateAction,
    #[serde(default)]
    pub verify: Option<VerifyAction>,
    #[serde(default)]
    pub notify: Vec<String>,
    /// If set, this rule is expanded once per item in the named list param.
    /// Use `{{item}}` in rule fields to reference the current item.
    pub for_each: Option<String>,
}

/// A handler — executed once at end of module if notified by any rule.
#[derive(Debug, Deserialize)]
pub struct Handler {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub service: Option<String>,
    pub pre_check: Option<String>,
}

/// Severity level for a module or rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// How to check if a rule is already satisfied.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckAction {
    ConfigLine {
        file: String,
        key: String,
        expected: String,
    },
    IniValue {
        file: String,
        section: String,
        key: String,
        expected: String,
    },
    ServiceState {
        service: String,
        expected: ServiceExpectedState,
    },
    Sysctl {
        key: String,
        expected: String,
    },
    Package {
        name: String,
        expected: PackageExpectedState,
    },
    Command {
        command: String,
        expected_output: Option<String>,
        expected_exit_code: Option<i32>,
    },
    // --- Declarative types (resolved via providers) ---
    FirewallEnabled,
    FirewallPortAllowed {
        port: u16,
        proto: String,
    },
    PackageInstalled {
        name: String,
    },
    ServiceEnabled {
        service: String,
    },
    ServiceActive {
        service: String,
    },
}

/// How to fix a rule that is not satisfied.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemediateAction {
    SetConfigLine {
        file: String,
        key: String,
        value: String,
        restart_service: Option<String>,
    },
    SetIniValue {
        file: String,
        section: String,
        key: String,
        value: String,
        /// Additional default keys to write when creating a new section
        #[serde(default)]
        section_defaults: std::collections::HashMap<String, String>,
    },
    SetServiceState {
        service: String,
        state: ServiceExpectedState,
    },
    SetSysctl {
        key: String,
        value: String,
        persist: Option<bool>,
    },
    InstallPackage {
        name: String,
    },
    RemovePackage {
        name: String,
    },
    Command {
        command: String,
    },
    // --- Declarative types (resolved via providers) ---
    FirewallEnable,
    FirewallAllowPort {
        port: u16,
        proto: String,
    },
    FirewallRateLimitPort {
        port: u16,
        proto: String,
    },
    FirewallSetDefault {
        direction: String,
        policy: String,
    },
    FirewallEnableLogging,
    PackageInstall {
        name: String,
    },
    ServiceEnable {
        service: String,
    },
}

/// How to verify the remediation was applied.
#[allow(dead_code)] // verify not yet implemented — fields populated by serde for future use
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerifyAction {
    ConfigLine {
        file: String,
        key: String,
        expected: String,
    },
    IniValue {
        file: String,
        section: String,
        key: String,
        expected: String,
    },
    ServiceState {
        service: String,
        expected: ServiceExpectedState,
    },
    Sysctl {
        key: String,
        expected: String,
    },
    Package {
        name: String,
        expected: PackageExpectedState,
    },
    Command {
        command: String,
        expected_output: Option<String>,
        expected_exit_code: Option<i32>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceExpectedState {
    Enabled,
    Disabled,
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageExpectedState {
    Installed,
    Absent,
}
