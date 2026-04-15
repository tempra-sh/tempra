pub mod schema;

use std::path::Path;

use crate::common::error::TempraError;

use self::schema::HardeningModule;

/// Load a single hardening module from a TOML file.
///
/// # Errors
///
/// Returns `TempraError::ModuleLoad` if the file cannot be read or parsed.
/// Returns `TempraError::ModuleValidation` if the module content is invalid.
pub fn load_module(path: &Path) -> Result<HardeningModule, TempraError> {
    let content = std::fs::read_to_string(path).map_err(|e| TempraError::ModuleLoad {
        path: path.to_owned(),
        reason: e.to_string(),
    })?;

    let module: HardeningModule =
        toml::from_str(&content).map_err(|e| TempraError::ModuleLoad {
            path: path.to_owned(),
            reason: e.to_string(),
        })?;

    validate_module(&module)?;

    Ok(module)
}

fn validate_module(module: &HardeningModule) -> Result<(), TempraError> {
    if module.module.name.is_empty() {
        return Err(TempraError::ModuleValidation("module name is empty".into()));
    }
    if module.rules.is_empty() {
        return Err(TempraError::ModuleValidation(format!(
            "module '{}' has no rules",
            module.module.name
        )));
    }
    Ok(())
}

/// Load all modules from a directory tree.
///
/// # Errors
///
/// Returns errors from individual module loads.
pub fn load_modules_from_dir(dir: &Path) -> Result<Vec<HardeningModule>, TempraError> {
    fn walk(dir: &Path, modules: &mut Vec<HardeningModule>) -> Result<(), TempraError> {
        let entries = std::fs::read_dir(dir).map_err(|e| TempraError::ModuleLoad {
            path: dir.to_owned(),
            reason: e.to_string(),
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| TempraError::ModuleLoad {
                path: dir.to_owned(),
                reason: e.to_string(),
            })?;
            let path = entry.path();
            if path.is_dir() {
                walk(&path, modules)?;
            } else if path.extension().is_some_and(|ext| ext == "toml") {
                if let Ok(m) = load_module(&path) {
                    modules.push(m);
                }
                // non-module TOML files (registry.toml, etc.) silently skipped
            }
        }
        Ok(())
    }

    let mut modules = Vec::new();
    walk(dir, &mut modules)?;
    Ok(modules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_valid_module_from_toml() {
        let toml_content = r#"
[module]
name = "test_module"
description = "A test module"
version = "0.1.0"
category = "test"
severity = "low"
opinionated = false
references = ["TEST-1"]

[module.supported]
distros = ["ubuntu"]

[[rules]]
id = "test-rule-1"
description = "Test rule"
severity = "low"
reference = "TEST-1"

[rules.check]
type = "command"
command = "echo ok"
expected_output = "ok"

[rules.remediate]
type = "command"
command = "echo fix"

[rules.verify]
type = "command"
command = "echo ok"
expected_output = "ok"
"#;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let module = load_module(&path).unwrap();
        assert_eq!(module.module.name, "test_module");
        assert_eq!(module.rules.len(), 1);
    }
}
