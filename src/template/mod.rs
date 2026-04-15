use std::collections::HashMap;

/// Render template strings by replacing `{{params.x}}` with values.
/// Also replaces `{{item}}` for `for_each` expansion.
pub fn render(template: &str, params: &HashMap<String, String>) -> String {
    let mut result = template.to_owned();
    for (key, value) in params {
        let pattern = format!("{{{{params.{key}}}}}");
        result = result.replace(&pattern, value);
        // Also support short form {{key}}
        let short = format!("{{{{{key}}}}}");
        result = result.replace(&short, value);
    }
    result
}

/// Resolve params: module defaults → user config overrides.
pub fn resolve_params(
    module_params: &HashMap<String, crate::knowledge::schema::ParamDef>,
    user_overrides: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut resolved = HashMap::new();

    // Start with module defaults
    for (key, def) in module_params {
        if let Some(ref default) = def.default {
            let val = match default {
                toml::Value::String(s) => s.clone(),
                toml::Value::Integer(i) => i.to_string(),
                toml::Value::Boolean(b) => b.to_string(),
                toml::Value::Float(f) => f.to_string(),
                other => other.to_string(),
            };
            resolved.insert(key.clone(), val);
        }
    }

    // Override with user config
    for (key, value) in user_overrides {
        resolved.insert(key.clone(), value.clone());
    }

    resolved
}

/// Resolve list params for `for_each` expansion.
/// Returns the list of values if the param is an array, empty vec otherwise.
pub fn resolve_list_param(
    param_name: &str,
    module_params: &HashMap<String, crate::knowledge::schema::ParamDef>,
    user_overrides: &HashMap<String, String>,
) -> Vec<String> {
    // Check user override first (comma-separated string)
    if let Some(val) = user_overrides.get(param_name) {
        return val
            .trim_matches(|c| c == '[' || c == ']')
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
    }

    // Fall back to module default
    if let Some(def) = module_params.get(param_name) {
        if let Some(toml::Value::Array(arr)) = &def.default {
            return arr
                .iter()
                .map(|v| match v {
                    toml::Value::String(s) => s.clone(),
                    toml::Value::Integer(i) => i.to_string(),
                    other => other.to_string(),
                })
                .collect();
        }
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_replaces_params() {
        let mut params = HashMap::new();
        params.insert("port".into(), "2222".into());
        params.insert("proto".into(), "tcp".into());

        assert_eq!(
            render("ufw allow {{params.port}}/{{params.proto}}", &params),
            "ufw allow 2222/tcp"
        );
    }

    #[test]
    fn render_replaces_short_form() {
        let mut params = HashMap::new();
        params.insert("port".into(), "443".into());

        assert_eq!(render("allow {{port}}/tcp", &params), "allow 443/tcp");
    }

    #[test]
    fn render_leaves_unknown_params() {
        let params = HashMap::new();
        assert_eq!(
            render("{{params.unknown}} stays", &params),
            "{{params.unknown}} stays"
        );
    }
}
