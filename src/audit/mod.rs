use std::path::Path;

use serde::{Deserialize, Serialize};

const AUDIT_PATH: &str = "/var/lib/tempra/audit.toml";

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AuditLog {
    #[serde(default)]
    pub entries: Vec<AuditEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub rule_id: String,
    pub module: String,
    pub module_version: String,
    pub description: String,
    pub before: String,
    pub after: String,
    #[serde(default)]
    pub file: Option<String>,
}

impl AuditLog {
    /// Load audit log from disk. Returns empty log if file doesn't exist.
    pub fn load() -> Self {
        let path = Path::new(AUDIT_PATH);
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(content) => toml::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Record an entry (upsert by `rule_id`). Non-fatal on write failure.
    pub fn record(&mut self, entry: AuditEntry) {
        // Replace existing entry for same rule, or append if new
        if let Some(existing) = self.entries.iter_mut().find(|e| e.rule_id == entry.rule_id) {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
        self.save();
    }

    /// Save audit log to disk. Creates directory if needed. Non-fatal.
    fn save(&self) {
        let dir = Path::new("/var/lib/tempra");
        if !dir.exists() {
            let _ = crate::common::exec::run("mkdir", &["-p", "/var/lib/tempra"]);
        }

        let Ok(content) = toml::to_string_pretty(self) else {
            return;
        };

        // Write directly — tempra should be run as root
        let _ = crate::common::exec::run(
            "sh",
            &[
                "-c",
                &format!(
                    "echo '{}' | tee {} > /dev/null",
                    content.replace('\'', "'\\''"),
                    AUDIT_PATH
                ),
            ],
        );
    }
}

/// Get current timestamp as ISO 8601 string.
pub fn now_timestamp() -> String {
    // Use system time — no chrono dependency needed
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Simple UTC timestamp without external crate
    format!("{secs}")
}
