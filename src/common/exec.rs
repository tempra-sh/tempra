use std::process::Command;

use crate::common::error::TempraError;

/// Result of executing a system command.
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

/// Execute a command.
///
/// # Errors
///
/// Returns `TempraError::CommandExec` if the command fails to spawn.
pub fn run(program: &str, args: &[&str]) -> Result<CommandOutput, TempraError> {
    let output =
        Command::new(program)
            .args(args)
            .output()
            .map_err(|e| TempraError::CommandExec {
                command: format!("{program} {}", args.join(" ")),
                reason: e.to_string(),
            })?;

    Ok(CommandOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        success: output.status.success(),
    })
}

/// Check if running as root.
pub fn is_root() -> bool {
    run("id", &["-u"]).is_ok_and(|o| o.stdout.trim() == "0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_echo_succeeds() {
        let result = run("echo", &["hello"]).unwrap();
        assert!(result.success);
        assert_eq!(result.stdout.trim(), "hello");
    }

    #[test]
    fn run_nonexistent_command_returns_error() {
        let result = run("this-command-does-not-exist-xyz", &[]);
        assert!(result.is_err());
    }
}
