use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tempra", version, about = "Security hardening for the masses")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Setup tempra with sensible defaults for detected OS
    Init {
        /// Interactive mode — ask preferences instead of using defaults
        #[arg(short, long)]
        interactive: bool,
        /// Show what defaults would be without writing
        #[arg(long)]
        show: bool,
    },
    /// Detect system and show current security state
    Scan,
    /// Generate hardening plan (no changes made)
    Plan {
        /// Load modules from a directory instead of using built-in modules
        #[arg(long)]
        modules_dir: Option<String>,
    },
    /// Execute hardening plan
    Apply {
        /// Skip interactive confirmation
        #[arg(short, long)]
        yes: bool,
        /// Load modules from a directory instead of using built-in modules
        #[arg(long)]
        modules_dir: Option<String>,
    },
    /// Show what tempra has changed and detect manual modifications
    Status,
    /// List and manage hardening modules
    Modules {
        #[command(subcommand)]
        action: Option<ModulesAction>,
    },
}

#[derive(Subcommand)]
pub enum ModulesAction {
    /// List available modules with version and status
    List,
    /// Update modules from community registry
    Update,
    /// Show detailed info about a module (rules, params, authors)
    Info {
        /// Module name
        name: String,
    },
    /// Enable a module (adds to tempra.toml)
    Enable {
        /// Module name
        name: String,
    },
    /// Disable a module (removes from tempra.toml)
    Disable {
        /// Module name
        name: String,
    },
    /// Add a custom local module
    Add {
        /// Path to module directory or TOML file
        path: String,
    },
}
