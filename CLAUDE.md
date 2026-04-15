# Tempra

**Server hardening tool. Single binary. Knowledge built-in. No agents, no playbooks.**

Tempra is a security knowledge engine written in Rust. It detects your system, knows what needs hardening (CIS Benchmarks, industry best practices), generates a plan, applies it with native OS tools, and verifies the result. Think Terraform lifecycle for server security.

- **Website:** tempra.sh
- **GitHub:** tempra-sh/tempra
- **License:** MIT OR Apache-2.0 (dual-licensed)
- **Language:** Rust (edition 2024)
- **MSRV:** latest stable minus one (e.g., if stable is 1.85, MSRV is 1.84)

---

## Cardinal Rules

1. **No workarounds in modules.** Modules are declarative. If a check type can't express what you need, fix the check engine — don't hack the module with shell commands. The modules ARE the product; they must stay clean, readable, and correct. Think first principles, always.
2. **No hardcoded sudo.** The user runs `sudo tempra apply`. The binary never escalates privileges itself.
3. **Convergent, not procedural.** `tempra plan` reads the real system every time. There is no state file to corrupt. The system is the source of truth.
4. **Test everything you write.** Every new feature, fix, or module gets tests. Unit tests for logic, integration tests for workflows. No code lands without tests. Use `cargo test` locally, `just ci` before push. Target high coverage — untested code is broken code you haven't found yet.
5. **Reduce backlog, don't add it.** Prefer spending extra time now to do things properly over leaving `#[allow(dead_code)]` TODOs and technical debt. If a feature needs a type, wire it up end-to-end — don't leave phantom code. Use established crates for solved problems.

## Design Principles

1. **Knowledge engine, not config management.** Tempra knows what to do. The user doesn't write playbooks — Tempra ships with hardening knowledge as declarative modules.
2. **Native tools only.** Tempra never installs its own daemons, agents, or runtimes. It uses `apt`/`dnf`, `systemctl`, `ufw`/`nftables`, `sysctl`, and native config files. The only thing on disk is the `tempra` binary.
3. **Plan/Apply/Verify lifecycle.** Inspired by Terraform. Every change is shown before execution, requires confirmation, and is verified after application.
4. **Idempotency.** Every operation can be re-run safely. Running `tempra apply` twice produces the same result.
5. **No root by default.** Tempra runs as a regular user and escalates with `sudo` only when needed, for the specific commands that require it. Never suggest running `tempra` as root.
6. **Explain before acting.** Every plan step includes a human-readable explanation of what will change and why (with CIS/standard reference).
7. **Drift detection.** The desired secure state is defined; Tempra detects when reality diverges from it.
8. **Community modules.** The engine is a compiled binary; hardening knowledge lives in declarative module files that anyone can contribute.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                      CLI (clap)                     │
├─────────────────────────────────────────────────────┤
│                   Plan Engine                       │
│         (diff current state vs desired state)       │
├──────────┬──────────┬──────────┬────────────────────┤
│ Detection│ Knowledge│  Apply   │      Verify        │
│  Layer   │   Base   │  Engine  │      Engine        │
├──────────┴──────────┴──────────┴────────────────────┤
│              System Abstraction Layer                │
│      (package mgr, init system, firewall, fs)       │
└─────────────────────────────────────────────────────┘
```

### Layer Responsibilities

| Layer | What it does | Key traits |
|-------|-------------|------------|
| **Detection** | Discovers OS, distro, version, init system, package manager, active services, open ports, installed packages | Read-only, no side effects |
| **Knowledge Base** | Collection of hardening modules — declarative files describing secure states per component | Loaded at runtime, filterable by detected system |
| **Plan Engine** | Compares detected state against desired state from applicable modules, produces ordered change plan | Pure function: `(current_state, modules) -> Plan` |
| **Apply Engine** | Executes plan steps using native OS commands, with privilege escalation via sudo | Transactional where possible, rollback on critical failure |
| **Verify Engine** | Re-checks system state after apply to confirm changes took effect | Same detection logic, compared against expected post-state |
| **Drift Detector** | Compares current state vs last-known-good state, reports deviations | Designed for cron/scheduled execution |

---

## Directory Structure

```
tempra/
├── CLAUDE.md                  # This file
├── Cargo.toml                 # Workspace root
├── Cargo.lock
├── LICENSE-MIT
├── LICENSE-APACHE
├── README.md
├── deny.toml                  # cargo-deny configuration
├── rustfmt.toml               # Formatting config
├── clippy.toml                # Clippy config
│
├── src/
│   ├── main.rs                # Entry point, CLI setup
│   ├── cli/                   # CLI argument parsing and command dispatch
│   │   ├── mod.rs
│   │   ├── scan.rs
│   │   ├── plan.rs
│   │   ├── apply.rs
│   │   ├── verify.rs
│   │   ├── drift.rs
│   │   └── modules.rs
│   │
│   ├── detection/             # System detection layer
│   │   ├── mod.rs
│   │   ├── os.rs              # OS/distro/version detection
│   │   ├── packages.rs        # Installed packages
│   │   ├── services.rs        # Active services, init system
│   │   ├── network.rs         # Open ports, firewall state
│   │   └── system_info.rs     # Aggregate system snapshot
│   │
│   ├── knowledge/             # Module loading and knowledge base
│   │   ├── mod.rs
│   │   ├── loader.rs          # Parse module files (TOML)
│   │   ├── registry.rs        # Module registry and filtering
│   │   └── schema.rs          # Module schema types
│   │
│   ├── plan/                  # Plan generation
│   │   ├── mod.rs
│   │   ├── engine.rs          # Diff current vs desired → Plan
│   │   ├── step.rs            # Individual plan step types
│   │   └── display.rs         # Plan rendering for CLI output
│   │
│   ├── apply/                 # Plan execution
│   │   ├── mod.rs
│   │   ├── engine.rs          # Step executor
│   │   ├── privilege.rs       # sudo escalation handling
│   │   └── rollback.rs        # Rollback on failure
│   │
│   ├── verify/                # Post-apply verification
│   │   ├── mod.rs
│   │   └── engine.rs
│   │
│   ├── drift/                 # Drift detection
│   │   ├── mod.rs
│   │   └── detector.rs
│   │
│   └── common/                # Shared types, errors, utilities
│       ├── mod.rs
│       ├── error.rs           # Error types (thiserror)
│       ├── exec.rs            # Command execution wrapper
│       └── fs.rs              # File operations (read, write, backup)
│
├── modules/                   # Built-in hardening modules (TOML)
│   ├── ssh/
│   │   └── sshd_hardening.toml
│   ├── firewall/
│   │   └── basic_firewall.toml
│   ├── kernel/
│   │   └── sysctl_hardening.toml
│   ├── auth/
│   │   └── user_hardening.toml
│   └── updates/
│       └── auto_security_updates.toml
│
└── tests/                     # Integration tests
    ├── common/
    │   └── mod.rs             # Test helpers, mock system state
    ├── detection_test.rs
    ├── plan_test.rs
    ├── module_loading_test.rs
    └── verify_test.rs
```

---

## Module Format

Modules are TOML files. Each module declares what it hardens, on which systems, and how.

```toml
[module]
name = "sshd_hardening"
description = "Harden OpenSSH server configuration"
version = "0.1.0"
category = "ssh"
severity = "critical"                    # critical | high | medium | low
opinionated = false                      # true = beyond CIS baseline
references = ["CIS-5.2.1", "CIS-5.2.4", "CIS-5.2.5"]

[module.supported]
distros = ["ubuntu", "debian", "rhel", "fedora", "arch"]
min_versions = { ubuntu = "20.04", debian = "11" }
requires_service = "sshd"               # Only apply if this service exists

# Each [[rule]] is one atomic hardening check + remediation
[[rule]]
id = "ssh-disable-root-login"
description = "Disable direct root login via SSH"
severity = "critical"
reference = "CIS-5.2.10"

[rule.check]
type = "config_line"                     # config_line | service_state | sysctl | package | file_permission | command
file = "/etc/ssh/sshd_config"
key = "PermitRootLogin"
expected = "no"

[rule.remediate]
type = "set_config_line"
file = "/etc/ssh/sshd_config"
key = "PermitRootLogin"
value = "no"
restart_service = "sshd"

[rule.verify]
type = "config_line"
file = "/etc/ssh/sshd_config"
key = "PermitRootLogin"
expected = "no"
```

### Check/Remediate Types

| Type | Check behavior | Remediate behavior |
|------|---------------|-------------------|
| `config_line` | Grep config file for key=value | Set/replace line in config file |
| `service_state` | Check if service is enabled/running/stopped | Enable/disable/start/stop service |
| `sysctl` | Read current sysctl value | Write sysctl value + persist in conf |
| `package` | Check if package is installed/absent | Install/remove package via native pkg mgr |
| `file_permission` | Check file owner/group/mode | Set owner/group/mode |
| `command` | Run command, check exit code or output | Run remediation command |

### Adding a New Module

1. Create a TOML file under `modules/<category>/<name>.toml`
2. Follow the schema above — every field is validated at load time
3. Add integration tests in `tests/` that verify the module loads and plan generation works
4. Test on at least one supported distro (use containers for CI)
5. Submit PR with module file + tests

---

## CLI Design

```
tempra <command> [options]

Commands:
  scan              Detect system and show current security state
  plan              Generate hardening plan (no changes made)
  apply             Execute hardening plan
  verify            Check current state against desired secure state
  drift             Detect configuration drift from secure baseline
  modules           List available hardening modules
  modules update    Update modules from community registry

Global options:
  -v, --verbose     Increase output verbosity
  -q, --quiet       Minimal output (for scripts)
  --no-color        Disable colored output
  --json            Output in JSON format (for tooling integration)
  --modules-dir     Custom modules directory path
  --config          Path to tempra config file

Apply options:
  --yes             Skip interactive confirmation
  --dry-run         Show commands that would run (without executing)
  --only <modules>  Apply only specific modules (comma-separated)
  --skip <modules>  Skip specific modules (comma-separated)
```

### Output Conventions

- Use colored output by default (disable with `--no-color` or when not a TTY)
- Plan output uses `+` (green) for additions, `~` (yellow) for changes, `-` (red) for removals
- Every plan step shows: what changes, why (CIS reference), and the actual command
- JSON output (`--json`) for machine consumption — same data, structured
- Exit codes: 0 = success/no drift, 1 = error, 2 = drift detected, 3 = plan has changes

---

## Code Style

### Rust Conventions

- **Edition:** 2024
- **Formatter:** `rustfmt` — run `cargo fmt` before every commit, no exceptions
- **Linter:** `clippy` with `#![warn(clippy::all, clippy::pedantic)]` — fix all warnings
- **Dependencies:** audited with `cargo-deny` — no duplicate versions, no known vulnerabilities
- **Error handling:** `thiserror` for library errors, `anyhow` only in `main.rs` / CLI boundary. Never `unwrap()` or `expect()` in library code. Use `?` propagation everywhere.
- **No unsafe:** Zero `unsafe` blocks unless absolutely required (and then documented + reviewed)

### Naming

| Item | Convention | Example |
|------|-----------|---------|
| Crates | `kebab-case` | `tempra` |
| Modules | `snake_case` | `system_info` |
| Types/Traits | `PascalCase` | `SystemSnapshot`, `HardeningModule` |
| Functions | `snake_case` | `detect_os`, `generate_plan` |
| Constants | `SCREAMING_SNAKE` | `DEFAULT_MODULES_DIR` |
| CLI flags | `kebab-case` | `--modules-dir`, `--no-color` |

### Code Organization

- **Small files.** 200-400 lines typical, 800 max. If a file grows, split by responsibility.
- **Immutable by default.** Prefer owned types and return new values over `&mut` where practical.
- **Builders for complex structs.** Use the builder pattern for types with many optional fields.
- **Traits for abstraction.** The system abstraction layer uses traits so detection/apply logic can be tested without root or a real system.
- **No global state.** Pass configuration and context explicitly.

### Dependencies Policy

Use well-established crates for solved problems. Do not reimplement parsers, formats, or protocols that have battle-tested libraries. Do not add a dependency for something the stdlib can do.

Current dependencies:
- `clap` — CLI parsing (derive API)
- `serde` + `toml` — module loading and config
- `rust-ini` — INI file parsing (fail2ban, systemd configs)
- `thiserror` / `anyhow` — error handling
- `tokio` — only if async is genuinely needed (prefer sync for system commands)

When in doubt: if a crate has >1M downloads and solves a real parsing/format problem, use it.

---

## Testing Strategy

### Unit Tests

- Every module in `src/` has inline `#[cfg(test)]` tests
- Detection layer: test against mock system data (not real OS — use trait abstraction)
- Plan engine: test with known current state + module → assert expected plan
- Module loading: test parsing of valid/invalid TOML files

### Integration Tests

- Located in `tests/`
- Test full workflows: load modules → detect (mocked) → plan → verify plan correctness
- Module validation: every built-in module file must parse and validate successfully

### Container Tests (CI)

- Test actual apply + verify on real distros using Docker containers
- Matrix: Ubuntu 22.04/24.04, Debian 12, Fedora 40, RHEL 9 (where available)
- These tests run `tempra plan` and `tempra apply --yes` inside containers

### Running Tests

```bash
cargo test                    # Unit + integration tests
cargo test -- --ignored       # Container tests (requires Docker)
cargo clippy                  # Lint
cargo fmt -- --check          # Format check
cargo deny check              # Dependency audit
```

### Test Naming

```rust
#[test]
fn detect_os_returns_ubuntu_on_ubuntu_system() { }

#[test]
fn plan_includes_ssh_hardening_when_sshd_installed() { }

#[test]
fn module_with_missing_name_fails_validation() { }
```

Pattern: `<action>_<expected_outcome>_<condition>`

---

## Contributing Guidelines

1. **Fork and branch.** Branch from `main`, name branches `feat/`, `fix/`, `docs/`, `module/`.
2. **One concern per PR.** Don't mix module additions with engine changes.
3. **Tests required.** No PR is merged without tests for the changed behavior.
4. **Format and lint.** `cargo fmt && cargo clippy` must pass with zero warnings.
5. **Module PRs.** Include the TOML module file, at least one supported distro, and a test that verifies parsing. Reference the CIS benchmark or standard you're implementing.
6. **Commit messages.** `type(scope): description` — e.g., `feat(detection): add arch linux support`, `module(ssh): add key exchange algorithms rule`.
7. **No breaking changes without discussion.** Open an issue first for architectural changes.

---

## Security Policy

- **Tempra modifies system security configuration.** Every change must be auditable and reversible.
- **Backup before modify.** Before changing any config file, back up the original to a known location (e.g., `/var/lib/tempra/backups/`).
- **Principle of least privilege.** Only escalate to sudo for the specific command that needs it. Never run the entire process as root.
- **No network calls by default.** `tempra scan`, `plan`, `apply`, `verify`, and `drift` work fully offline. Only `modules update` makes network calls (to fetch community modules).
- **Module integrity.** Community modules fetched from the registry must be verified (checksums, signatures in future versions).
- **Vulnerability reports.** Email security@tempra.sh — do not open public issues for security vulnerabilities.

---

## Build and Run

```bash
# Development
cargo build
cargo run -- scan
cargo run -- plan

# Release
cargo build --release
./target/release/tempra scan

# Install locally
cargo install --path .
```

---

## Release Process

When tagging a release:

1. Update version in `Cargo.toml`
2. Generate changelog from commits since last tag:
   ```bash
   git log $(git describe --tags --abbrev=0)..HEAD --oneline --no-decorate
   ```
3. Group changelog entries by type (feat/fix/refactor/docs)
4. Tag with `just release --sign` (bumps version, creates signed tag)
5. Push tag — CI builds binaries and creates GitHub Release
6. Edit the GitHub Release to include the changelog in the body

### Changelog format in GitHub Release

```markdown
## What's Changed

### Features
- feat: implement plan and apply commands (#commit)
- feat: add modules subcommands (list/info/enable/disable)

### Fixes
- fix(ci): resolve clippy errors for Rust 1.94

### Other
- refactor(cli): replace verify/drift with init/status
- docs: add inspirations section to README
```

## Roadmap Context

### v0.1 (done)

- Detection: OS, distro, version, package manager, init system
- Modules: SSH hardening, basic firewall, fail2ban (embedded in binary)
- CLI: scan, plan, apply, modules
- Target distros: Ubuntu 22.04+, Debian 12+

### v0.2 (in progress)

- Handlers: batch service restarts, syntax check before restart
- Audit log: track what tempra changed, `tempra status` command
- Provider system: declarative rules, auto-detect ufw/systemd/apt
- Params: configurable modules via `/etc/tempra/tempra.toml`
- `tempra init`: interactive setup survey

### v0.3

- Community module registry + channels (stable/testing)
- Multi-OS overrides (directory-based modules)
- Module composition / profiles
- More providers: dnf, nftables, firewalld, openrc
