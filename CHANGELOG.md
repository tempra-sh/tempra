# Changelog

## v0.0.1

Initial release. Security hardening for the masses.

### Engine
- **Plan/Apply lifecycle**: detect system → check rules → show plan → apply with confirmation
- **Provider system**: trait-based abstractions for firewall (UFW), service (systemd), package (apt)
- **Check engine**: `config_line`, `ini_value`, `service_state`, `package`, `sysctl`, `command`
- **Template engine**: `{{params.x}}` rendering, `for_each` list expansion
- **Handlers**: batched service restarts with pre-check validation (`sshd -t`)
- **Audit log**: tracks what tempra changed, `tempra status` shows holding/drifted rules
- **Config file**: `/etc/tempra/tempra.toml` with module param overrides
- **Custom hooks**: `custom_pre`/`custom_post` rules per module in config
- **Managed file headers**: `# Managed by Tempra` + `# tempra:key` line markers

### CLI
- `tempra init` — writes sensible defaults + downloads modules from hub (`-i` for interactive)
- `tempra scan` — detect OS, distro, version, init system, package manager
- `tempra plan` — show what needs hardening (exit code 3 if changes needed)
- `tempra apply [-y]` — apply plan with confirmation (or skip with `-y`)
- `tempra status` — show audit history and detect manual changes
- `tempra modules [list|update|info]` — manage hardening modules

### Architecture
- Binary = engine only. Zero hardening knowledge embedded.
- Modules downloaded from `tempra-sh/hub` via `git clone` on `tempra init`
- Convergent model: system is the source of truth, no state file
- Runs as root (`sudo tempra apply`), no hardcoded sudo in engine

### Quick start
```bash
curl -fsSL https://tempra.sh/install.sh | bash
sudo tempra init
sudo tempra apply -y
sudo tempra status
```
