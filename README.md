# Tempra

Server hardening tool. Single binary. Knowledge built-in.

Tempra detects your system, knows what needs hardening (CIS benchmarks, security best practices), generates a plan, applies it with native OS tools, and verifies the result.

```
$ tempra scan
OS:              Linux
Distribution:    ubuntu
Version:         24.04
Init system:     Systemd
Package manager: Apt

$ tempra plan
[+] SSH: Disable root login (CIS-5.2.10)
[~] SSH: Set MaxAuthTries to 4 (CIS-5.2.7)
[+] Firewall: Enable UFW with deny incoming (CIS-3.5.1.2)
[+] Fail2ban: Enable SSH jail (NIST-AC-7)

$ tempra apply
4 changes to apply. Continue? [y/N]
```

## Quick start

SSH into your new Ubuntu server and run:

```bash
curl -fsSL https://tempra.sh/install.sh | bash
tempra scan
tempra plan
tempra apply
```

That's it. Four commands from fresh install to hardened server.

## Install

### One-liner (recommended)

```bash
curl -fsSL https://tempra.sh/install.sh | bash
```

Detects your architecture, downloads the latest release, verifies SHA256 checksum, installs to `/usr/local/bin/`.

### Manual download

```bash
# Linux x86_64
curl -fsSL https://github.com/tempra-sh/tempra/releases/latest/download/tempra-linux-amd64 -o tempra

# Linux ARM64
curl -fsSL https://github.com/tempra-sh/tempra/releases/latest/download/tempra-linux-arm64 -o tempra

chmod +x tempra
sudo mv tempra /usr/local/bin/
```

### Verify checksum

```bash
curl -fsSL https://github.com/tempra-sh/tempra/releases/latest/download/checksums.txt -o checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

### Build from source

Requires [Rust](https://rustup.rs/) 1.85+.

```bash
git clone https://github.com/tempra-sh/tempra.git
cd tempra
cargo build --release
sudo cp target/release/tempra /usr/local/bin/
```

## Usage

```bash
tempra scan              # Detect system and show current security state
tempra plan              # Generate hardening plan (no changes made)
tempra apply             # Apply the plan (asks for confirmation)
tempra apply --yes       # Apply without confirmation
tempra verify            # Check current state against desired secure state
tempra drift             # Detect configuration drift
```

## What it hardens

Tempra ships with hardening modules based on CIS benchmarks:

| Module | Rules | Standards |
|--------|-------|-----------|
| SSH | 12 | CIS 5.2 |
| Firewall (UFW) | 7 | CIS 3.5 |
| Fail2ban | 4 | CIS 5.2, NIST AC-7 |

Modules are declarative TOML files in the [hub](https://github.com/tempra-sh/hub) repo.

## How it works

1. **Detect** — identifies OS, distro, package manager, init system, installed services
2. **Plan** — compares current state against hardening modules, shows what would change
3. **Apply** — executes changes using native tools (apt, systemctl, ufw, sysctl)
4. **Verify** — confirms changes were applied correctly

Tempra uses your system's own tools. It doesn't install agents, daemons, or runtimes — just the single `tempra` binary.

## Inspired by

Tempra wouldn't exist without the ideas and work of these projects:

- **[Ansible](https://ansible.com)** + **[DevSec Hardening](https://dev-sec.io/)** — Ansible proved that infrastructure should be described, not scripted. DevSec's hardening roles are the gold standard for CIS-compliant configurations. We learned *what* to harden from them. Tempra exists because we wanted that knowledge without writing playbooks or managing an Ansible installation.

- **[Terraform](https://terraform.io)** — The `plan → apply` lifecycle, provider abstraction, and convergent model are directly inspired by Terraform. Where Terraform manages cloud infrastructure, Tempra manages server security — same philosophy, different domain.

- **[Nix/NixOS](https://nixos.org/)** — Nix can declaratively configure an entire system, including security settings. In theory, you could write a CIS-compliant NixOS config. In practice, no such ready-to-use config exists, Nix adds unwanted friction in many scenarios, and the learning curve is steep. Tempra brings the declarative security idea to any Linux box with a single binary.

- **[Lynis](https://cisofy.com/lynis/)** — The best security auditing tool for Linux. Lynis knows what to check but intentionally doesn't fix it. Tempra adds the "apply" step — audit and remediate in one tool.

Each of these is excellent at what it does. Tempra fills a specific gap: **sensible security defaults that work in seconds for everyone, regardless of skill level — with full customization power for seasoned engineers who can contribute back to the module ecosystem**.

## Supported systems

- Ubuntu 22.04+
- Debian 12+

More distros coming.

## License

MIT OR Apache-2.0
