# Linux Guardian

<img src="https://lg.wondtech.com/logo.png" alt="Linux Guardian" width="200">

Linux Guardian v1.0 — Production-Ready Linux Server Security Hardening Script

## Overview

Linux Guardian implements a **Defence in Depth** strategy — multiple independent security layers stacked on top of each other. Bypassing one layer does not compromise the server; the attacker must defeat all layers simultaneously.

## Security Layers

| Layer | Name | What it does |
|-------|------|--------------|
| [1] | **Binary Lockdown** | Restricts dangerous binaries (nc, gcc, python, perl, ruby, lua, node, etc.) to root only |
| [2] | **Kernel Hardening** | Blocks unused and vulnerable kernel modules (dccp, sctp, rds, tipc, rxrpc, esp4, esp6) eliminating their attack surface entirely, and applies sysctl hardening (ASLR, SYN cookies, reverse path filtering, kernel pointer hiding) to mitigate exploitation of kernel vulnerabilities such as Dirty Frag and CopyFail variants. |
| [3] | **System Files** | Hardens permissions on /etc/shadow, /etc/passwd, /etc/sudoers, SSH config, and cron directories |
| [4] | **MySQL / MariaDB** | Binds database to 127.0.0.1 — blocks remote access |
| [5] | **PHP disable_functions** | Disables shell_exec, system, exec, passthru, proc_open and 60+ dangerous PHP functions |
| [6] | **noexec /tmp** | Mounts /tmp and /var/tmp with noexec, nosuid, nodev — uploaded binaries cannot execute |
| [7] | **AppArmor / SELinux** | Enforces Mandatory Access Control — web server cannot exec binaries even if uploaded |
| [8] | **Auditd** | Real-time monitoring: logs webshell execution, privilege escalation, and critical file changes |
| [A] | **FTP + ClamAV** | Pure-FTPd upload scanning — infected files are removed and an alert is sent |
| [B] | **Snuffleupagus** | Optional PHP RASP module — additional protection layer on top of disable_functions |
| [9] | **nspawn Isolation** | Each website runs in an isolated systemd-nspawn container — breach of site-A cannot reach site-B |

## Requirements

- Linux server (Debian / Ubuntu / CentOS / RHEL / Rocky / AlmaLinux / Alpine / Arch)
- Root privileges
- bash 4.0+
- PHP (for PHP hardening layers)
- systemd (for nspawn isolation)

## Quick Install
```bash
curl -L https://raw.githubusercontent.com/mogbil/lg/main/lg.sh -o /tmp/lg.sh && mv /tmp/lg.sh /usr/local/bin/lg && chmod +x /usr/local/bin/lg && lg
```
or
```bash
curl -L https://raw.githubusercontent.com/mogbil/lg/main/lg.sh -o /tmp/lg.sh && sudo mv /tmp/lg.sh /usr/local/bin/lg && sudo chmod +x /usr/local/bin/lg && sudo lg
```

## Usage

```bash
# Interactive mode — recommended for first run
sudo lg

# Auto mode — no prompts, applies all layers
sudo lg --auto

# Dry-run — preview every change without applying anything
sudo lg --dry-run

# Undo — rollback all changes from the last run
sudo lg --undo

# Silent mode for cron jobs
sudo lg --cron

# Install daily auto-update cron job + new-user hook
sudo lg --setup-auto
```

## Dry-Run Mode

Preview exactly what the script will do before touching the server:

```bash
sudo lg --dry-run
```

Every action is printed with a `[DRY-RUN]` tag. Nothing is written, mounted, or modified.

## Undo / Rollback

Every run creates a timestamped undo manifest in `/root/lg/backups/`. To restore the server to its previous state:

```bash
sudo lg --undo
```

The undo command restores:
- All modified files from backup copies
- Original file permissions
- Removed modprobe / sysctl configuration files
- Dismounted noexec tmpfs entries from /etc/fstab
- Stopped and removed nspawn containers and services
- AppArmor profiles set back to complain mode
- Auditd rules removed

## Auto-Update

Running `--setup-auto` installs:

- **Cron job** — runs daily at 03:00 AM in silent mode
- **New-user hook** — `/usr/local/bin/lg-user-hook` — automatically re-applies hardening when a new user is created (compatible with cPanel via `/scripts/prewwwacct`)

## Namespace Isolation (nspawn)

Each website is placed in a separate systemd-nspawn container with:

- Its own isolated filesystem (site files mounted read-only)
- A dedicated network interface on a private bridge (10.200.0.x)
- A noexec tmpfs for /tmp (32M)
- Dropped capabilities: CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE
- Runs as `www-data` with `NoNewPrivileges=yes`

```bash
# Manage containers
machinectl list              # list running containers
machinectl status <name>     # container details
machinectl login  <name>     # shell inside container
journalctl -u nspawn-<name>  # container logs
```

## Monitoring (Auditd)

The script installs audit rules that monitor:

| Rule key | What is monitored |
|----------|-------------------|
| `tmp_exec` | Binary execution from /tmp or /var/tmp |
| `webshell` | Any exec call by the web server user (www-data) |
| `passwd_change` | Writes to /etc/passwd or /etc/shadow |
| `sudoers_change` | Writes to /etc/sudoers or /etc/sudoers.d |
| `sshd_config` | Changes to /etc/ssh/sshd_config |
| `priv_esc` | setuid / setgid / setreuid syscalls |
| `home_exec` | Binary execution from /home |
| `php_config` | Changes to /etc/php |

```bash
# Search for webshell activity
ausearch -k webshell -ts recent

# Daily report
aureport --start today

# Live monitoring
tail -f /var/log/audit/audit.log
```

## Backups

All modified files are backed up before changes are applied:

```
/root/lg/backups/
├── phpini_php.ini.20240115_030000
├── mysql_my.cnf.20240115_030000
├── pureftpd_pure-ftpd.conf.20240115_030000
└── undo_manifest_20240115_030000.txt
```

Log file: `/var/log/lg-hardening.log`

## Verification

After running, verify each layer is active:

```bash
# Layer 5 — PHP disable_functions
php -r 'echo ini_get("disable_functions");' | tr , '\n' | head -10

# Layer 6 — noexec
mount | grep noexec

# Layer 7 — MAC
sestatus 2>/dev/null || apparmor_status 2>/dev/null

# Layer 8 — Auditd
ausearch -k webshell -ts recent

# Layer 9 — nspawn containers
machinectl list
```

## License

MIT License — see [LICENSE](LICENSE)
