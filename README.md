# Linux Guardian

<img src="https://lg.wondtech.com/logo.png" alt="Linux Guardian" width="200">

Linux Guardian v1.0 — Production-Ready Linux Server Security Hardening Script

## Overview

Linux Guardian implements a **Defence in Depth** strategy — multiple independent security layers stacked on top of each other. Bypassing one layer does not compromise the server; the attacker must defeat all layers simultaneously.

## Security Layers

| Layer | Name | What it does |
|-------|------|--------------|
| [1] | **Binary Lockdown** | Restricts dangerous binaries (nc, gcc, python, perl, ruby, lua, node, etc.) to root only |
| [2] | **Kernel Hardening** | Blocks unused and vulnerable kernel modules (dccp, sctp, rds, tipc, rxrpc, esp4, esp6) eliminating their attack surface entirely, and applies sysctl hardening (ASLR, SYN cookies, reverse path filtering, kernel pointer hiding) to mitigate exploitation of kernel vulnerabilities such as Dirty Frag and CopyFail variants |
| [3] | **System Files** | Hardens permissions on /etc/shadow, /etc/passwd, /etc/sudoers, SSH config, and cron directories |
| [4] | **MySQL / MariaDB** | Binds database to 127.0.0.1 — blocks remote access |
| [5] | **PHP disable_functions** | Disables shell_exec, system, exec, passthru, proc_open and 60+ dangerous PHP functions |
| [6] | **noexec (auto-detect)** | Auto-detects all site roots from /var/www, /home/*/public_html, and Apache/Nginx config — applies noexec, nosuid, nodev to each |
| [7] | **AppArmor / SELinux** | Enforces Mandatory Access Control — web server cannot exec binaries even if uploaded |
| [8] | **Auditd** | Real-time monitoring: logs and emails alerts for webshell execution, privilege escalation, and critical file changes |
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

# Watch mode — monitor for new sites and isolate them automatically
sudo lg --watch
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

## Alert Email

During interactive mode, the script asks for a single alert email address used across all security layers:

```
Alert email for security notifications (default: root): admin@example.com
```

This email receives alerts from:

| Source | Trigger |
|--------|---------|
| **Auditd** | webshell execution, privilege escalation, critical file changes |
| **ClamAV** | infected file uploaded via FTP |

## Watch Mode

Watch mode monitors the server for new websites and automatically isolates and hardens them — no manual intervention required.

```bash
sudo lg --watch
```

When a new site is detected under `/var/www` or `/home/*/public_html`, the script automatically:

1. Creates an isolated **nspawn container** for the site
2. Mounts the site files **read-only** inside the container
3. Applies **open_basedir** to all php.ini files for the new site path
4. Restarts the web server to apply PHP changes
5. Logs every action to `/var/log/lg-hardening.log`

```
[2024-01-15 14:32:01] [WATCH] New site detected: mysite (/var/www/mysite)
[2024-01-15 14:32:03] [WATCH] mysite isolated successfully (IP: 10.200.0.11)
[2024-01-15 14:32:03] [WATCH] open_basedir updated in 2 php.ini(s) for mysite
```

Sites in `/home/USER/public_html` are automatically assigned:
- `WorkingDirectory` set to `/home/USER/public_html`
- Container runs as the actual site owner (not www-data)

Press `Ctrl+C` to stop watching.

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

The script installs audit rules that monitor and send email alerts for suspicious activity:

| Rule key | What is monitored | Alert sent? |
|----------|-------------------|-------------|
| `tmp_exec` | Binary execution from /tmp or /var/tmp | ✅ |
| `webshell` | Any exec call by the web server user (www-data) | ✅ |
| `passwd_change` | Writes to /etc/passwd or /etc/shadow | ✅ |
| `sudoers_change` | Writes to /etc/sudoers or /etc/sudoers.d | ✅ |
| `sshd_config` | Changes to /etc/ssh/sshd_config | ✅ |
| `priv_esc` | setuid / setgid / setreuid syscalls | ✅ |
| `home_exec` | Binary execution from /home | ✅ |
| `php_config` | Changes to /etc/php | ✅ |

Alerts are sent via `/etc/audit/lg-alert.sh` — registered as an audisp plugin. If audisp is unavailable, a cron fallback runs every minute.

Email subject format: `[LG ALERT] webshell detected on server1`

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

# Layer 5 — open_basedir
php -r 'echo ini_get("open_basedir");'

# Layer 6 — noexec
mount | grep noexec

# Layer 7 — MAC
sestatus 2>/dev/null || apparmor_status 2>/dev/null

# Layer 8 — Auditd rules
auditctl -l | grep lg

# Layer 8 — Recent alerts
ausearch -k webshell -ts recent

# Layer 9 — nspawn containers
machinectl list

# Watch mode log
tail -f /var/log/lg-hardening.log
```

## License

MIT License — see [LICENSE](LICENSE)
