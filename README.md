# Linux Guardian

<img src="https://lg.wondtech.com/logo.png" alt="Linux Guardian" width="200">

Linux Guardian v1.0 — Production-Ready Linux Server Security Hardening Script

## Overview

Linux Guardian implements a **Defence in Depth** strategy — multiple independent security layers stacked on top of each other. Bypassing one layer does not compromise the server; the attacker must defeat all layers simultaneously.

## Security Layers

| Layer | Name | What it does |
|-------|------|--------------|
| [1] | **Binary Lockdown** | Restricts dangerous binaries (nc, gcc, python, perl, ruby, lua, node, wget, curl, etc.) to root only |
| [2] | **Kernel Hardening** | Blocks unused and vulnerable kernel modules (dccp, sctp, rds, tipc, rxrpc, esp4, esp6) eliminating their attack surface entirely, and applies sysctl hardening (ASLR, SYN cookies, reverse path filtering, kernel pointer hiding) to mitigate exploitation of kernel vulnerabilities such as Dirty Frag and CopyFail variants |
| [3] | **System Files** | Hardens permissions on /etc/shadow, /etc/passwd, /etc/gshadow, SSH config, and cron directories |
| [4] | **MySQL / MariaDB** | Binds database to 127.0.0.1 — blocks all remote database access |
| [5] | **PHP Hardening** | Global php.ini: disables 60+ dangerous functions (shell_exec, system, exec, passthru, proc_open, pcntl_*, posix_*, fsockopen...) and applies security settings |
| [5.1] | **PHP-FPM Pools** | Auto-detects all sites and creates an isolated pool per site — each site runs under its own user with its own open_basedir, session directory, and log files |
| [6] | **noexec (auto-detect)** | Auto-detects site roots from /var/www, /home/*/public_html, and Apache/Nginx configs — applies noexec, nosuid, nodev to /tmp, /var/tmp, and all site directories |
| [7] | **AppArmor / SELinux** | Auto-detects the available MAC system and enforces it — web server cannot exec binaries even if uploaded |
| [8] | **Auditd** | Real-time monitoring — logs and emails instant alerts for webshell execution, privilege escalation, and critical file changes |
| [A] | **FTP + ClamAV** | Pure-FTPd upload scanning — infected files are removed immediately and an alert email is sent |
| [B] | **Snuffleupagus** | Optional PHP RASP module — auto-detects PHP mode (FPM / CGI / mod_php) and configures a shared rules file accordingly |

## Requirements

- Linux server (Debian / Ubuntu / CentOS / RHEL / Rocky / AlmaLinux / Alpine / Arch)
- Root privileges
- bash 4.0+
- PHP (for PHP hardening layers)
- systemd

## Quick Install

```bash
curl -L https://raw.githubusercontent.com/mogbil/lg/main/lg.sh -o /tmp/lg.sh \
  && sudo mv /tmp/lg.sh /usr/local/bin/lg \
  && sudo chmod +x /usr/local/bin/lg \
  && sudo lg
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

# Watch mode — monitor for new sites and harden them automatically
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
- Dismounted noexec/nosuid/nodev mounts and /etc/fstab changes
- AppArmor profiles set back to complain mode
- Auditd rules removed

## Alert Email

During interactive mode, the script asks for a single alert email address used across all security layers:

```
Alert email for security notifications (default: root): admin@example.com
```

This email receives instant alerts from:

| Source | Trigger |
|--------|---------|
| **Auditd** | Webshell execution, privilege escalation, critical file changes |
| **ClamAV** | Infected file uploaded via FTP |

## PHP Hardening — Two Layers

### Layer 5 — Global php.ini (all sites)

Applied to every php.ini found on the server (excluding CLI):

- `disable_functions` — 60+ dangerous functions blocked globally
- `allow_url_fopen = Off`
- `allow_url_include = Off`
- `expose_php = Off`
- `display_errors = Off`
- Session security flags (httponly, secure, samesite=Strict)
- Upload and execution limits

### Layer 5.1 — PHP-FPM Pool per Site

Auto-detected and created for each site:

```ini
[mysite]
user  = mysite
group = mysite

; Per-site only — global settings inherited from php.ini
php_admin_value[open_basedir]   = /home/mysite/public_html:/tmp
php_value[session.save_path]    = /var/lib/php/sessions/mysite
php_admin_value[error_log]      = /var/log/php-fpm/mysite-error.log
```

If PHP-FPM is not installed, open_basedir falls back to php.ini directly.

## Watch Mode

Watch mode monitors the server for new websites and automatically hardens them.

```bash
sudo lg --watch
```

When a new site is detected under `/var/www` or `/home/*/public_html`, the script automatically:

1. Applies **noexec, nosuid, nodev** — bind-mounts the site directory with these flags
2. Creates a **PHP-FPM pool** with open_basedir, session isolation, and per-site logging (FPM mode)
3. Updates **open_basedir** in php.ini (CGI / mod_php mode)

Everything is logged to `/var/log/lg-hardening.log`:

```
[2024-01-15 14:32:01] [WATCH] New site detected: mysite (/var/www/mysite)
[2024-01-15 14:32:02] [WATCH] /var/www/mysite noexec,nosuid,nodev applied
[2024-01-15 14:32:02] [WATCH] PHP-FPM pool created: /etc/php-fpm.d/mysite.conf
[2024-01-15 14:32:02] [WATCH] mysite complete: noexec,nosuid,nodev + open_basedir + PHP-FPM pool
```

Press `Ctrl+C` to stop watching.

## Snuffleupagus (PHP RASP)

An optional PHP extension that adds runtime protection on top of disable_functions. The script auto-detects the PHP mode and configures it accordingly:

| PHP Mode | Configuration method |
|----------|---------------------|
| **PHP-FPM** | Added to each site's pool.conf |
| **PHP-CGI** | Added to php.ini |
| **mod_php** | Added to php.ini |

A single shared rules file is used for all sites: `/etc/snuffleupagus/lg.rules`

Rules include: dangerous function blocking, cookie encryption and protection, upload extension filtering, XXE protection, unserialize HMAC, and global strict mode.

```bash
# Verify active
php -m | grep -i snuffleupagus

# View or edit rules
cat /etc/snuffleupagus/lg.rules
```

## Monitoring (Auditd)

Audit rules that monitor and send email alerts:

| Rule key | What is monitored | Alert sent? |
|----------|-------------------|-------------|
| `tmp_exec` | Binary execution from /tmp or /var/tmp | ✅ |
| `webshell` | Any exec call by the web server user | ✅ |
| `passwd_change` | Writes to /etc/passwd or /etc/shadow | ✅ |
| `sudoers_change` | Writes to /etc/sudoers or /etc/sudoers.d | ✅ |
| `sshd_config` | Changes to /etc/ssh/sshd_config | ✅ |
| `priv_esc` | setuid / setgid / setreuid syscalls | ✅ |
| `home_exec` | Binary execution from /home | ✅ |
| `php_config` | Changes to /etc/php | ✅ |

Alerts are delivered via `/etc/audit/lg-alert.sh` registered as an audisp plugin. If audisp is unavailable, a cron fallback runs every minute.

Email subject: `[LG ALERT] webshell detected on server1`

```bash
# Search for suspicious activity
ausearch -k webshell -ts recent

# Daily report
aureport --start today

# Live log
tail -f /var/log/audit/audit.log
```

## Backups

All modified files are backed up before any change is applied:

```
/root/lg/backups/
├── phpini_php.ini.20240115_030000
├── phpfpm_pool_mysite.20240115_030000
├── mysql_my.cnf.20240115_030000
├── pureftpd_pure-ftpd.conf.20240115_030000
└── undo_manifest_20240115_030000.txt
```

Log file: `/var/log/lg-hardening.log`

## Verification

```bash
# Layer 5 — disable_functions
php -r 'echo ini_get("disable_functions");' | tr , '\n' | head -10

# Layer 5.1 — PHP-FPM pools
ls /etc/php-fpm.d/
systemctl status php-fpm

# Layer 6 — noexec/nosuid/nodev
mount | grep -E "noexec|nosuid"

# Layer 7 — MAC
sestatus 2>/dev/null || apparmor_status 2>/dev/null

# Layer 8 — Audit rules
auditctl -l | grep lg
ausearch -k webshell -ts recent

# Snuffleupagus
php -m | grep -i snuffleupagus

# Watch mode log
tail -f /var/log/lg-hardening.log
```

## License

MIT License — see [LICENSE](LICENSE)