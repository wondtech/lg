# Linux Guardian

<img src="https://lg.wondtech.com/logo.png" alt="Linux Guardian" width="200">

**[Linux Guardian v1.1](https://lg.wondtech.com/)** — Production-Ready Linux Server Security Hardening https://lg.wondtech.com/

## Overview

Linux Guardian implements a **Defence in Depth** strategy — multiple independent security layers stacked on top of each other. On the second run, it automatically displays a live security status dashboard with integrated scan, behavior analysis, and integrity check.

## Quick Install

```bash
curl -L https://raw.githubusercontent.com/mogbil/lg/main/lg.sh -o /tmp/lg.sh && mv /tmp/lg.sh /usr/local/bin/lg && chmod +x /usr/local/bin/lg && lg
```

With sudo:

```bash
curl -L https://raw.githubusercontent.com/mogbil/lg/main/lg.sh -o /tmp/lg.sh && sudo mv /tmp/lg.sh /usr/local/bin/lg && sudo chmod +x /usr/local/bin/lg && sudo lg
```

Verify before running:

```bash
bash -n /usr/local/bin/lg && echo "Syntax OK"
```

## Usage

```bash
sudo lg                         # First run — interactive, applies all layers
sudo lg                         # Second run — security status dashboard (automatic)
sudo lg --force                 # Re-apply all layers
sudo lg --auto                  # Auto mode — no prompts
sudo lg --dry-run               # Preview every change — zero modifications
sudo lg --undo                  # Rollback all changes from last run
sudo lg --cron                  # Silent mode — logs to /var/log/lg-hardening.log
sudo lg --watch                 # Monitor for new sites and harden automatically
sudo lg --fixmail               # Fix Dovecot/vmail SELinux contexts and policy
sudo lg --scan                  # Scan for webshells and reverse shells
sudo lg --scan --path /var/www  # Scan a specific directory
sudo lg --auto-analyze          # Start background behavior monitoring (daemon)
sudo lg --integrity             # Check integrity of critical system files
sudo lg --update                # Update to latest version from lg.wondtech.com
sudo lg --help                  # Show all options
```

## Security Layers

| Layer | Name | What it does |
|-------|------|--------------|
| [1] | **Binary Lockdown** | Restricts nc, gcc, python, perl, curl, wget and 30+ tools to root only |
| [2] | **Kernel Hardening** | Blocks dccp, sctp, rds, tipc modules — applies ASLR, SYN cookies, reverse path filtering |
| [3] | **System Files** | Hardens /etc/shadow, /etc/passwd, sshd_config, cron directories |
| [4] | **Apache & MySQL / MariaDB** | ServerTokens, ServerSignature, UseCanonicalName and Binds database to 127.0.0.1 |
| [5] | **PHP Hardening** | Disables 60+ dangerous functions + sets open_basedir per site + date.timezone |
| [5.1] | **PHP-FPM Pools** | Creates an isolated pool per site with open_basedir, session dir, and logs |
| [5.2] | **Panel php.ini** | Fixes date.timezone in all panel-specific php.ini files |
| [6] | **noexec** | Applies noexec/nosuid/nodev to /tmp, /var/tmp, and all site directories |
| [7] | **AppArmor / SELinux** | Enforces MAC — fixes vmail/Dovecot contexts — loads dovecot_lg policy |
| [8] | **Auditd** | Real-time alerts for webshell execution, privilege escalation, file changes |
| [A] | **FTP + ClamAV** | Scans uploaded files — infected files removed immediately |
| [B] | **Snuffleupagus** | PHP RASP runtime protection |

## Supported Control Panels

Auto-detected — fixes `date.timezone` and `open_basedir` for each panel's PHP paths:

| Panel | PHP paths | Restart |
|-------|-----------|---------|
| CWP | `/usr/local/cwp/**` | cwpsrv |
| cPanel / WHM | `/usr/local/lib/php*/**` + `/opt/cpanel/**` | — |
| Plesk | `/opt/plesk/**` + `/usr/local/psa/**` | psa |
| DirectAdmin | `/usr/local/php/**` | — |
| CyberPanel | `/usr/local/lsws/**` | lsws |
| HestiaCP / VestaCP | `/etc/php/**` | — |
| ISPConfig | `/etc/php/**` | — |
| aaPanel | `/www/server/php/**` | — |
| Webmin / Virtualmin | `/etc/php/**` | — |
| InterWorx | `/usr/local/interworx/**` | — |
| Froxlor | `/etc/php/**` | — |
| RunCloud | `/etc/php/**` | — |
| CentminMod | `/usr/local/lib/php*/**` | — |

## open_basedir

Applied automatically per PHP mode:

| Mode | How |
|------|-----|
| **PHP-FPM** | Per-site pool file — each site isolated independently |
| **PHP-CGI / mod_php** | Global php.ini — all site roots combined |
| **New user (cron)** | Added automatically when a new user/site is detected |

Site roots detected automatically for all panels:
`/home/*/public_html` · `/var/www/*` · `/var/www/vhosts/*/httpdocs` · `/home/*/web/*/public_html` · `/www/wwwroot/*` · `/var/customers/webs/*` · and more.

## Second Run — Status Dashboard

After the first run, `sudo lg` automatically shows:

```
────────────────────────────────────────────────────────────────────────
   Linux Guardian v1.1 — Security Status Dashboard
   Last applied: 2026-05-16 03:30:15
────────────────────────────────────────────────────────────────────────

  ✓ [1] Binary Lockdown       — active
  ✓ [2] Kernel Hardening      — active
  ✓ [3] System Files          — hardened
  ✓ [4.1] Apache httpd.conf   — hardened
  ✓ [4.2] MySQL/MariaDB       — bound to 127.0.0.1
  ✓ [5] PHP disable_functions — active (820 chars)
  i [5.1] PHP-FPM Pools       — 4 pool(s) active
  i [5.2] Panel php.ini       — CWP (tz: Asia/Riyadh)
  ✓ [6] noexec /tmp           — active
  ✓ [7] SELinux               — enforcing
  ✓ [8] Auditd                — active (12 rules)
  — [A] FTP + ClamAV          — not installed
  — [B] Snuffleupagus         — not installed

  ✓ Dovecot                   — running
  ✓ vmail context             — mail_spool_t
  ✓ dovecot_lg policy         — loaded
  — Auto-analyze              — stopped

[SCAN]      No suspicious files found
[ANALYZE]   System behavior looks normal
[INTEGRITY] All critical files intact

────────────────────────────────────────────────────────────────────────
  Run 'sudo lg --force'     to re-apply all layers
  Run 'sudo lg --fixmail'   to fix Dovecot/vmail
  Run 'sudo lg --undo'      to rollback
────────────────────────────────────────────────────────────────────────
```

## --fixmail

Fixes Dovecot/vmail SELinux independently without touching any other layer:

```bash
sudo lg --fixmail
```

1. Detects vmail path and correct SELinux type (`mail_spool_t` or `dovecot_var_t`)
2. Registers fcontext permanently (survives reboot)
3. Removes stale `.lock` files carrying `unlabeled_t`
4. Applies `restorecon -RF`
5. Compiles and loads `dovecot_lg` policy (MySQL socket + vmail access + mmap)
6. Re-registers fcontext after semodule
7. Restarts Dovecot

## --scan

```bash
sudo lg --scan
sudo lg --scan --path /var/www/html
```

Detects: PHP webshells (eval+base64, system(\$_GET, @eval, preg_replace /e, known signatures), Perl/Python reverse shells (socket+subprocess, /dev/tcp), executables in web directories.

Log: `/var/log/lg-scan.log` — email alert sent if findings exist.

## --auto-analyze

```bash
sudo lg --auto-analyze    # Start daemon
kill $(cat /var/run/lg-analyze.pid)  # Stop
```

Runs every 5 minutes in background. Monitors: processes from /tmp, new executables in /tmp, new SUID files vs baseline. Sends email alerts on detection.

## --analyze (automatic on second run)

Checks: outbound connections on unexpected ports, hidden processes, system files modified in last 24h, failed login brute force, suspicious crontab entries, unexpected listening ports.

## --integrity

```bash
sudo lg --integrity   # First run: builds SHA-256 database
sudo lg --integrity   # Subsequent: verifies all files
```

Monitors: /etc/passwd, /etc/shadow, /etc/sudoers, /etc/ssh/sshd_config, /usr/bin/sudo, /usr/sbin/sshd, and more.

Database: `/root/lg/integrity.db`

## --update

```bash
sudo lg --update
```

Downloads latest version from `https://lg.wondtech.com/lg.sh`, verifies syntax with `bash -n`, backs up current version, installs if newer.

## Interactive Prompts (first run)

```
Alert email for security notifications (default: root): admin@example.com

[INFO]    PHP date.timezone — detected: Asia/Riyadh
[INFO]    Examples: Asia/Riyadh  Asia/Dubai  UTC  America/New_York

Enter timezone (press Enter to keep [Asia/Riyadh]):
```

In `--auto` and `--cron` modes, detected values are used without prompting.

## Cron — Auto-hardening New Users

Added automatically after first install:

```
0 * * * * /usr/local/bin/lg --cron
```

Every hour: detects new users/sites added since last run and applies noexec, open_basedir, and PHP-FPM pool automatically. Logged to `/var/log/lg-hardening.log`.

## Undo / Rollback

```bash
sudo lg --undo
```

Restores: all modified files, original permissions, modprobe/sysctl configs, noexec mounts, fstab entries, AppArmor profiles, audit rules.

## Reboot After Hardening

Automatic 10-second countdown after first run (Ctrl+C to cancel). Required for SELinux relabel, kernel module blocks, and sysctl activation.

## Auditd Rules

| Rule | Monitored | Alert |
|------|-----------|-------|
| `tmp_exec` | Execution from /tmp or /var/tmp | Yes |
| `webshell` | Exec by web server user | Yes |
| `passwd_change` | Writes to /etc/passwd, /etc/shadow | Yes |
| `sudoers_change` | Writes to /etc/sudoers | Yes |
| `sshd_config` | Changes to sshd_config | Yes |
| `priv_esc` | setuid/setgid/setreuid syscalls | Yes |
| `home_exec` | Execution from /home | Yes |
| `php_config` | Changes to /etc/php | Yes |

## Files

```
/var/log/lg-hardening.log     Main hardening log
/var/log/lg-scan.log          Webshell scan results
/var/log/lg-analyze.log       Behavior analysis log
/root/lg/.applied             State file (triggers dashboard on second run)
/root/lg/.known_users         User baseline for cron new-user detection
/root/lg/.suid_baseline       SUID baseline for auto-analyze
/root/lg/integrity.db         File integrity SHA-256 database
/root/lg/backups/             Timestamped backups + undo manifests
/var/run/lg-analyze.pid       Auto-analyze daemon PID
```

## Verification

```bash
bash -n /usr/local/bin/lg && echo "Syntax OK"
php -r 'echo ini_get("disable_functions");' | tr , '\n' | wc -l
php -r 'echo ini_get("date.timezone");'
php -r 'echo ini_get("open_basedir");'
mount | grep noexec
sestatus 2>/dev/null || apparmor_status 2>/dev/null
semodule -l | grep dovecot_lg
ls -lZ /var/vmail/ 2>/dev/null | head -3
auditctl -l | grep webshell
sudo lg --scan
sudo lg --integrity
```

## Error Handling

`set -euo pipefail` — stops on unexpected errors. All detection calls (`timedatectl`, `sestatus`, `getsebool`, etc.) guarded with `|| true` for container/OpenVZ compatibility.

```bash
tail -50 /var/log/lg-hardening.log
```

## License

MIT License — see [LICENSE](LICENSE)
