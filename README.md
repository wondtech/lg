# Linux Guardian

<img src="https://lg.wondtech.com/logo.png" alt="Linux Guardian" width="200">

Linux Guardian v1.0 - Linux Server Security Hardening Script

## Features

- **Binary Lockdown** — Secures dangerous binaries (cc, gcc, python, perl, nc, etc.)
- **Kernel Protection** — Applies sysctl hardening and blocks vulnerable protocols, like (Dirty Frag, Copy Fail 1,2,3 etc.)
- **Network Hardening** — SSH configuration, iptables firewall, file permissions
- **PHP Security** — Hardens php.ini with disable_functions and security settings
- **FTP Protection** — Pure-FTPd + ClamAV upload scanning
- **Snuffleupagus** — Optional PHP RASP security module installation

## Requirements

- Linux server (Debian/Ubuntu/CentOS/RHEL)
- Root privileges
- PHP (for PHP hardening feature)
- bash 4.0+

## Quick Install

```bash
curl -L https://raw.githubusercontent.com/mogbil/lg/main/lg.sh | sudo tee /usr/local/bin/lg > /dev/null && sudo chmod +x /usr/local/bin/lg && sudo lg
```


## Run

```bash
# Interactive mode
sudo lg

# Silent mode for cron
sudo lg --cron

# Auto mode (no prompts)
sudo lg --auto

# Install auto-update cron job + user hook
sudo lg --setup-auto
```


## Auto-Update

When run with `--setup-auto`, installs:
- Cron job: runs daily at 3 AM
- User-add hook: `/usr/local/bin/php-security-update` — automatically applies hardening when new users are created

## Backups

All modified files are backed up to `/root/lg`

## License

MIT License — see [LICENSE](LICENSE)
