# Linux Guardian

<img src="https://lg.wondtech.com/logo.png" alt="Linux Guardian" width="200">

Linux Guardian v1.0 - Linux Server Security Hardening Script

## Features

- **Binary Lockdown** — Secures dangerous binaries (nc, gcc, python, perl, ruby, lua, node, etc.)
- **Kernel Protection** — Blocks vulnerable protocols (esp4, esp6, rxrpc, dccp, sctp, rds, tipc) and (Dirty Frag, Copy Fail 1,2,3 etc.)
- **System Files** — Secures /etc/shadow, /etc/group, and cron directories
- **PHP Security** — Hardens php.ini with disable_functions, open_basedir, and security settings
- **FTP Protection** — Pure-FTPd + ClamAV upload scanning
- **Snuffleupagus** — Optional PHP RASP security module

## Requirements

- Linux server (Debian/Ubuntu/CentOS/RHEL)
- Root privileges (sudo)
- PHP (for PHP hardening)
- bash 3.2+

## Quick Install

```bash
curl -L https://raw.githubusercontent.com/mogbil/lg/main/lg.sh -o /tmp/lg.sh && sudo mv /tmp/lg.sh /usr/local/bin/lg && sudo chmod +x /usr/local/bin/lg && sudo lg
```

## Run

```bash
# Interactive mode (prompts for confirmation)
sudo lg

# Auto mode (no prompts)
sudo lg --auto

# Silent mode for cron
sudo lg --cron

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