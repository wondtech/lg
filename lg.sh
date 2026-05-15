#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Linux Guardian v1.0 — Production-Ready Server Security Hardening
# By WondTech.com | info@wondtech.com
#
# Security Layers (Defence in Depth):
#   [1] Binary Lockdown       — Restrict dangerous tools
#   [2] Kernel Hardening      — Harden kernel + sysctl
#   [3] System Files          — Secure critical file permissions
#   [4] MySQL/MariaDB         — Harden database configuration
#   [5] PHP disable_functions — Block shell_exec/system/exec
#   [6] noexec /tmp /var/tmp  — Prevent uploaded binary execution
#   [7] AppArmor / SELinux    — Mandatory access control for web server
#   [8] Auditd                — Real-time monitoring and alerting
#   [A] FTP + ClamAV          — Scan uploaded files for malware
#   [B] Snuffleupagus         — PHP RASP
#
# Usage:
#   sudo lg                  Interactive (recommended first run)
#   sudo lg --auto           Auto mode — no prompts
#   sudo lg --cron           Silent mode for cron jobs
#   sudo lg --dry-run        Preview changes without applying
#   sudo lg --undo           Rollback all changes from last run
#   sudo lg --watch          Watch for new sites and isolate them automatically
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ─── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Trap: clean exit on error ───────────────────────────────────────────────
_lg_exit() {
    local code=$?
    [ $code -eq 0 ] && return
    echo -e "\n  ${RED}[ERROR]${NC}   Script exited unexpectedly (code: ${code})" >&2
    echo -e "  ${YELLOW}[WARN]${NC}    Some layers may be incomplete — review log: ${LOG_FILE:-/var/log/lg-hardening.log}" >&2
}
trap '_lg_exit' EXIT

# ─── Banner ──────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${BOLD}${CYAN}"
    echo "────────────────────────────────────────────────────────────────────────"
    echo "   ▗▖   ▗▄▄▄▖▗▖  ▗▖▗▖ ▗▖▗▖  ▗▖  ▗▄▄▖▗▖ ▗▖ ▗▄▖ ▗▄▄▖ ▗▄▄▄ ▗▄▄▄▖ ▗▄▖ ▗▖ "
    echo "   ▐▌     █  ▐▛▚▖▐▌▐▌ ▐▌ ▝▚▞▘   ▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌  █  █  ▐▌ ▐▌▐▌"
    echo "   ▐▌     █  ▐▌ ▝▜▌▐▌ ▐▌  ▐▌    ▐▌▝▜▌▐▌ ▐▌▐▛▀▜▌▐▛▀▚▖▐▌  █  █  ▐▛▀▜▌▐▌"
    echo "   ▐▙▄▄▖▗▄█▄▖▐▌  ▐▌▝▚▄▞▘▗▞▘▝▚▖  ▝▚▄▞▘▝▚▄▞▘▐▌ ▐▌▐▌ ▐▌▐▙▄▄▀▗▄█▄▖▐▌ ▐▌▐▌"
    echo ""
    echo "   ╔══════════════════════════════════════════════════════════════════╗"
    echo "   ║  Linux Server Security Hardening  v1.0  |  WondTech.com          ║"
    echo "   ║  One Script · Defence in Depth · Zero Compromise                 ║"
    echo "   ╚══════════════════════════════════════════════════════════════════╝"
    echo "────────────────────────────────────────────────────────────────────────"
    echo -e "${NC}"
}

# ─── Logging helpers ─────────────────────────────────────────────────────────
log_ok()     { echo -e "  ${GREEN}[OK]${NC}      $*"; }
log_warn()   { echo -e "  ${YELLOW}[WARN]${NC}    $*"; }
log_skip()   { echo -e "  [SKIP]    $*"; }
log_info()   { echo -e "  ${CYAN}[INFO]${NC}    $*"; }
log_error()  { echo -e "  ${RED}[ERROR]${NC}   $*"; }
log_dry()    { echo -e "  ${YELLOW}[DRY-RUN]${NC} Would: $*"; }
section()    { echo ""; echo -e "${BOLD}${GREEN}══ $* ══${NC}"; echo ""; }

# ─── run_cmd: execute or print in dry-run ────────────────────────────────────
run_cmd() {
    if [ "$DRY_RUN" = true ]; then log_dry "$*"
    else "$@"; fi
}

# ─── backup_file: copy + record in undo manifest ─────────────────────────────
backup_file() {
    local src="$1" tag="${2:-file}"
    [ -f "$src" ] || return 0
    local dest="${BACKUP_DIR}/${tag}_$(basename "$src").${TIMESTAMP}"
    if [ "$DRY_RUN" = false ]; then
        cp "$src" "$dest"
        chmod 600 "$dest"
        echo "FILE:${src}:${dest}" >> "$UNDO_MANIFEST"
    fi
    log_info "Backup → $dest"
}

# ─── record_perm: save permissions for undo ──────────────────────────────────
record_perm() {
    local path="$1"
    [ -e "$path" ] || return 0
    [ "$DRY_RUN" = true ] && return 0
    local perm owner
    perm=$(stat -c '%a'   "$path" 2>/dev/null || echo "644")
    owner=$(stat -c '%U:%G' "$path" 2>/dev/null || echo "root:root")
    echo "PERM:${path}:${perm}:${owner}" >> "$UNDO_MANIFEST"
}

# ─── secure_binary: chmod 750 + chown root:root ──────────────────────────────
secure_binary() {
    local bin="$1"
    if [ -e "$bin" ]; then
        record_perm "$bin"
        if [ "$DRY_RUN" = true ]; then
            log_dry "chmod 750 chown root:root $bin"
        else
            chown root:root "$bin" 2>/dev/null
            chmod 750       "$bin" 2>/dev/null
            log_ok "Secured: $bin  →  $(stat -c '%A %U:%G' "$bin")"
        fi
    else
        log_skip "$bin"
    fi
}

# ─── svc_running: check if a service is active ───────────────────────────────
svc_running() {
    local svc
    for svc in "$@"; do
        systemctl is-active --quiet "$svc" 2>/dev/null && return 0
        service "$svc" status &>/dev/null 2>&1         && return 0
        pgrep -x "$svc" &>/dev/null                    && return 0
    done
    return 1
}

# ─── svc_installed: check if binary exists ───────────────────────────────────
svc_installed() {
    local bin
    for bin in "$@"; do
        command -v "$bin" &>/dev/null               && return 0
        [ -x "/usr/sbin/${bin}"       ]             && return 0
        [ -x "/usr/bin/${bin}"        ]             && return 0
        [ -x "/usr/local/sbin/${bin}" ]             && return 0
        [ -x "/usr/local/bin/${bin}"  ]             && return 0
    done
    return 1
}

# ─── find_conf: locate a config file from a list of candidate paths ──────────
# Usage: find_conf /etc/my.cnf /etc/mysql/my.cnf ...
# Prints the first found path; returns 1 if none found
find_conf() {
    local f
    for f in "$@"; do
        [ -f "$f" ] && echo "$f" && return 0
    done
    return 1
}

# ─── find_conf_deep: full filesystem search for a config file ────────────────
# Usage: find_conf_deep "my.cnf" [maxdepth]
# Prints first match; used as fallback when find_conf fails
find_conf_deep() {
    local name="$1" depth="${2:-8}"
    { find / -maxdepth "$depth" -type f -name "$name" \
        ! -path "*/proc/*" ! -path "*/sys/*" ! -path "*/dev/*" \
        2>/dev/null || true; } | head -1
}

# ─── install_pkg: cross-distro package install ───────────────────────────────
install_pkg() {
    local pkg="$1"
    if command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" 2>/dev/null
    elif command -v dnf &>/dev/null; then
        dnf install -y -q "$pkg" 2>/dev/null
    elif command -v yum &>/dev/null; then
        yum install -y -q "$pkg" 2>/dev/null
    elif command -v apk &>/dev/null; then
        apk add -q "$pkg" 2>/dev/null
    elif command -v pacman &>/dev/null; then
        pacman -S --noconfirm -q "$pkg" 2>/dev/null
    else
        return 1
    fi
}

# ── detect_php_mode: returns fpm / cgi / mod_php ─────────────────────────────
detect_php_mode() {
    for b in php-fpm php-fpm8.2 php-fpm8.1 php-fpm8.0 php-fpm7.4; do
        if command -v "$b" &>/dev/null \
           || [ -x "/usr/sbin/${b}" ] \
           || [ -x "/usr/local/sbin/${b}" ]; then
            echo "fpm"; return
        fi
    done
    if command -v php-cgi &>/dev/null \
       || [ -x "/usr/local/bin/php-cgi" ]; then
        echo "cgi"; return
    fi
    if httpd   -M 2>/dev/null | grep -qi "php" \
    || apache2 -M 2>/dev/null | grep -qi "php"; then
        echo "mod_php"; return
    fi
    echo "mod_php"
}

# ── find_pool_dir: locate PHP-FPM pool directory ─────────────────────────────
find_pool_dir() {
    for d in \
        /etc/php-fpm.d \
        /etc/php/8.2/fpm/pool.d /etc/php/8.1/fpm/pool.d \
        /etc/php/8.0/fpm/pool.d /etc/php/7.4/fpm/pool.d \
        /etc/php/fpm/pool.d /usr/local/etc/php-fpm.d; do
        [ -d "$d" ] && echo "$d" && return
    done
    echo ""
}

# ── restart_php_services: restart web/php services by mode ───────────────────
restart_php_services() {
    local mode="$1"
    case "$mode" in
        fpm)
            for svc in php-fpm php8.2-fpm php8.1-fpm php8.0-fpm php7.4-fpm; do
                systemctl is-active --quiet "$svc" 2>/dev/null \
                    && systemctl restart "$svc" 2>/dev/null \
                    && { log_ok "Restarted: $svc"; return 0; }
            done
            log_warn "No active php-fpm service — restart manually"
            ;;
        cgi|mod_php)
            local _restarted=0
            for svc in apache2 httpd nginx; do
                if systemctl is-active --quiet "$svc" 2>/dev/null; then
                    systemctl restart "$svc" 2>/dev/null \
                        && { log_ok "Restarted: $svc"; _restarted=$((_restarted+1)); } \
                        || log_warn "Failed to restart: $svc"
                fi
            done
            [ "$_restarted" -eq 0 ] && log_warn "No active web service found to restart"
            ;;
    esac
    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# INITIALISATION
# ══════════════════════════════════════════════════════════════════════════════

print_banner

# Root check
if [ "$(id -u)" -ne 0 ]; then
    log_error "Must be run as root.  Run: sudo $0"
    exit 1
fi

# Parse arguments
RUN_MODE="interactive"
DRY_RUN=false
UNDO_MODE=false

for arg in "$@"; do
    case "$arg" in
        --cron)    RUN_MODE="cron";  exec > /dev/null 2>&1 ;;
        --auto)    RUN_MODE="auto" ;;
        --dry-run) DRY_RUN=true ;;
        --undo)    UNDO_MODE=true ;;
        --watch)   ;; # handled after globals are set
        --help|-h) grep '^#   sudo lg' "$0"; exit 0 ;;
    esac
done

# Globals
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/lg/backups"
LOG_FILE="/var/log/lg-hardening.log"
UNDO_MANIFEST="${BACKUP_DIR}/undo_manifest_${TIMESTAMP}.txt"
MAC_SYSTEM="none"
PHP_SKIP=false
PHPFPM_SKIP=false        # set to true when Part 5.1 is skipped — respected by Part B FPM mode
PHP_INI_FILES=()
SELECTED_FILES=()
ALERT_EMAIL="root"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Tee output to log file (not in dry-run, not in cron)
if [ "$DRY_RUN" = false ] && [ "$RUN_MODE" != "cron" ]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

# ── Ask for alert email once — used by Auditd, ClamAV, and Watch mode ────────
if [[ "$RUN_MODE" == "interactive" ]] && [ "$DRY_RUN" = false ] && [ "$UNDO_MODE" = false ]; then
    echo ""
    read -r -p "  Alert email for security notifications (default: root): " _INPUT_EMAIL
    [ -n "$_INPUT_EMAIL" ] && ALERT_EMAIL="$_INPUT_EMAIL"
    echo -e "  ${GREEN}[OK]${NC}      Alert email: ${ALERT_EMAIL}"
    echo ""
fi

# Dry-run banner
if [ "$DRY_RUN" = true ]; then
    echo -e "${BOLD}${YELLOW}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║    DRY-RUN MODE — ZERO CHANGES WILL BE MADE     ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# UNDO MODE — Restore everything from last manifest
# ══════════════════════════════════════════════════════════════════════════════
if [ "$UNDO_MODE" = true ]; then
    section "UNDO — Restoring previous state"

    LATEST=$(ls -t "${BACKUP_DIR}"/undo_manifest_*.txt 2>/dev/null | head -1)
    if [ -z "${LATEST:-}" ]; then
        log_error "No undo manifest found in $BACKUP_DIR"
        exit 1
    fi
    log_info "Manifest: $LATEST"
    echo ""

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        T="${line%%:*}"
        REST="${line#*:}"
        case "$T" in
            FILE)
                ORIG="${REST%%:*}"
                BKUP="${REST#*:}"
                [ -f "$BKUP" ] \
                    && cp "$BKUP" "$ORIG" && log_ok "Restored: $ORIG" \
                    || log_warn "Backup missing: $BKUP"
                ;;
            PERM)
                # Format: PERM:path:mode:owner — owner may contain ':'
                _perm_path=$(echo "$REST" | cut -d: -f1)
                _perm_mode=$(echo "$REST" | cut -d: -f2)
                _perm_owner=$(echo "$REST" | cut -d: -f3-)
                if [ -e "$_perm_path" ]; then
                    chmod "$_perm_mode"  "$_perm_path" 2>/dev/null || true
                    chown "$_perm_owner" "$_perm_path" 2>/dev/null || true
                    log_ok "Restored perms: $_perm_path ($_perm_mode $_perm_owner)"
                fi
                ;;
            MOUNT_NOEXEC)
                MNT="$REST"
                mount -o remount,exec "$MNT" 2>/dev/null \
                    && log_ok "Re-enabled exec: $MNT" \
                    || log_warn "Could not remount: $MNT"
                ;;
            FSTAB_TMP)
                sed -i '/Linux Guardian: noexec/d'    /etc/fstab 2>/dev/null || true
                sed -i '/tmpfs.*noexec.*nosuid/d'     /etc/fstab 2>/dev/null || true
                log_ok "Removed noexec entries from /etc/fstab"
                ;;
            MODPROBE)
                rm -f "$REST" && log_ok "Removed modprobe conf: $REST"
                ;;
            SYSCTL)
                rm -f "$REST" || true
                sysctl --system &>/dev/null || true
                log_ok "Removed sysctl conf: $REST"
                ;;
            APPARMOR_PROFILE)
                aa-complain "$REST" 2>/dev/null && log_ok "AppArmor complain: $REST" || true
                ;;
            AUDITD_RULE)
                rm -f "$REST" || true
                systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
                log_ok "Removed audit rules: $REST"
                ;;
            NSPAWN_SERVICE)
                systemctl stop    "$REST" 2>/dev/null || true
                systemctl disable "$REST" 2>/dev/null || true
                rm -f "/etc/systemd/system/${REST}.service"
                rm -f "/etc/systemd/nspawn/${REST##nspawn-}.nspawn"
                systemctl daemon-reload 2>/dev/null || true
                log_ok "Removed: $REST"
                ;;
        esac
    done < "$LATEST"

    echo ""
    log_ok "Undo complete — system restored to previous state"
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT: Update packages
# ══════════════════════════════════════════════════════════════════════════════
if [ "$DRY_RUN" = false ]; then
    section "Pre-flight: Updating System Packages"
    if command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq   2>&1 | tail -2 || true
        DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq 2>&1 | tail -2 || true
        log_ok "Packages updated (apt)"
    elif command -v dnf &>/dev/null; then
        dnf update -y -q 2>&1 | tail -3 && log_ok "Packages updated (dnf)" || log_warn "dnf update failed — continuing"
    elif command -v yum &>/dev/null; then
        yum update -y -q 2>&1 | tail -3 && log_ok "Packages updated (yum)" || log_warn "yum update failed — continuing"
    elif command -v apk &>/dev/null; then
        apk update -q && apk upgrade -q && log_ok "Packages updated (apk)" || log_warn "apk update failed — continuing"
    elif command -v pacman &>/dev/null; then
        pacman -Syu --noconfirm -q 2>&1 | tail -3 && log_ok "Packages updated (pacman)" || log_warn "pacman update failed — continuing"
    else
        log_warn "No supported package manager found"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — Binary Lockdown
# Restrict tools an attacker could exploit after initial compromise
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 1: Binary Lockdown"
# NOTE: sudo chmod ls vi are intentionally excluded — would break the system

DANGEROUS_BINS=(
    # Network pivot tools
    /usr/bin/nc      /usr/bin/ncat      /usr/bin/netcat
    /usr/bin/socat   /usr/bin/telnet    /usr/bin/tftp
    # Post-exploitation scripting
    /usr/bin/ruby    /usr/bin/lua       /usr/bin/tclsh
    /usr/bin/expect  /usr/bin/node      /usr/bin/nodejs
    /usr/bin/perl
    # Compilers (privilege escalation helpers)
    /usr/bin/gcc     /usr/bin/cc        /usr/bin/g++    /usr/bin/c++
    # Download tools
    /usr/bin/wget    /usr/bin/curl      /usr/bin/lynx   /usr/bin/scp
    # Reconnaissance
    /usr/bin/nslookup  /usr/sbin/nslookup
    /usr/bin/traceroute /usr/sbin/traceroute
    # Legacy tools
    /usr/bin/rsh     /usr/bin/rlogin    /usr/bin/ftp
    /usr/bin/uudecode /usr/bin/uuencode
    /usr/bin/at      /usr/bin/wall
)

for bin in "${DANGEROUS_BINS[@]}"; do
    secure_binary "$bin"
done

log_info "Scanning for Python interpreters..."
while IFS= read -r pybin; do
    secure_binary "$pybin"
done < <({ find /usr/bin /usr/sbin /usr/local/bin /usr/libexec \
    -maxdepth 2 -type f \
    \( -name "python" -o -name "python[0-9]*" -o -name "platform-python*" \) \
    ! -type l 2>/dev/null || true; })

log_ok "Layer 1 complete"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — Kernel Hardening
# Harden the kernel: block unused protocols and apply sysctl parameters
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 2: Kernel Hardening"

MODPROBE_CONF="/etc/modprobe.d/99-lg-hardening.conf"
SYSCTL_CONF="/etc/sysctl.d/99-lg-hardening.conf"

if [ -d /etc/modprobe.d ]; then
    if [ "$DRY_RUN" = true ]; then
        log_dry "Create $MODPROBE_CONF blocking: dccp sctp rds tipc rxrpc esp4 esp6"
    else
        cat > "$MODPROBE_CONF" << 'EOF'
# Linux Guardian — block unused/vulnerable kernel modules
install dccp  /bin/false
install sctp  /bin/false
install rds   /bin/false
install tipc  /bin/false
install rxrpc /bin/false
install esp4  /bin/false
install esp6  /bin/false
EOF
        chmod 644 "$MODPROBE_CONF"
        echo "MODPROBE:${MODPROBE_CONF}" >> "$UNDO_MANIFEST"
        log_ok "Kernel modules blocked"
    fi
fi

for mod in dccp sctp rds tipc rxrpc esp4 esp6; do
    if lsmod 2>/dev/null | grep -q "^${mod} " 2>/dev/null; then
        run_cmd rmmod "$mod" 2>/dev/null && log_ok "Unloaded: $mod" || true
    else
        log_skip "Not loaded: $mod"
    fi
done

if [ "$DRY_RUN" = true ]; then
    log_dry "Create $SYSCTL_CONF with kernel/network hardening"
else
    cat > "$SYSCTL_CONF" << 'EOF'
# Linux Guardian — Kernel & Network Hardening

# ASLR
kernel.randomize_va_space = 2
# Restrict kernel log to root
kernel.dmesg_restrict = 1
# Hide kernel pointers
kernel.kptr_restrict = 2
# Disable core dumps for setuid programs
fs.suid_dumpable = 0
# SYN flood protection
net.ipv4.tcp_syncookies = 1
# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter     = 1
net.ipv4.conf.default.rp_filter = 1
# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects     = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects     = 0
# Do not forward/send redirects
net.ipv4.conf.all.send_redirects = 0
# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route = 0
# Protect hardlinks and symlinks (/tmp race attacks)
fs.protected_hardlinks = 1
fs.protected_symlinks  = 1
EOF
    chmod 644 "$SYSCTL_CONF"
    echo "SYSCTL:${SYSCTL_CONF}" >> "$UNDO_MANIFEST"
    sysctl -p "$SYSCTL_CONF" &>/dev/null \
        && log_ok "sysctl parameters applied" \
        || log_warn "Some sysctl parameters failed — normal in containers/OpenVZ"
fi

log_ok "Layer 2 complete"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — System Files Permissions
# Secure permissions on sensitive system files
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 3: System Files Permissions"

declare -A SYSFILE_PERMS=(
    ["/etc/shadow"]="600"
    ["/etc/gshadow"]="600"
    ["/etc/group"]="644"
    ["/etc/passwd"]="644"
    ["/etc/ssh/sshd_config"]="600"
)

for f in "${!SYSFILE_PERMS[@]}"; do
    if [ -f "$f" ]; then
        record_perm "$f"
        run_cmd chmod "${SYSFILE_PERMS[$f]}" "$f"
        log_ok "$f → ${SYSFILE_PERMS[$f]}"
    else
        log_skip "$f not found"
    fi
done
unset SYSFILE_PERMS

for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly \
               /etc/cron.monthly /etc/cron.weekly; do
    if [ -d "$crondir" ]; then
        record_perm "$crondir"
        run_cmd chmod 700 "$crondir"
        log_ok "$crondir → 700"
    fi
done

log_ok "Layer 3 complete"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — MySQL / MariaDB Hardening
# Harden database: bind to localhost only
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 4: MySQL / MariaDB Hardening"

# ── Step 1: Check if service is installed ────────────────────────────────────
if ! svc_installed mysqld mariadbd mysql mariadb; then
    log_skip "MySQL/MariaDB not installed — skipping"
else
    log_info "MySQL/MariaDB detected"

    # ── Step 2: Locate config file ───────────────────────────────────────────
    MY_CNF=$(find_conf \
        /etc/my.cnf \
        /etc/mysql/my.cnf \
        /etc/my.cnf.d/server.cnf \
        /etc/my.cnf.d/mariadb-server.cnf \
        /etc/mysql/mariadb.conf.d/50-server.cnf \
        /usr/local/etc/my.cnf) || true

    # fallback: deep filesystem search
    if [ -z "$MY_CNF" ]; then
        log_info "Searching filesystem for my.cnf..."
        MY_CNF=$(find_conf_deep "my.cnf") || true
    fi

    if [ -z "$MY_CNF" ]; then
        log_warn "MySQL/MariaDB installed but config file not found — skipping"
    else
        log_info "Config: $MY_CNF"
        backup_file "$MY_CNF" "mysql"

        if [ "$DRY_RUN" = true ]; then
            log_dry "Set bind-address = 127.0.0.1 in $MY_CNF"
        else
            # ── Step 3: Apply change ─────────────────────────────────────────
            if grep -q "^bind-address" "$MY_CNF" 2>/dev/null; then
                sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$MY_CNF"
            else
                printf '\n# Linux Guardian\nbind-address = 127.0.0.1\n' >> "$MY_CNF"
            fi
            log_ok "bind-address = 127.0.0.1"

            # ── Step 4: Restart service ──────────────────────────────────────
            if systemctl restart mariadb 2>/dev/null; then
                log_ok "MariaDB restarted"
            elif systemctl restart mysqld 2>/dev/null; then
                log_ok "MySQL restarted"
            elif systemctl restart mysql 2>/dev/null; then
                log_ok "MySQL restarted"
            elif service mariadb restart 2>/dev/null; then
                log_ok "MariaDB restarted (service)"
            elif service mysqld restart 2>/dev/null; then
                log_ok "MySQL restarted (service)"
            else
                log_warn "Could not restart DB — restart manually"
            fi
        fi
    fi
fi

log_ok "Layer 4 complete"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5 — PHP Security Hardening (disable_functions)
# Prevent PHP from executing shell commands
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 5: PHP Security Hardening (disable_functions)"

# find exits non-zero when it hits unreadable dirs — isolate with subshell
# to prevent pipefail from killing the script
TMPF=$(mktemp)
{ find / -maxdepth 7 -type f -name "php.ini" 2>/dev/null || true; } \
    | sort -u > "$TMPF"
while IFS= read -r line; do PHP_INI_FILES+=("$line"); done < "$TMPF"
rm -f "$TMPF"

if [ ${#PHP_INI_FILES[@]} -eq 0 ]; then
    log_warn "No php.ini found — skipping PHP hardening"
    PHP_SKIP=true
else
    log_info "Found ${#PHP_INI_FILES[@]} php.ini file(s):"
    for i in "${!PHP_INI_FILES[@]}"; do
        f="${PHP_INI_FILES[$i]}"
        ctx=""
        [[ "$f" == *cli*    ]] && ctx=" [CLI]"
        [[ "$f" == *apache* || "$f" == *httpd* ]] && ctx=" [Apache]"
        [[ "$f" == *fpm*    ]] && ctx=" [PHP-FPM]"
        printf "    [%d] %s%s\n" $((i+1)) "$f" "$ctx"
    done
    echo ""

    if [[ "$RUN_MODE" == "cron" || "$RUN_MODE" == "auto" || "$DRY_RUN" == "true" ]]; then
        SELECTED_FILES=("${PHP_INI_FILES[@]}")
        PHP_SKIP=false
    else
        echo "  Select php.ini files:  a=all  s=skip  1,3=specific"
        read -r -p "  Your choice: " choice
        echo ""
        if [[ "$choice" =~ ^[sS]$ ]]; then
            PHP_SKIP=true
            log_skip "PHP hardening skipped"
        else
            PHP_SKIP=false
            if [[ "$choice" =~ ^[aA]$ ]]; then
                SELECTED_FILES=("${PHP_INI_FILES[@]}")
            else
                IFS=',' read -ra nums <<< "$choice"
                for n in "${nums[@]}"; do
                    n=$(echo "$n" | tr -d ' ')
                    if [[ "$n" =~ ^[0-9]+$ ]] && \
                       [ "$n" -ge 1 ] && [ "$n" -le "${#PHP_INI_FILES[@]}" ]; then
                        SELECTED_FILES+=("${PHP_INI_FILES[$((n-1))]}")
                    else
                        log_warn "Invalid selection ignored: $n"
                    fi
                done
            fi
            if [ ${#SELECTED_FILES[@]} -eq 0 ]; then
                log_warn "No valid files selected — skipping PHP hardening"
                PHP_SKIP=true
            fi
        fi
    fi
fi

if [ "$PHP_SKIP" = false ] && [ ${#SELECTED_FILES[@]} -gt 0 ]; then

    DISABLE_FUNCTIONS="exec,passthru,shell_exec,system,popen,proc_open,proc_close,\
proc_get_status,proc_terminate,proc_nice,pcntl_exec,pcntl_fork,pcntl_signal,\
pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,\
pcntl_wexitstatus,pcntl_wstopsig,pcntl_signal_dispatch,pcntl_get_last_error,\
pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_alarm,\
pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,posix_kill,posix_mkfifo,\
posix_setpgid,posix_setsid,posix_setuid,posix_setgid,posix_seteuid,posix_setegid,\
fsockopen,pfsockopen,stream_socket_client,stream_socket_server,socket_create,\
socket_connect,socket_bind,socket_listen,socket_accept,phpinfo,show_source,\
highlight_file,symlink,link,dl,assert,create_function,parse_ini_file,\
opcache_get_status,opcache_reset,putenv,apache_setenv"

    # Declared once outside loop — avoids redeclaration and state leakage
    declare -A PHPSEC=(
        ["allow_url_fopen"]="Off"
        ["allow_url_include"]="Off"
        ["expose_php"]="Off"
        ["display_errors"]="Off"
        ["log_errors"]="On"
        ["disable_classes"]="Imagick,gs"
        ["file_uploads"]="On"
        ["upload_tmp_dir"]="/tmp"
        ["upload_max_filesize"]="2M"
        ["session.cookie_httponly"]="1"
        ["session.cookie_secure"]="1"
        ["session.use_strict_mode"]="1"
        ["session.use_only_cookies"]="1"
        ["session.cookie_samesite"]="Strict"
        ["enable_dl"]="Off"
        ["max_execution_time"]="30"
        ["max_input_time"]="30"
        ["memory_limit"]="128M"
        ["post_max_size"]="8M"
    )

    for inifile in "${SELECTED_FILES[@]}"; do
        log_info "Processing: $inifile"
        backup_file "$inifile" "phpini"

        if [ "$DRY_RUN" = true ]; then
            log_dry "Apply global security settings → $inifile"
            log_dry "  disable_functions (global)"
            log_dry "  session, error, limits (global)"
            log_dry "  open_basedir → set per-site in PART 5.1"
            continue
        fi

        # ── disable_functions (global — all sites) ────────────────────────────
        if grep -q "^disable_functions" "$inifile"; then
            sed -i "s|^disable_functions.*|disable_functions = ${DISABLE_FUNCTIONS}|" "$inifile"
        elif grep -q "^;disable_functions" "$inifile"; then
            sed -i "s|^;disable_functions.*|disable_functions = ${DISABLE_FUNCTIONS}|" "$inifile"
        else
            printf '\n; Linux Guardian %s\ndisable_functions = %s\n' \
                "$TIMESTAMP" "$DISABLE_FUNCTIONS" >> "$inifile"
        fi
        log_ok "disable_functions applied (global)"

        # ── Global security settings ──────────────────────────────────────────
        # open_basedir is intentionally excluded here —
        # it is set per-site in PART 5.1 (PHP-FPM pool) or via .htaccess
        for key in "${!PHPSEC[@]}"; do
            val="${PHPSEC[$key]}"
            if grep -qE "^\s*${key}\s*=" "$inifile"; then
                sed -i "s|^\s*${key}\s*=.*|${key} = ${val}|" "$inifile"
            elif grep -qE "^\s*;\s*${key}\s*=" "$inifile"; then
                sed -i "s|^\s*;\s*${key}\s*=.*|${key} = ${val}|" "$inifile"
            else
                echo "${key} = ${val}" >> "$inifile"
            fi
        done
        log_ok "Global security settings applied: $inifile"
    done
    unset PHPSEC

    # Restart services based on PHP mode
    if [ "$DRY_RUN" = false ]; then
        _L5_MODE=$(detect_php_mode 2>/dev/null || echo "mod_php")
        restart_php_services "$_L5_MODE"
    else
        log_dry "Restart PHP/web services"
    fi
fi

log_ok "Layer 5 complete"

# ══════════════════════════════════════════════════════════════════════════════
# PART 5.1 — PHP-FPM Pool per Site
# Auto-detects PHP-FPM config directory and creates isolated pool for each site
# Each site gets: own user, open_basedir, disable_functions, session, error_log
# ══════════════════════════════════════════════════════════════════════════════
section "PART 5.1: PHP-FPM Pool per Site (auto-detect)"

setup_phpfpm_pools() {

    # ── Detect php-fpm binary ─────────────────────────────────────────────────
    PHPFPM_BIN=""
    for b in php-fpm php-fpm8.2 php-fpm8.1 php-fpm8.0 php-fpm7.4 php-fpm74; do
        bp=$(command -v "$b" 2>/dev/null \
            || { [ -x "/usr/sbin/${b}"       ] && echo "/usr/sbin/${b}"; }       \
            || { [ -x "/usr/local/sbin/${b}" ] && echo "/usr/local/sbin/${b}"; } \
            || { [ -x "/usr/local/bin/${b}"  ] && echo "/usr/local/bin/${b}"; }  \
            || true)
        bp=$(echo "$bp" | head -1)
        if [ -n "$bp" ] && [ -x "$bp" ]; then
            PHPFPM_BIN="$bp"
            break
        fi
    done

    if [ -z "$PHPFPM_BIN" ]; then
        log_skip "php-fpm not found — skipping pool configuration"
        log_info "Install: dnf install php-fpm -y  (CentOS/RHEL)"
        log_info "Install: apt install php-fpm -y  (Ubuntu/Debian)"
        PHPFPM_SKIP=true
        return 0
    fi
    log_ok "php-fpm found: $PHPFPM_BIN"

    # ── Detect PHP-FPM pool directory ─────────────────────────────────────────
    POOL_DIR=""
    for d in \
        /etc/php-fpm.d \
        /etc/php/8.2/fpm/pool.d \
        /etc/php/8.1/fpm/pool.d \
        /etc/php/8.0/fpm/pool.d \
        /etc/php/7.4/fpm/pool.d \
        /etc/php/fpm/pool.d \
        /usr/local/etc/php-fpm.d; do
        [ -d "$d" ] && POOL_DIR="$d" && break
    done

    if [ -z "$POOL_DIR" ]; then
        log_warn "PHP-FPM pool directory not found — trying to locate..."
        POOL_DIR=$($PHPFPM_BIN --test 2>&1 \
            | grep -oP 'include=\K[^*]+' | head -1 | xargs dirname 2>/dev/null || true)
        [ -d "$POOL_DIR" ] || {
            log_warn "Cannot detect pool directory — skipping"
            PHPFPM_SKIP=true
            return 0
        }
    fi
    log_ok "PHP-FPM pool dir: $POOL_DIR"

    # ── Detect PHP-FPM service name ───────────────────────────────────────────
    PHPFPM_SVC=""
    for svc in php-fpm php8.2-fpm php8.1-fpm php8.0-fpm php7.4-fpm; do
        systemctl list-units --type=service --all 2>/dev/null \
            | grep -q "${svc}.service" && PHPFPM_SVC="$svc" && break
    done
    [ -z "$PHPFPM_SVC" ] && log_warn "php-fpm service not detected — will skip restart"

    # ── Detect sites ──────────────────────────────────────────────────────────
    SITES=()
    for d in /var/www/*/; do
        [ -d "$d" ] && [[ "$d" != "/var/www/html/" ]] && SITES+=("${d%/}")
    done
    for d in /home/*/public_html/; do
        [ -d "$d" ] && SITES+=("${d%/}")
    done
    [ ${#SITES[@]} -eq 0 ] && [ -d "/var/www/html" ] && SITES+=("/var/www/html")

    if [ ${#SITES[@]} -gt 0 ]; then
        mapfile -t SITES < <(printf '%s\n' "${SITES[@]}" | sort -u)
    fi

    if [ ${#SITES[@]} -eq 0 ]; then
        log_warn "No sites found — skipping pool creation"
        PHPFPM_SKIP=true
        return 0
    fi

    log_info "Creating pools for ${#SITES[@]} site(s):"
    for s in "${SITES[@]}"; do echo "    → $s"; done
    echo ""

    # ── Create pool per site ──────────────────────────────────────────────────
    SESSION_BASE="/var/lib/php/sessions"
    LOG_BASE="/var/log/php-fpm"
    [ "$DRY_RUN" = false ] && mkdir -p "$SESSION_BASE" "$LOG_BASE"

    for site in "${SITES[@]}"; do
        # Derive site name and user
        if [[ "$site" == /home/* ]]; then
            SITE_NAME=$(echo "$site" | cut -d/ -f3)
            SITE_USER="$SITE_NAME"
            SITE_ROOT="$site"
        else
            SITE_NAME=$(basename "$site")
            SITE_USER=$(stat -c '%U' "$site" 2>/dev/null || echo "www-data")
            SITE_ROOT="$site"
        fi

        # Fallback user if system user doesn't exist
        id "$SITE_USER" &>/dev/null || SITE_USER="www-data"
        SITE_GROUP=$(id -gn "$SITE_USER" 2>/dev/null || echo "www-data")

        # Detect web server socket owner
        SOCK_OWNER="apache"
        systemctl is-active --quiet nginx  2>/dev/null && SOCK_OWNER="nginx"
        systemctl is-active --quiet apache2 2>/dev/null && SOCK_OWNER="www-data"

        POOL_CONF="${POOL_DIR}/${SITE_NAME}.conf"
        SOCK_PATH="/run/php-fpm/${SITE_NAME}.sock"
        SESSION_PATH="${SESSION_BASE}/${SITE_NAME}"
        ERROR_LOG="${LOG_BASE}/${SITE_NAME}-error.log"
        OPEN_BASEDIR="${SITE_ROOT}:/tmp:/usr/share/php:/usr/share/pear"

        log_info "Pool: ${SITE_NAME}  user=${SITE_USER}  root=${SITE_ROOT}"

        if [ "$DRY_RUN" = true ]; then
            log_dry "Create ${POOL_CONF}"
            log_dry "  user=${SITE_USER}  open_basedir=${OPEN_BASEDIR}"
            continue
        fi

        mkdir -p "$SESSION_PATH" 2>/dev/null
        chown "${SITE_USER}:${SITE_GROUP}" "$SESSION_PATH" 2>/dev/null
        chmod 700 "$SESSION_PATH" 2>/dev/null
        backup_file "$POOL_CONF" "phpfpm_pool"

        cat > "$POOL_CONF" << EOF
; ══════════════════════════════════════════════════════
; Linux Guardian — PHP-FPM Pool: ${SITE_NAME}
; Generated: ${TIMESTAMP}
;
; Global settings (disable_functions, session security,
; limits) are inherited from php.ini
; Per-site: open_basedir + session path + logging
; ══════════════════════════════════════════════════════

[${SITE_NAME}]

; ── Process user ───────────────────────────────────────
user  = ${SITE_USER}
group = ${SITE_GROUP}

; ── Socket ─────────────────────────────────────────────
listen       = ${SOCK_PATH}
listen.owner = ${SOCK_OWNER}
listen.group = ${SOCK_OWNER}
listen.mode  = 0660

; ── Process management ─────────────────────────────────
pm                   = dynamic
pm.max_children      = 10
pm.start_servers     = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests      = 500

; ── Per-site: open_basedir ─────────────────────────────
; Restricts file access to this site's directory only
php_admin_value[open_basedir] = ${OPEN_BASEDIR}

; ── Per-site: session isolation ────────────────────────
; Each site stores sessions in its own directory
php_value[session.save_handler] = files
php_value[session.save_path]    = ${SESSION_PATH}

; ── Per-site: logging ──────────────────────────────────
php_admin_value[error_log] = ${ERROR_LOG}
access.log                 = ${LOG_BASE}/${SITE_NAME}-access.log
slowlog                    = ${LOG_BASE}/${SITE_NAME}-slow.log
request_slowlog_timeout    = 5s
EOF

        chmod 640 "$POOL_CONF"
        echo "FILE:${POOL_CONF}:${BACKUP_DIR}/phpfpm_pool_${SITE_NAME}.${TIMESTAMP}" \
            >> "$UNDO_MANIFEST"
        log_ok "Pool created: $POOL_CONF"
    done

    # ── Validate and restart php-fpm ──────────────────────────────────────────
    if [ "$DRY_RUN" = false ]; then
        echo ""
        if $PHPFPM_BIN --test 2>/dev/null; then
            log_ok "PHP-FPM config test passed"
        else
            log_warn "PHP-FPM config test failed — check pool files"
            $PHPFPM_BIN --test 2>&1 | tail -10
        fi

        if [ -n "$PHPFPM_SVC" ]; then
            systemctl enable "$PHPFPM_SVC" 2>/dev/null
            systemctl restart "$PHPFPM_SVC" 2>/dev/null \
                && log_ok "PHP-FPM restarted: $PHPFPM_SVC" \
                || log_warn "Could not restart $PHPFPM_SVC — restart manually"

            echo ""
            log_info "Verify pools:"
            echo "    systemctl status ${PHPFPM_SVC}"
            echo "    ls ${POOL_DIR}/"
            echo "    ls /run/php-fpm/"
        fi
    fi
}

setup_phpfpm_pools || log_warn "Part 5.1: PHP-FPM pool setup encountered an issue — check log for details"

log_ok "Part 5.1 complete"

# Auto-detects site roots and applies noexec to prevent binary execution
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 6: noexec on writable directories (auto-detect)"

# ── Helper: apply noexec to a single directory ────────────────────────────────
# For /tmp /var/tmp : safe to overlay with tmpfs if not a mountpoint
# For site dirs     : bind-mount only — never replace with tmpfs (has real data)
_apply_noexec_dir() {
    local mnt="$1"
    local allow_tmpfs="${2:-false}"   # true only for /tmp and /var/tmp
    local size="${3:-256M}"

    # Already noexec?
    if mount 2>/dev/null | grep -qE " on ${mnt} .*noexec"; then
        log_ok "${mnt}  →  already noexec"
        return 0
    fi

    if mountpoint -q "$mnt" 2>/dev/null; then
        # Separate mountpoint — safe to remount
        if [ "$DRY_RUN" = true ]; then
            log_dry "remount ${mnt} noexec,nosuid,nodev"
        else
            mount -o remount,noexec,nosuid,nodev "$mnt" 2>/dev/null \
                && log_ok "${mnt}  →  remounted noexec" \
                || { log_warn "${mnt}  →  remount failed"; true; }
            echo "MOUNT_NOEXEC:${mnt}" >> "$UNDO_MANIFEST"
        fi

        # Persist in /etc/fstab
        if [ "$DRY_RUN" = false ]; then
            if grep -qE "\s${mnt}\s" /etc/fstab 2>/dev/null; then
                if ! grep -E "\s${mnt}\s" /etc/fstab | grep -q "noexec"; then
                    sed -i "/\s${mnt//\//\\/}\s/ s/defaults/defaults,noexec,nosuid,nodev/" \
                        /etc/fstab 2>/dev/null
                    echo "FSTAB_TMP:${mnt}" >> "$UNDO_MANIFEST"
                    log_ok "${mnt}  →  noexec persisted in /etc/fstab"
                fi
            fi
        fi

    elif [ "$allow_tmpfs" = "true" ]; then
        # Not a mountpoint + tmpfs allowed (/tmp, /var/tmp)
        if [ "$DRY_RUN" = true ]; then
            log_dry "overlay ${mnt} with tmpfs noexec (size=${size})"
        else
            mount -t tmpfs -o "size=${size},noexec,nosuid,nodev" tmpfs "$mnt" 2>/dev/null \
                && log_ok "${mnt}  →  overlaid with noexec tmpfs (${size})" \
                || log_warn "${mnt}  →  tmpfs overlay failed"
            echo "MOUNT_NOEXEC:${mnt}" >> "$UNDO_MANIFEST"
        fi

        # Persist in /etc/fstab
        if [ "$DRY_RUN" = false ]; then
            if ! grep -qE "tmpfs\s+${mnt}\s" /etc/fstab 2>/dev/null; then
                echo "# Linux Guardian: noexec ${mnt}" >> /etc/fstab
                echo "tmpfs ${mnt} tmpfs defaults,noexec,nosuid,nodev,size=${size} 0 0" \
                    >> /etc/fstab
                echo "FSTAB_TMP:${mnt}" >> "$UNDO_MANIFEST"
                log_ok "${mnt}  →  added to /etc/fstab"
            fi
        fi

    else
        # Not a mountpoint + no tmpfs allowed → bind-mount on itself
        if [ "$DRY_RUN" = true ]; then
            log_dry "bind-mount ${mnt} noexec,nosuid,nodev"
        else
            if mount --bind "$mnt" "$mnt" 2>/dev/null; then
                if mount -o remount,noexec,nosuid,nodev,bind "$mnt" 2>/dev/null; then
                    log_ok "${mnt}  →  bind-mounted noexec"
                    echo "MOUNT_NOEXEC:${mnt}" >> "$UNDO_MANIFEST"
                else
                    log_warn "${mnt}  →  remount after bind failed"
                    # Undo the bind since remount failed
                    umount "$mnt" 2>/dev/null || true
                fi
            else
                log_warn "${mnt}  →  bind-mount failed"
            fi
        fi
    fi
}

# ── Auto-detect all site root directories ────────────────────────────────────
detect_site_roots() {
    local roots=()

    # 1. /var/www subdirectories (each site)
    for d in /var/www/*/; do
        [ -d "$d" ] && roots+=("${d%/}")
    done
    # If no subdirs, use /var/www itself
    [ ${#roots[@]} -eq 0 ] && [ -d /var/www ] && roots+=("/var/www")

    # 2. /home/USER/public_html
    for d in /home/*/public_html/; do
        [ -d "$d" ] && roots+=("${d%/}")
    done

    # 3. Custom paths from Apache/Nginx config (DocumentRoot / root)
    for conf in \
        /etc/apache2/sites-enabled/*.conf \
        /etc/httpd/conf.d/*.conf \
        /etc/nginx/sites-enabled/* \
        /etc/nginx/conf.d/*.conf; do
        [ -f "$conf" ] || continue
        while IFS= read -r docroot; do
            [ -d "$docroot" ] && roots+=("$docroot")
        done < <(grep -hEi \
            '^\s*(DocumentRoot|root)\s+"?([^";\s]+)"?' "$conf" 2>/dev/null \
            | awk '{print $NF}' | tr -d '"')
    done

    # Deduplicate — only print if roots has entries
    if [ ${#roots[@]} -gt 0 ]; then
        printf '%s\n' "${roots[@]}" | sort -u
    fi
}

# ── Apply noexec to /tmp and /var/tmp ─────────────────────────────────────────
log_info "Applying noexec to temp directories..."
_apply_noexec_dir "/tmp"     "true"  "256M"
_apply_noexec_dir "/var/tmp" "true"  "128M"

# ── Auto-detect and apply noexec to site directories ─────────────────────────
log_info "Auto-detecting site directories..."
echo ""

SITE_ROOTS=()
while IFS= read -r root; do
    SITE_ROOTS+=("$root")
done < <(detect_site_roots)

if [ ${#SITE_ROOTS[@]} -eq 0 ]; then
    log_warn "No site directories detected"
else
    log_info "Detected ${#SITE_ROOTS[@]} site root(s):"
    for r in "${SITE_ROOTS[@]}"; do
        echo "    → $r"
    done
    echo ""
    for root in "${SITE_ROOTS[@]}"; do
        _apply_noexec_dir "$root" "false"
    done
fi

log_ok "Layer 6 complete"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 7 — AppArmor / SELinux (MAC)
# Auto-installs and enforces the appropriate MAC system for this distro
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 7: MAC — AppArmor / SELinux (auto-install + enforce)"

# ── Helper: install AppArmor ──────────────────────────────────────────────────
install_apparmor() {
    log_info "Installing AppArmor..."
    if command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            apparmor apparmor-utils apparmor-profiles 2>/dev/null \
            && log_ok "AppArmor installed (apt)" && return 0
    elif command -v dnf &>/dev/null; then
        dnf install -y -q apparmor apparmor-utils 2>/dev/null \
            && log_ok "AppArmor installed (dnf)" && return 0
    elif command -v yum &>/dev/null; then
        yum install -y -q apparmor apparmor-utils 2>/dev/null \
            && log_ok "AppArmor installed (yum)" && return 0
    elif command -v apk &>/dev/null; then
        apk add -q apparmor 2>/dev/null \
            && log_ok "AppArmor installed (apk)" && return 0
    elif command -v pacman &>/dev/null; then
        pacman -S --noconfirm -q apparmor 2>/dev/null \
            && log_ok "AppArmor installed (pacman)" && return 0
    fi
    return 1
}

# ── Helper: enable AppArmor on boot (distro-aware) ───────────────────────────
enable_apparmor_boot() {
    # systemd
    if command -v systemctl &>/dev/null; then
        systemctl enable apparmor 2>/dev/null && return 0
    fi
    # OpenRC (Alpine)
    if command -v rc-update &>/dev/null; then
        rc-update add apparmor boot 2>/dev/null && return 0
    fi
    # Arch — needs kernel params
    if command -v pacman &>/dev/null; then
        if [ -f /etc/default/grub ]; then
            if ! grep -q "apparmor=1" /etc/default/grub; then
                sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor /' \
                    /etc/default/grub 2>/dev/null
                grub-mkconfig -o /boot/grub/grub.cfg &>/dev/null
                log_info "GRUB updated for AppArmor — reboot required"
            fi
        fi
        return 0
    fi
    return 1
}

# ── Helper: detect distro family ─────────────────────────────────────────────
detect_distro_family() {
    local _id _id_like
    if [ -f /etc/os-release ]; then
        _id=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"' || true)
        _id_like=$(grep "^ID_LIKE=" /etc/os-release | cut -d= -f2 | tr -d '"' || true)
        case "${_id}${_id_like}" in
            *rhel*|*centos*|*fedora*|*rocky*|*alma*) echo "rhel" ;;
            *debian*|*ubuntu*)                        echo "debian" ;;
            *alpine*)                                 echo "alpine" ;;
            *arch*|*manjaro*)                         echo "arch" ;;
            *)                                        echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

# ── Detect existing MAC system ────────────────────────────────────────────────
DISTRO_FAMILY=$(detect_distro_family)
log_info "Distro family: ${DISTRO_FAMILY}"

# Prefer SELinux on RHEL family, AppArmor on others
if command -v sestatus &>/dev/null; then
    MAC_SYSTEM="selinux"
elif command -v apparmor_status &>/dev/null; then
    MAC_SYSTEM="apparmor"
else
    # Not installed — decide what to install
    case "$DISTRO_FAMILY" in
        rhel)    MAC_SYSTEM="selinux_install" ;;
        *)       MAC_SYSTEM="apparmor_install" ;;
    esac
fi

log_info "MAC system: ${MAC_SYSTEM}"
echo ""

case "$MAC_SYSTEM" in

    # ── SELinux — already installed ───────────────────────────────────────────
    selinux)
        SE_STATUS=$(sestatus 2>/dev/null | awk '/SELinux status/{print $3}')
        SE_MODE=$(sestatus   2>/dev/null | awk '/Current mode/{print $3}')
        log_info "SELinux status: ${SE_STATUS}  mode: ${SE_MODE}"

        if [ "${SE_STATUS}" != "enabled" ]; then
            if [ "$DRY_RUN" = true ]; then
                log_dry "Enable SELinux in /etc/selinux/config + reboot"
            else
                sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
                log_warn "SELinux was disabled — set to enforcing in config"
                log_warn "A reboot is required to fully enable SELinux"
            fi
        else
            # Ensure enforcing mode
            if [ "${SE_MODE}" != "enforcing" ]; then
                if [ "$DRY_RUN" = true ]; then
                    log_dry "setenforce 1 + SELINUX=enforcing in /etc/selinux/config"
                else
                    setenforce 1 2>/dev/null \
                        && log_ok "SELinux: enforcing mode active" \
                        || { log_warn "setenforce 1 failed — check SELinux policy"; true; }
                    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
                fi
            else
                log_ok "SELinux already enforcing"
            fi

            # Ensure all filesystem labels are correct on next boot
            if [ "$DRY_RUN" = true ]; then
                log_dry "fixfiles -F onboot — schedule full filesystem relabel on next boot"
            else
                if command -v fixfiles &>/dev/null; then
                    if [ -f /.autorelabel ]; then
                        log_ok "SELinux: filesystem relabel already scheduled (/.autorelabel exists)"
                    else
                        fixfiles -F onboot 2>/dev/null \
                            && log_ok "SELinux: full filesystem relabel scheduled on next boot" \
                            || log_warn "fixfiles -F onboot failed — run manually if needed"
                    fi
                else
                    log_skip "fixfiles not found — install policycoreutils"
                fi
            fi

            # Harden httpd booleans
            if [ "$DRY_RUN" = true ]; then
                log_dry "Apply SELinux httpd security booleans"
            else
                declare -A SEBOOLS=(
                    ["httpd_execmem"]="off"
                    ["httpd_execute_tmp"]="off"
                    ["httpd_unified"]="off"
                    ["httpd_can_network_connect"]="off"
                    ["httpd_can_network_relay"]="off"
                )
                for b in "${!SEBOOLS[@]}"; do
                    # Pre-check — some policy versions do not support all booleans
                    if ! getsebool "$b" &>/dev/null; then
                        log_info "SELinux bool not supported on this policy version: $b (skipped)"
                        continue
                    fi
                    # Skip if already set to desired value — setsebool -P is slow
                    _current=$(getsebool "$b" 2>/dev/null | awk '{print $3}')
                    if [ "$_current" = "${SEBOOLS[$b]}" ]; then
                        log_ok "SELinux bool: $b = ${SEBOOLS[$b]} (already set)"
                        continue
                    fi
                    setsebool -P "$b" "${SEBOOLS[$b]}" 2>/dev/null \
                        && log_ok "SELinux bool: $b = ${SEBOOLS[$b]}" \
                        || log_warn "Failed to set bool: $b"
                done
                unset SEBOOLS
            fi
        fi
        MAC_SYSTEM="selinux"
        ;;

    # ── AppArmor — already installed ──────────────────────────────────────────
    apparmor)
        if [ "$DRY_RUN" = true ]; then
            log_dry "Enable AppArmor service + enforce web server profiles"
        else
            # Start and enable
            systemctl enable --now apparmor 2>/dev/null \
                || service apparmor start 2>/dev/null \
                || true
            log_ok "AppArmor service enabled"

            # Enforce web server profiles
            ENFORCED=0
            for prof in \
                /etc/apparmor.d/usr.sbin.apache2 \
                /etc/apparmor.d/usr.sbin.httpd \
                /etc/apparmor.d/usr.sbin.nginx; do
                if [ -f "$prof" ]; then
                    aa-enforce "$prof" 2>/dev/null \
                        && { log_ok "Enforcing: $prof"
                             echo "APPARMOR_PROFILE:${prof}" >> "$UNDO_MANIFEST"
                             ENFORCED=$((ENFORCED+1)); }
                fi
            done
            # php-fpm profiles (versioned names)
            for prof in /etc/apparmor.d/usr.sbin.php-fpm*; do
                [ -f "$prof" ] \
                    && aa-enforce "$prof" 2>/dev/null \
                    && { log_ok "Enforcing: $prof"
                         echo "APPARMOR_PROFILE:${prof}" >> "$UNDO_MANIFEST"; }
            done
            if [ "$ENFORCED" -eq 0 ]; then
                log_info "No web-server profiles found — attempting to install apparmor-profiles"
                install_pkg "apparmor-profiles" 2>/dev/null || true
                # retry after install
                for prof in \
                    /etc/apparmor.d/usr.sbin.apache2 \
                    /etc/apparmor.d/usr.sbin.httpd \
                    /etc/apparmor.d/usr.sbin.nginx; do
                    [ -f "$prof" ] \
                        && aa-enforce "$prof" 2>/dev/null \
                        && { log_ok "Enforcing: $prof"
                             echo "APPARMOR_PROFILE:${prof}" >> "$UNDO_MANIFEST"; }
                done
            fi
        fi
        ;;

    # ── SELinux — needs install (RHEL family without it active) ───────────────
    selinux_install)
        if [ "$DRY_RUN" = true ]; then
            log_dry "Install selinux-policy + setools + policycoreutils (RHEL/CentOS)"
        else
            log_info "Installing SELinux packages..."
            for pkg in selinux-policy selinux-policy-targeted \
                       setools policycoreutils policycoreutils-python-utils; do
                install_pkg "$pkg" 2>/dev/null || true
            done

            if command -v sestatus &>/dev/null; then
                log_ok "SELinux packages installed"
                # Enable in config
                if [ -f /etc/selinux/config ]; then
                    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
                    log_ok "SELinux set to enforcing in /etc/selinux/config"
                else
                    cat > /etc/selinux/config << 'SECONF'
# Linux Guardian — SELinux configuration
SELINUX=enforcing
SELINUXTYPE=targeted
SECONF
                    log_ok "SELinux config created"
                fi
                # Try to enable immediately
                setenforce 1 2>/dev/null \
                    && log_ok "SELinux enforcing — active now" \
                    || log_warn "SELinux will be enforcing after reboot"
                # Schedule full relabel on next boot
                if command -v fixfiles &>/dev/null; then
                    fixfiles -F onboot 2>/dev/null \
                        && log_ok "SELinux: full filesystem relabel scheduled on next boot" \
                        || log_warn "fixfiles -F onboot failed — run manually if needed"
                fi
                MAC_SYSTEM="selinux"
            else
                log_warn "SELinux install failed — trying AppArmor as fallback"
                MAC_SYSTEM="apparmor_install"
            fi
        fi
        # If SELinux install failed, fall back to AppArmor
        # (MAC_SYSTEM is already set to "apparmor_install" in that case)
        ;;

    # ── AppArmor — needs install (Debian/Ubuntu/Alpine/Arch) ─────────────────
    apparmor_install)
        if [ "$DRY_RUN" = true ]; then
            log_dry "Install AppArmor + apparmor-utils + apparmor-profiles"
            log_dry "Enable AppArmor service"
        else
            # Check kernel support first
            if grep -qi "CONFIG_SECURITY_APPARMOR=y\|CONFIG_SECURITY_APPARMOR=m" \
               /boot/config-"$(uname -r)" 2>/dev/null; then
                log_ok "Kernel supports AppArmor"
            else
                log_warn "Kernel AppArmor support unknown — attempting install anyway"
            fi

            if install_apparmor; then
                # Enable on boot
                enable_apparmor_boot && log_ok "AppArmor enabled on boot"

                # Start service
                systemctl start apparmor 2>/dev/null \
                    || service apparmor start 2>/dev/null \
                    || rc-service apparmor start 2>/dev/null \
                    || true

                # Verify
                if command -v apparmor_status &>/dev/null; then
                    log_ok "AppArmor installed and active"
                    MAC_SYSTEM="apparmor"
                    # Enforce available profiles
                    for prof in \
                        /etc/apparmor.d/usr.sbin.apache2 \
                        /etc/apparmor.d/usr.sbin.httpd \
                        /etc/apparmor.d/usr.sbin.nginx; do
                        [ -f "$prof" ] \
                            && aa-enforce "$prof" 2>/dev/null \
                            && { log_ok "Enforcing: $prof"
                                 echo "APPARMOR_PROFILE:${prof}" >> "$UNDO_MANIFEST"; }
                    done
                else
                    log_warn "AppArmor installed but not yet active — reboot may be required"
                fi
            else
                log_warn "Could not install AppArmor on this system"
                log_info "Install manually:"
                log_info "  Debian/Ubuntu : apt install apparmor apparmor-utils -y"
                log_info "  Alpine        : apk add apparmor"
                log_info "  Arch          : pacman -S apparmor"
                MAC_SYSTEM="none"
            fi
        fi
        ;;

    # ── No MAC system ─────────────────────────────────────────────────────────
    none)
        log_warn "No MAC system could be installed"
        ;;
esac

# Handle SELinux→AppArmor fallback (selinux_install failed, apparmor_install needed)
if [ "$MAC_SYSTEM" = "apparmor_install" ]; then
    log_info "Running AppArmor fallback install..."
    if install_apparmor; then
        enable_apparmor_boot && log_ok "AppArmor enabled on boot"
        systemctl start apparmor 2>/dev/null \
            || service apparmor start 2>/dev/null \
            || true
        if command -v apparmor_status &>/dev/null; then
            log_ok "AppArmor installed and active"
            MAC_SYSTEM="apparmor"
        else
            log_warn "AppArmor installed — reboot may be required"
        fi
    else
        log_warn "AppArmor install also failed"
        MAC_SYSTEM="none"
    fi
fi

log_ok "Layer 7 complete (MAC: ${MAC_SYSTEM})"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 8 — Auditd (Monitoring & Alerts)
# Monitor and log all suspicious activity in real time
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 8: Auditd — Monitoring & Alerts"

AUDIT_RULES="/etc/audit/rules.d/99-lg-hardening.rules"

# ── Step 1: Check if auditd is installed, install if missing ──────────────
if ! svc_installed auditctl auditd; then
    if [ "$DRY_RUN" = true ]; then
        log_dry "Install auditd package"
    else
        log_info "auditd not found — installing..."
        install_pkg "auditd" || install_pkg "audit" || true
    fi
fi

if ! svc_installed auditctl auditd && [ "$DRY_RUN" = false ]; then
    log_warn "auditd not available and could not be installed — skipping Layer 8"
else
    if [ "$DRY_RUN" = true ]; then
        log_dry "Create $AUDIT_RULES monitoring:"
        echo "    • exec in /tmp /var/tmp       (webshell)"
        echo "    • exec by web user (www-data) (PHP shell)"
        echo "    • writes to passwd/shadow/sudoers"
        echo "    • privilege escalation syscalls"
        echo "    • exec from /home"
    else
        mkdir -p /etc/audit/rules.d

        WWWUID=$(id -u www-data 2>/dev/null \
              || id -u apache   2>/dev/null \
              || echo "33")

        cat > "$AUDIT_RULES" << EOF
## Linux Guardian Audit Rules — ${TIMESTAMP}

# Webshell execution — exec from writable dirs
-a always,exit -F arch=b64 -S execve -F dir=/tmp     -k tmp_exec
-a always,exit -F arch=b32 -S execve -F dir=/tmp     -k tmp_exec
-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k tmp_exec

# PHP/Apache exec (web user uid=${WWWUID})
-a always,exit -F arch=b64 -S execve -F uid=${WWWUID} -k webshell

# Critical file modifications
-w /etc/passwd          -p wa -k passwd_change
-w /etc/shadow          -p wa -k shadow_change
-w /etc/sudoers         -p wa -k sudoers_change
-w /etc/sudoers.d       -p wa -k sudoers_change
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/crontab         -p wa -k cron_change
-w /etc/cron.d          -p wa -k cron_change

# Privilege escalation
-a always,exit -F arch=b64 -S setuid   -k priv_esc
-a always,exit -F arch=b64 -S setgid   -k priv_esc
-a always,exit -F arch=b64 -S setreuid -k priv_esc

# Exec from home directories
-a always,exit -F arch=b64 -S execve -F dir=/home -k home_exec

# PHP config changes
-w /etc/php -p wa -k php_config
EOF
        chmod 640 "$AUDIT_RULES"
        echo "AUDITD_RULE:${AUDIT_RULES}" >> "$UNDO_MANIFEST"

        # ── Email alert script — triggered by audisp ──────────────────────────
        AUDISP_ALERT="/etc/audit/lg-alert.sh"
        cat > "$AUDISP_ALERT" << ALERTEOF
#!/bin/bash
# Linux Guardian — Auditd email alert
# Called by audispd when a monitored rule fires
ALERT_EMAIL="${ALERT_EMAIL}"
LOG="${LOG_FILE}"

read -r -t 1 LINE || true
[ -z "\$LINE" ] && exit 0

# Only alert on our rule keys
echo "\$LINE" | grep -qE '"key":"(webshell|tmp_exec|priv_esc|passwd_change|shadow_change|sudoers_change|home_exec)"' || exit 0

TS=\$(date '+%Y-%m-%d %H:%M:%S')
HOST=\$(hostname)
KEY=\$(echo "\$LINE" | grep -oP '"key":"\K[^"]+')
COMM=\$(echo "\$LINE" | grep -oP '"comm":"\K[^"]+' || echo "unknown")
PID=\$(echo "\$LINE"  | grep -oP '"pid":\K[0-9]+'  || echo "?")

SUBJECT="[LG ALERT] \${KEY} detected on \${HOST}"
BODY=\$(printf "Linux Guardian Security Alert\n\nHost:    %s\nTime:    %s\nKey:     %s\nProcess: %s (PID %s)\n\nRaw event:\n%s\n\nLog: %s" \
    "\$HOST" "\$TS" "\$KEY" "\$COMM" "\$PID" "\$LINE" "\$LOG")

echo "\$BODY" | mail -s "\$SUBJECT" "\$ALERT_EMAIL" 2>/dev/null
echo "\$TS [ALERT] \$KEY — \$COMM (PID \$PID)" >> "\$LOG"
ALERTEOF
        chmod 750 "$AUDISP_ALERT"
        echo "AUDITD_RULE:${AUDISP_ALERT}" >> "$UNDO_MANIFEST"
        log_ok "Alert script: ${AUDISP_ALERT}  (email: ${ALERT_EMAIL})"

        # ── Register alert script with audisp ─────────────────────────────────
        AUDISP_PLUGIN_DIR=""
        [ -d /etc/audisp/plugins.d ] && AUDISP_PLUGIN_DIR="/etc/audisp/plugins.d"
        [ -d /etc/audit/plugins.d  ] && AUDISP_PLUGIN_DIR="/etc/audit/plugins.d"

        if [ -n "$AUDISP_PLUGIN_DIR" ]; then
            cat > "${AUDISP_PLUGIN_DIR}/lg-alert.conf" << PLUGEOF
active = yes
direction = out
path = ${AUDISP_ALERT}
type = always
format = json
PLUGEOF
            log_ok "Audisp plugin registered: ${AUDISP_PLUGIN_DIR}/lg-alert.conf"
            echo "AUDITD_RULE:${AUDISP_PLUGIN_DIR}/lg-alert.conf" >> "$UNDO_MANIFEST"
        else
            log_warn "audisp plugins directory not found — email alerts via cron fallback"
            # Fallback: cron checks audit log every minute
            AUDIT_CRON="/etc/cron.d/lg-audit-alert"
            cat > "$AUDIT_CRON" << CRONEOF
# Linux Guardian — audit alert fallback (runs every minute)
* * * * * root ausearch -k webshell -k tmp_exec -k priv_esc -ts recent 2>/dev/null | grep -q 'type=SYSCALL' && ausearch -k webshell -k tmp_exec -k priv_esc -ts recent 2>/dev/null | mail -s "[LG ALERT] Suspicious activity on \$(hostname)" ${ALERT_EMAIL}
CRONEOF
            chmod 640 "$AUDIT_CRON"
            echo "AUDITD_RULE:${AUDIT_CRON}" >> "$UNDO_MANIFEST"
            log_ok "Fallback cron alert installed: ${AUDIT_CRON}"
        fi

        systemctl enable auditd 2>/dev/null || true
        # Try multiple restart methods (CWP / OpenVZ may block systemctl)
        if systemctl restart auditd 2>/dev/null; then
            log_ok "Auditd restarted (systemctl)"
        elif service auditd restart 2>/dev/null; then
            log_ok "Auditd restarted (service)"
        else
            _auditd_pid=$(cat /var/run/auditd.pid 2>/dev/null || true)
            if [ -n "$_auditd_pid" ] && kill -HUP "$_auditd_pid" 2>/dev/null; then
                log_ok "Auditd reloaded (HUP signal)"
            else
                log_warn "Could not restart auditd — rules will apply after next reboot"
                log_info "Manual restart: service auditd restart"
            fi
        fi

        augenrules --load &>/dev/null \
            || auditctl -R "$AUDIT_RULES" &>/dev/null \
            || log_warn "Could not load rules live (will apply after reboot)"

        log_ok "Audit rules: $AUDIT_RULES"
        log_info "Monitor:  tail -f /var/log/audit/audit.log"
        log_info "Search:   ausearch -k webshell -ts recent"
        log_info "Report:   aureport --start today"
    fi
fi  # end auditd installed check

log_ok "Layer 8 complete"

# ══════════════════════════════════════════════════════════════════════════════
# PART A — FTP Security (Pure-FTPd + ClamAV)
# Scan FTP-uploaded files for malware
# ══════════════════════════════════════════════════════════════════════════════
section "PART A: FTP Security (Pure-FTPd + ClamAV)"

# ── Step 1: Check if Pure-FTPd is installed ─────────────────────────────────
if ! svc_installed pure-ftpd pure-ftpd-mysql pure-ftpd-postgresql; then
    log_skip "Pure-FTPd not installed — skipping FTP + ClamAV"
else
    log_info "Pure-FTPd detected"

    # ── Step 2: Locate config file ───────────────────────────────────────────
    PUREFTPD_CONF=$(find_conf \
        /etc/pure-ftpd.conf \
        /etc/pure-ftpd/pure-ftpd.conf \
        /usr/local/etc/pure-ftpd.conf \
        /usr/local/etc/pure-ftpd/pure-ftpd.conf) || true

    # fallback: deep filesystem search
    if [ -z "$PUREFTPD_CONF" ]; then
        log_info "Searching filesystem for pure-ftpd.conf..."
        PUREFTPD_CONF=$(find_conf_deep "pure-ftpd.conf") || true
    fi

    if [ -z "$PUREFTPD_CONF" ]; then
        log_warn "Pure-FTPd installed but config not found — CallUploadScript not set"
    else
        log_info "Config: $PUREFTPD_CONF"
        backup_file "$PUREFTPD_CONF" "pureftpd"

        if [ "$DRY_RUN" = true ]; then
            log_dry "Enable CallUploadScript in $PUREFTPD_CONF"
        else
            # ── Step 3: Apply change ─────────────────────────────────────────
            if grep -q "^CallUploadScript" "$PUREFTPD_CONF"; then
                sed -i 's/^CallUploadScript.*/CallUploadScript yes/' "$PUREFTPD_CONF"
            else
                echo "CallUploadScript yes" >> "$PUREFTPD_CONF"
            fi
            log_ok "CallUploadScript enabled in $PUREFTPD_CONF"
        fi
    fi

    # ── Step 4: Create ClamAV scanner ────────────────────────────────────────
    if [ "$DRY_RUN" = false ]; then
        mkdir -p /etc/pure-ftpd
        log_info "ClamAV alert email: ${ALERT_EMAIL}"
        cat > /etc/pure-ftpd/clamav_check.sh << CLAMAVEOF
#!/bin/bash
# Linux Guardian — ClamAV upload scanner
MAXSIZE=10485760
ALERT="${ALERT_EMAIL}"
[ -z "\$1" ] || [ ! -f "\$1" ] && exit 0
if [ "\${UPLOAD_SIZE:-0}" -le "\$MAXSIZE" ] && command -v clamdscan &>/dev/null; then
    if clamdscan --no-summary --infected "\$1" 2>/dev/null | grep -q FOUND; then
        RESULT=\$(clamdscan --no-summary --infected "\$1" 2>/dev/null)
        clamdscan --remove --no-summary "\$1" 2>/dev/null
        printf "Infected upload removed:\n%s\n" "\$RESULT" \
            | mail -s "[LG] Infected Upload" "\$ALERT"
    fi
fi
CLAMAVEOF
        chmod 750 /etc/pure-ftpd/clamav_check.sh
        log_ok "ClamAV scanner: /etc/pure-ftpd/clamav_check.sh"

        pkill -f pure-uploadscript 2>/dev/null || true
        /usr/sbin/pure-uploadscript -B -r /etc/pure-ftpd/clamav_check.sh 2>/dev/null \
            && log_ok "pure-uploadscript started" \
            || log_warn "pure-uploadscript failed — ensure Pure-FTPd is running"

        # ── Step 5: Restart Pure-FTPd to activate CallUploadScript ─────────────
        if systemctl restart pure-ftpd 2>/dev/null; then
            log_ok "Pure-FTPd restarted"
        elif systemctl restart pure-ftpd-mysql 2>/dev/null; then
            log_ok "Pure-FTPd (mysql) restarted"
        elif service pure-ftpd restart 2>/dev/null; then
            log_ok "Pure-FTPd restarted (service)"
        else
            log_warn "Could not restart Pure-FTPd — restart manually: systemctl restart pure-ftpd"
        fi
    fi
fi

log_ok "Part A complete"

# ══════════════════════════════════════════════════════════════════════════════
# PART B — Snuffleupagus (PHP RASP)
# Auto-detects PHP mode (FPM / CGI / mod_php)
# One shared rules file for ALL sites
# ══════════════════════════════════════════════════════════════════════════════
section "PART B: Snuffleupagus — PHP RASP"

# ── Main setup function ───────────────────────────────────────────────────────
setup_snuffleupagus() {

    PHP_MODE=$(detect_php_mode)
    log_info "PHP mode: ${PHP_MODE}"

    # ── Check / install ───────────────────────────────────────────────────────
    # If already installed and loaded — nothing to do, skip entirely
    if { php -m 2>/dev/null || true; } | grep -qi "snuffleupagus"; then
        log_ok "Snuffleupagus already installed and active — skipping"
        return 0
    fi
    # ── Not installed — prompt or auto-skip ──────────────────────────────────
    if [ "$DRY_RUN" = true ]; then
        log_dry "Install Snuffleupagus via PECL (mode: ${PHP_MODE})"
        log_dry "Create /etc/snuffleupagus/lg.rules (shared, all sites)"
        return 0
    elif [[ "$RUN_MODE" == "interactive" ]]; then
        read -r -p "  Install Snuffleupagus PHP RASP? [y/N]: " -n 1
        echo ""
        [[ $REPLY =~ ^[Yy]$ ]] || { log_skip "Snuffleupagus skipped"; return 0; }
    else
        log_skip "Snuffleupagus — run interactively to install"
        return 0
    fi

    log_info "Installing build dependencies..."
    if command -v apt-get &>/dev/null; then
        install_pkg php-dev
        install_pkg autoconf
        install_pkg build-essential
    elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
        install_pkg php-devel
        install_pkg autoconf
        install_pkg gcc
    fi

    if pecl install snuffleupagus 2>&1 | tail -15; then
        log_ok "Snuffleupagus installed via PECL"
    else
        log_warn "PECL install failed — see output above"
        return 0
    fi

    # ── Locate snuffleupagus.so ───────────────────────────────────────────────
    SNUFF_SO=""

    # Search common PHP extension directories
    for _snuff_dir in \
        /usr/lib/php /usr/local/lib/php \
        /usr/lib64/php /usr/local/lib64/php \
        /usr/lib/php7 /usr/lib/php8 \
        /usr/local/cwp/php71/lib/php \
        /usr/local/php/lib/php; do
        [ -d "$_snuff_dir" ] || continue
        _found=$(find "$_snuff_dir" -name "snuffleupagus.so" 2>/dev/null | head -1)
        if [ -n "$_found" ]; then
            SNUFF_SO="$_found"
            break
        fi
    done

    # Fallback: use PHP's own extension_dir
    if [ -z "$SNUFF_SO" ]; then
        _ext_dir=$(php -r "echo ini_get('extension_dir');" 2>/dev/null || true)
        [ -n "$_ext_dir" ] && [ -f "${_ext_dir}/snuffleupagus.so" ] \
            && SNUFF_SO="${_ext_dir}/snuffleupagus.so"
    fi

    # Last resort: full filesystem search
    if [ -z "$SNUFF_SO" ]; then
        log_info "Searching filesystem for snuffleupagus.so..."
        SNUFF_SO=$(find_conf_deep "snuffleupagus.so") || true
    fi

    if [ -z "$SNUFF_SO" ] || [ ! -f "$SNUFF_SO" ]; then
        log_warn "snuffleupagus.so not found — skipping Part B configuration"
        log_info "Try: find / -name snuffleupagus.so 2>/dev/null"
        return 0
    fi
    log_ok "snuffleupagus.so: $SNUFF_SO"

    # ── One shared rules file for ALL sites ───────────────────────────────────
    SNUFF_DIR="/etc/snuffleupagus"
    SNUFF_RULES="${SNUFF_DIR}/lg.rules"
    mkdir -p "$SNUFF_DIR"
    chmod 755 "$SNUFF_DIR"

    cat > "$SNUFF_RULES" << 'RULESEOF'
# ══════════════════════════════════════════════════════════════════════════════
# Linux Guardian — Snuffleupagus Rules (shared — all sites)
# ══════════════════════════════════════════════════════════════════════════════

# ── Disable dangerous execution functions ─────────────────────────────────────
sp.disable_function.function("system").drop();
sp.disable_function.function("exec").drop();
sp.disable_function.function("shell_exec").drop();
sp.disable_function.function("passthru").drop();
sp.disable_function.function("popen").drop();
sp.disable_function.function("proc_open").drop();
sp.disable_function.function("pcntl_exec").drop();
sp.disable_function.function("pcntl_fork").drop();
sp.disable_function.function("posix_setuid").drop();
sp.disable_function.function("posix_setgid").drop();
sp.disable_function.function("posix_seteuid").drop();
sp.disable_function.function("posix_setegid").drop();

# ── Eval — log first, switch to .drop() when confident ───────────────────────
sp.disable_function.function("eval").log();

# ── Cookie protection ─────────────────────────────────────────────────────────
sp.cookie.name("*").encrypt().samesite("Strict").readonly();

# ── Block dangerous upload extensions ────────────────────────────────────────
sp.upload.disable_upload.extensions("php,phtml,phar,php7,php8,pht").drop();

# ── XXE protection ────────────────────────────────────────────────────────────
sp.xxe_protection.enable();

# ── Unserialize HMAC — prevent object injection ───────────────────────────────
sp.unserialize_hmac.enable();

# ── Global strict mode ────────────────────────────────────────────────────────
sp.global_strict.enable();
RULESEOF

    chmod 640 "$SNUFF_RULES"
    log_ok "Shared rules: $SNUFF_RULES"

    # ── Enable in PHP based on detected mode ──────────────────────────────────
    case "$PHP_MODE" in

        # ── PHP-FPM: add to each site pool ───────────────────────────────────
        fpm)
            # Honour Part 5.1 skip — if pools were skipped, skip here too
            if [ "$PHPFPM_SKIP" = true ]; then
                log_skip "[FPM] Part 5.1 was skipped — skipping Snuffleupagus FPM injection"
                log_info "[FPM] Install php-fpm and re-run to enable Snuffleupagus"
            else
            POOL_DIR=$(find_pool_dir)
            if [ -z "$POOL_DIR" ]; then
                log_warn "[FPM] Pool directory not found — falling back to php.ini"
                PHP_MODE="mod_php"
            else
                ADDED_POOLS=0
                for pool_conf in "${POOL_DIR}"/*.conf; do
                    [ -f "$pool_conf" ] || continue
                    # Skip default www.conf — we have site-specific pools
                    [[ "$(basename "$pool_conf")" == "www.conf" ]] && continue
                    if ! grep -q "snuffleupagus" "$pool_conf" 2>/dev/null; then
                        backup_file "$pool_conf" "phpfpm_snuff"
                        cat >> "$pool_conf" << EOF

; ── Snuffleupagus (Linux Guardian) ───────────────────
; Loaded per-pool so each site uses the shared rules
php_admin_value[extension]                = ${SNUFF_SO}
php_admin_value[snuffleupagus.rules_file] = ${SNUFF_RULES}
EOF
                        log_ok "[FPM] Snuffleupagus → pool: $(basename "$pool_conf")"
                        ADDED_POOLS=$((ADDED_POOLS+1))
                    else
                        log_info "[FPM] Already enabled: $(basename "$pool_conf")"
                    fi
                done

                # No site pools yet — add to www.conf as fallback
                if [ "$ADDED_POOLS" -eq 0 ]; then
                    WWW_CONF="${POOL_DIR}/www.conf"
                    if [ -f "$WWW_CONF" ] && ! grep -q "snuffleupagus" "$WWW_CONF" 2>/dev/null; then
                        backup_file "$WWW_CONF" "phpfpm_snuff"
                        cat >> "$WWW_CONF" << EOF

; ── Snuffleupagus (Linux Guardian) ───────────────────
php_admin_value[extension]                = ${SNUFF_SO}
php_admin_value[snuffleupagus.rules_file] = ${SNUFF_RULES}
EOF
                        log_ok "[FPM] Snuffleupagus → www.conf (fallback)"
                    else
                        log_info "[FPM] No pools found and www.conf already configured"
                    fi
                fi
            fi
            fi  # end PHPFPM_SKIP check
            ;;

        # ── PHP-CGI: add extension to php.ini ────────────────────────────────
        # php-cgi reads php.ini on every request, so we load the extension
        # there. The rules_file is the same shared lg.rules.
        cgi)
            # Honour the same php.ini selection made in Layer 5
            if [ "$PHP_SKIP" = true ] || [ ${#SELECTED_FILES[@]} -eq 0 ]; then
                log_skip "[CGI] php.ini selection was skipped in Layer 5 — skipping Snuffleupagus injection"
                log_info "[CGI] Re-run and select php.ini files in Layer 5 to enable Snuffleupagus"
            else
                INI_TARGETS=()
                for f in "${SELECTED_FILES[@]}"; do
                    [ -f "$f" ] && [[ "$f" != *cli* ]] && INI_TARGETS+=("$f")
                done
                for inifile in "${INI_TARGETS[@]:-}"; do
                    [ -f "$inifile" ] || continue
                    if grep -q "snuffleupagus" "$inifile" 2>/dev/null; then
                        log_info "[CGI] Already enabled: $inifile"
                        continue
                    fi
                    backup_file "$inifile" "phpini_snuff"
                    printf '\n; Snuffleupagus (Linux Guardian)\nextension=%s\nsnuffleupagus.rules_file=%s\n' \
                        "$SNUFF_SO" "$SNUFF_RULES" >> "$inifile"
                    log_ok "[CGI] Snuffleupagus → $inifile"
                done
            fi
            ;;

        # ── mod_php: add extension to php.ini ────────────────────────────────
        mod_php)
            # Honour the same php.ini selection made in Layer 5
            if [ "$PHP_SKIP" = true ] || [ ${#SELECTED_FILES[@]} -eq 0 ]; then
                log_skip "[MOD_PHP] php.ini selection was skipped in Layer 5 — skipping Snuffleupagus injection"
                log_info "[MOD_PHP] Re-run and select php.ini files in Layer 5 to enable Snuffleupagus"
            else
                INI_TARGETS=()
                for f in "${SELECTED_FILES[@]}"; do
                    [ -f "$f" ] && [[ "$f" != *cli* ]] && INI_TARGETS+=("$f")
                done
                for inifile in "${INI_TARGETS[@]:-}"; do
                    [ -f "$inifile" ] || continue
                    if grep -q "snuffleupagus" "$inifile" 2>/dev/null; then
                        log_info "[MOD_PHP] Already enabled: $inifile"
                        continue
                    fi
                    backup_file "$inifile" "phpini_snuff"
                    printf '\n; Snuffleupagus (Linux Guardian)\nextension=%s\nsnuffleupagus.rules_file=%s\n' \
                        "$SNUFF_SO" "$SNUFF_RULES" >> "$inifile"
                    log_ok "[MOD_PHP] Snuffleupagus → $inifile"
                done
            fi
            ;;
    esac

    # FPM fallback (if PHP_MODE was changed from fpm to mod_php above)
    if [[ "$PHP_MODE" == "mod_php" ]] && \
       grep -rq "snuffleupagus" "${POOL_DIR:-/nonexistent}" 2>/dev/null; then
        log_info "FPM fallback already handled above"
    fi

    # ── Restart ───────────────────────────────────────────────────────────────
    echo ""
    restart_php_services "$PHP_MODE"

    echo ""
    log_ok "Rules file:  $SNUFF_RULES"
    log_info "Verify:    php -m | grep -i snuffleupagus"
    log_info "Edit rules: $SNUFF_RULES"
}

setup_snuffleupagus || log_warn "Part B: Snuffleupagus setup encountered an issue — check log for details"

log_ok "Part B complete"

# ══════════════════════════════════════════════════════════════════════════════
# PART C — Watch Mode (auto-isolate new sites)
# Monitors /var/www and /home for new sites and isolates them automatically
# Usage: sudo lg --watch
# ══════════════════════════════════════════════════════════════════════════════

watch_mode() {
    section "WATCH MODE — Auto-isolating new sites"

    # ── Require inotifywait ───────────────────────────────────────────────────
    if ! command -v inotifywait &>/dev/null; then
        log_warn "inotifywait not found — attempting install..."
        if command -v apt-get &>/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq inotify-tools 2>/dev/null
        elif command -v dnf &>/dev/null; then
            dnf install -y -q inotify-tools 2>/dev/null
        elif command -v yum &>/dev/null; then
            yum install -y -q inotify-tools 2>/dev/null
        elif command -v apk &>/dev/null; then
            apk add -q inotify-tools 2>/dev/null
        elif command -v pacman &>/dev/null; then
            pacman -S --noconfirm -q inotify-tools 2>/dev/null
        fi

        if ! command -v inotifywait &>/dev/null; then
            log_error "Could not install inotify-tools — watch mode unavailable"
            log_info "Install manually:"
            log_info "  Debian/Ubuntu : apt install inotify-tools -y"
            log_info "  CentOS/RHEL   : yum install inotify-tools -y"
            log_info "  Fedora        : dnf install inotify-tools -y"
            log_info "  Alpine        : apk add inotify-tools"
            return 1
        fi
        log_ok "inotify-tools installed"
    fi

    # ── Collect already-isolated sites (skip on next detection) ──────────────
    KNOWN_SITES=()
    for d in /var/lib/lg-nspawn/*/; do
        [ -d "$d" ] && KNOWN_SITES+=("$(basename "$d")")
    done

    log_ok "Watch mode started — monitoring for new sites"
    log_info "Watching: /var/www  |  /home"
    log_info "Log: ${LOG_FILE}"
    log_info "Press Ctrl+C to stop"
    echo ""

    # ── Watch loop ────────────────────────────────────────────────────────────
    # Disable pipefail for the inotifywait pipe — it exits non-zero on Ctrl+C
    set +e
    inotifywait \
        --monitor \
        --quiet \
        --event create \
        --event moved_to \
        --format '%w%f' \
        /var/www \
        /home \
        2>/dev/null | while IFS= read -r NEW_PATH; do
    set -e

        # Only care about directories
        [ -d "$NEW_PATH" ] || continue

        # Normalise site name
        SN=$(echo "$NEW_PATH" \
            | sed 's|/var/www/||;s|/home/||;s|/public_html||;s|/$||;s|/||g' \
            | tr -cd '[:alnum:]-_' \
            | cut -c1-32)

        # Skip if empty name
        [ -z "$SN" ] && continue

        # Skip known/already-isolated sites
        ALREADY_KNOWN=false
        for k in "${KNOWN_SITES[@]:-}"; do
            [ "$k" = "$SN" ] && ALREADY_KNOWN=true && break
        done
        [ "$ALREADY_KNOWN" = true ] && continue

        # Skip system directories
        case "$SN" in
            html|cgi-bin|lost+found|tmp|var|etc|bin|usr|lib|lib64|proc|sys|dev)
                continue ;;
        esac

        # ── New site detected ─────────────────────────────────────────────────
        TS=$(date '+%Y-%m-%d %H:%M:%S')
        echo ""
        echo -e "  ${GREEN}[${TS}]${NC} New site detected: ${BOLD}${SN}${NC}  (${NEW_PATH})"
        echo "${TS} [WATCH] New site detected: ${SN} (${NEW_PATH})" >> "$LOG_FILE"

        # Wait briefly for site files to be fully written
        sleep 2

        # ── Resolve actual site path ──────────────────────────────────────────
        RESOLVED_PATH=""

        # 1. Use the detected path if it exists
        if [ -d "$NEW_PATH" ]; then
            RESOLVED_PATH="$NEW_PATH"
        fi

        # 2. Try /var/www/<name>
        if [ -z "$RESOLVED_PATH" ] && [ -d "/var/www/${SN}" ]; then
            RESOLVED_PATH="/var/www/${SN}"
            log_info "Resolved to /var/www/${SN}"
        fi

        # 3. Try /home/<name>/public_html
        if [ -z "$RESOLVED_PATH" ] && [ -d "/home/${SN}/public_html" ]; then
            RESOLVED_PATH="/home/${SN}/public_html"
            log_info "Resolved to /home/${SN}/public_html"
        fi

        # 4. Search Apache/Nginx configs
        if [ -z "$RESOLVED_PATH" ]; then
            for conf in \
                /etc/apache2/sites-enabled/*.conf \
                /etc/httpd/conf.d/*.conf \
                /etc/nginx/sites-enabled/* \
                /etc/nginx/conf.d/*.conf; do
                [ -f "$conf" ] || continue
                docroot=$(grep -hEi '^\s*(DocumentRoot|root)\s+"?([^";\s]+)"?' "$conf" \
                    2>/dev/null | awk '{print $NF}' | tr -d '"' \
                    | grep -i "$SN" | head -1)
                if [ -d "$docroot" ]; then
                    RESOLVED_PATH="$docroot"
                    log_info "Resolved from config ${conf}: ${RESOLVED_PATH}"
                    break
                fi
            done
        fi

        if [ -z "$RESOLVED_PATH" ]; then
            echo -e "  ${YELLOW}[WARN]${NC}    Cannot resolve site path for '${SN}'"
            log_info "  Tried: /var/www/${SN}"
            log_info "  Tried: /home/${SN}/public_html"
            log_info "  Tried: Apache/Nginx configs"
            echo "${TS} [WATCH] Cannot resolve path for ${SN} — skipped" >> "$LOG_FILE"
            continue
        fi

        log_info "Site path resolved: ${RESOLVED_PATH}"
        NEW_PATH="$RESOLVED_PATH"

        # ── noexec on the new site directory ─────────────────────────────────
        # Uses the same _apply_noexec_dir function from LAYER 6
        if mount 2>/dev/null | grep -qE " on ${NEW_PATH} .*noexec"; then
            echo -e "  ${GREEN}[OK]${NC}      ${NEW_PATH}  →  already noexec"
            echo "${TS} [WATCH] ${NEW_PATH} already noexec" >> "$LOG_FILE"
        else
            # Try bind-mount on itself with noexec
            if mount --bind "$NEW_PATH" "$NEW_PATH" 2>/dev/null && \
               mount -o remount,noexec,nosuid,nodev,bind "$NEW_PATH" 2>/dev/null; then
                echo -e "  ${GREEN}[OK]${NC}      ${NEW_PATH}  →  noexec applied"
                echo "${TS} [WATCH] ${NEW_PATH} noexec applied" >> "$LOG_FILE"
            else
                echo -e "  ${YELLOW}[WARN]${NC}    ${NEW_PATH}  →  noexec failed (check mount permissions)"
                echo "${TS} [WATCH] ${NEW_PATH} noexec failed" >> "$LOG_FILE"
            fi
        fi

        # ── Apply open_basedir for new site ──────────────────────────────────
        # FPM: handled via pool.conf below
        # CGI/mod_php: must be set in php.ini
        _W_PHP_MODE=$(detect_php_mode)
        NEW_BASEDIR="${NEW_PATH}:/tmp:/usr/share/php:/usr/share/pear"
        UPDATED_INI=0

        if [[ "$_W_PHP_MODE" == "cgi" || "$_W_PHP_MODE" == "mod_php" ]]; then
            while IFS= read -r inifile; do
                [ -f "$inifile" ] || continue
                [[ "$inifile" == *cli* ]] && continue
                if grep -qE "^\s*open_basedir\s*=" "$inifile"; then
                    CURRENT=$(grep -E "^\s*open_basedir\s*=" "$inifile" | head -1)
                    if ! echo "$CURRENT" | grep -q "$NEW_PATH"; then
                        sed -i "s|^\s*open_basedir\s*=.*|&:${NEW_PATH}|" "$inifile"
                        echo "${TS} [WATCH] open_basedir updated for ${SN} in ${inifile}" >> "$LOG_FILE"
                        UPDATED_INI=$((UPDATED_INI + 1))
                    fi
                else
                    echo "open_basedir = ${NEW_BASEDIR}" >> "$inifile"
                    echo "${TS} [WATCH] open_basedir added for ${SN} in ${inifile}" >> "$LOG_FILE"
                    UPDATED_INI=$((UPDATED_INI + 1))
                fi
            done < <({ find / -maxdepth 7 -type f -name "php.ini" 2>/dev/null || true; } | sort -u)
        else
            log_info "[WATCH] FPM mode — open_basedir handled via pool.conf"
        fi

        # ── Create PHP-FPM pool for new site ──────────────────────────────────
        # Use shared find_pool_dir helper
        W_POOL_DIR=$(find_pool_dir)

        POOL_CREATED=0
        if [ -n "$W_POOL_DIR" ]; then
            W_SITE_USER=$(stat -c '%U' "$NEW_PATH" 2>/dev/null || echo "www-data")
            id "$W_SITE_USER" &>/dev/null || W_SITE_USER="www-data"
            W_SITE_GROUP=$(id -gn "$W_SITE_USER" 2>/dev/null || echo "www-data")
            W_SOCK_OWNER="apache"
            systemctl is-active --quiet nginx   2>/dev/null && W_SOCK_OWNER="nginx"
            systemctl is-active --quiet apache2 2>/dev/null && W_SOCK_OWNER="www-data"

            W_POOL_CONF="${W_POOL_DIR}/${SN}.conf"
            W_SESSION_PATH="/var/lib/php/sessions/${SN}"
            W_OPEN_BASEDIR="${NEW_PATH}:/tmp:/usr/share/php:/usr/share/pear"

            mkdir -p "$W_SESSION_PATH" 2>/dev/null
            chown "${W_SITE_USER}:${W_SITE_GROUP}" "$W_SESSION_PATH" 2>/dev/null
            chmod 700 "$W_SESSION_PATH" 2>/dev/null

            cat > "$W_POOL_CONF" << POOLEOF
; Linux Guardian — PHP-FPM Pool: ${SN}
; Generated: ${TS}
; Global settings inherited from php.ini
; Per-site: open_basedir + session + logging

[${SN}]
user  = ${W_SITE_USER}
group = ${W_SITE_GROUP}

listen       = /run/php-fpm/${SN}.sock
listen.owner = ${W_SOCK_OWNER}
listen.group = ${W_SOCK_OWNER}
listen.mode  = 0660

pm                   = dynamic
pm.max_children      = 10
pm.start_servers     = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests      = 500

; Per-site: open_basedir only
php_admin_value[open_basedir]   = ${W_OPEN_BASEDIR}

; Per-site: session isolation
php_value[session.save_handler] = files
php_value[session.save_path]    = ${W_SESSION_PATH}

; Per-site: logging
php_admin_value[error_log]      = /var/log/php-fpm/${SN}-error.log
access.log                      = /var/log/php-fpm/${SN}-access.log
slowlog                         = /var/log/php-fpm/${SN}-slow.log
request_slowlog_timeout         = 5s
POOLEOF
            chmod 640 "$W_POOL_CONF"

            # Restart php-fpm using shared helper
            _W_MODE=$(detect_php_mode)
            if restart_php_services "$_W_MODE" 2>/dev/null; then
                echo -e "  ${GREEN}[OK]${NC}      PHP-FPM pool created + service restarted"
                echo "${TS} [WATCH] PHP-FPM pool created: ${W_POOL_CONF}" >> "$LOG_FILE"
                POOL_CREATED=1
            fi
            [ "$POOL_CREATED" -eq 0 ] && {
                echo -e "  ${GREEN}[OK]${NC}      PHP-FPM pool created: ${W_POOL_CONF}"
                echo -e "  ${YELLOW}[WARN]${NC}    php-fpm service not running — restart manually"
                echo "${TS} [WATCH] PHP-FPM pool created (fpm not running): ${W_POOL_CONF}" >> "$LOG_FILE"
            }
        fi

        if [ "$UPDATED_INI" -gt 0 ]; then
            echo -e "  ${GREEN}[OK]${NC}      open_basedir updated in ${UPDATED_INI} php.ini file(s)"
            echo "${TS} [WATCH] open_basedir updated in ${UPDATED_INI} php.ini(s) for ${SN}" >> "$LOG_FILE"
            for svc in apache2 httpd nginx; do
                systemctl is-active --quiet "$svc" 2>/dev/null \
                    && systemctl restart "$svc" 2>/dev/null \
                    && echo -e "  ${GREEN}[OK]${NC}      Restarted: ${svc}" \
                    || true
            done
        fi

        # ── Summary for this site ─────────────────────────────────────────────
        echo ""
        echo -e "  ${BOLD}${SN} hardening summary:${NC}"
        mount 2>/dev/null | grep -qE " on ${NEW_PATH} .*noexec" \
            && echo -e "    [6] noexec            →  active" \
            || echo -e "    [6] noexec            →  failed"
        echo -e "    [5] open_basedir      →  updated in ${UPDATED_INI} php.ini file(s)"
        [ "$POOL_CREATED" -eq 1 ] \
            && echo -e "    [5] PHP-FPM pool      →  created (${W_POOL_DIR}/${SN}.conf)" \
            || echo -e "    [5] PHP-FPM pool      →  $([ -n "$W_POOL_DIR" ] && echo 'created (fpm not running)' || echo 'skipped (fpm not installed)')"
        echo "${TS} [WATCH] ${SN} complete: noexec + open_basedir + PHP-FPM pool" >> "$LOG_FILE"

        # Add to known sites so we don't process it again
        KNOWN_SITES+=("$SN")
        echo ""
    done
}

# ── Entry point for --watch ───────────────────────────────────────────────────
if [[ "${1:-}" == "--watch" ]]; then
    watch_mode
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}"
echo "════════════════════════════════════════════════════════════════════"
if [ "$DRY_RUN" = true ]; then
    echo "        DRY-RUN COMPLETE — ZERO CHANGES WERE MADE"
    echo "        Re-run without --dry-run to apply"
else
    echo "                  ✓  HARDENING COMPLETE  ✓"
fi
echo "════════════════════════════════════════════════════════════════════"
echo -e "${NC}"

if [ "$DRY_RUN" = false ]; then
    echo -e "${GREEN}Security layers applied:${NC}"
    echo ""
    echo "  [1] Binary Lockdown       — tools restricted to root"
    echo "  [2] Kernel Hardening      — modules blocked + sysctl"
    echo "  [3] System Files          — permissions hardened"
    echo "  [4] MySQL/MariaDB         — bound to 127.0.0.1"
    echo "  [5] PHP disable_functions — shell_exec/exec disabled"
    echo "  [6] noexec /tmp           — uploaded binaries won't execute"
    echo "  [7] ${MAC_SYSTEM^^} (MAC)           — web exec policy enforced"
    echo "  [8] Auditd                — monitoring active"
    echo "  [A] FTP + ClamAV          — upload scanning enabled"
    echo "  [B] Snuffleupagus         — PHP RASP layer"
    echo ""
    echo -e "  ${CYAN}Backups:${NC}  $BACKUP_DIR"
    echo -e "  ${CYAN}Rollback:${NC} sudo $0 --undo"
    echo -e "  ${CYAN}Watch:${NC}    sudo $0 --watch"
    echo -e "  ${CYAN}Log:${NC}      $LOG_FILE"
    echo ""
    echo -e "${YELLOW}Verify:${NC}"
    echo "  php -r 'echo ini_get(\"disable_functions\");' | tr , '\n' | head -5"
    echo "  mount | grep noexec"
    echo "  ausearch -k webshell -ts recent"
    echo "  sestatus 2>/dev/null || apparmor_status 2>/dev/null"
fi
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# REBOOT — Apply SELinux relabel and activate all hardening changes
# ══════════════════════════════════════════════════════════════════════════════
if [ "$DRY_RUN" = false ]; then
    echo -e "${BOLD}${YELLOW}"
    echo "════════════════════════════════════════════════════════════════════"
    echo "  SERVER WILL REBOOT IN 10 SECONDS TO APPLY SELinux RELABEL"
    echo "  Press Ctrl+C to cancel"
    echo "════════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    sleep 10
    reboot
fi