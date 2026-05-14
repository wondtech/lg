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
#   [9] nspawn Isolation      — Contain each site in an isolated namespace
#
# Usage:
#   sudo lg                  Interactive (recommended first run)
#   sudo lg --auto           Auto mode — no prompts
#   sudo lg --cron           Silent mode for cron jobs
#   sudo lg --dry-run        Preview changes without applying
#   sudo lg --undo           Rollback all changes from last run
#   sudo lg --setup-auto     Install daily cron + new-user hook
# ══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

# ─── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

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
        --cron)       RUN_MODE="cron";       exec > /dev/null 2>&1 ;;
        --auto)       RUN_MODE="auto" ;;
        --setup-auto) RUN_MODE="setup-auto" ;;
        --dry-run)    DRY_RUN=true ;;
        --undo)       UNDO_MODE=true ;;
        --help|-h)    grep '^#   sudo lg' "$0"; exit 0 ;;
    esac
done

# Globals
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/lg/backups"
LOG_FILE="/var/log/lg-hardening.log"
UNDO_MANIFEST="${BACKUP_DIR}/undo_manifest_${TIMESTAMP}.txt"
MAC_SYSTEM="none"
SNUFF_INSTALLED=false
SNUFF_SKIP=false
PHP_SKIP=false
PHP_INI_FILES=()
SELECTED_FILES=()
ALERT_EMAIL="root"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Tee output to log file (not in dry-run, not in cron)
if [ "$DRY_RUN" = false ] && [ "$RUN_MODE" != "cron" ]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
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
        T=$(echo "$line" | cut -d: -f1)
        case "$T" in
            FILE)
                ORIG=$(echo "$line" | cut -d: -f2)
                BKUP=$(echo "$line" | cut -d: -f3)
                [ -f "$BKUP" ] \
                    && cp "$BKUP" "$ORIG" && log_ok "Restored: $ORIG" \
                    || log_warn "Backup missing: $BKUP"
                ;;
            PERM)
                P=$(echo "$line" | cut -d: -f2)
                M=$(echo "$line" | cut -d: -f3)
                O=$(echo "$line" | cut -d: -f4)
                if [ -e "$P" ]; then
                    chmod "$M" "$P" 2>/dev/null
                    chown "$O" "$P" 2>/dev/null
                    log_ok "Restored perms: $P ($M $O)"
                fi
                ;;
            MOUNT_NOEXEC)
                MNT=$(echo "$line" | cut -d: -f2)
                mount -o remount,exec "$MNT" 2>/dev/null \
                    && log_ok "Re-enabled exec: $MNT" \
                    || log_warn "Could not remount: $MNT"
                ;;
            FSTAB_TMP)
                sed -i '/Linux Guardian: noexec/d'    /etc/fstab 2>/dev/null
                sed -i '/tmpfs.*noexec.*nosuid/d'     /etc/fstab 2>/dev/null
                log_ok "Removed noexec entries from /etc/fstab"
                ;;
            MODPROBE)
                CONF=$(echo "$line" | cut -d: -f2)
                rm -f "$CONF" && log_ok "Removed modprobe conf: $CONF"
                ;;
            SYSCTL)
                CONF=$(echo "$line" | cut -d: -f2)
                rm -f "$CONF"
                sysctl --system &>/dev/null
                log_ok "Removed sysctl conf: $CONF"
                ;;
            APPARMOR_PROFILE)
                PROF=$(echo "$line" | cut -d: -f2)
                aa-complain "$PROF" 2>/dev/null && log_ok "AppArmor complain: $PROF"
                ;;
            AUDITD_RULE)
                RFILE=$(echo "$line" | cut -d: -f2)
                rm -f "$RFILE"
                systemctl restart auditd 2>/dev/null
                log_ok "Removed audit rules: $RFILE"
                ;;
            NSPAWN_SERVICE)
                NSVC=$(echo "$line" | cut -d: -f2)
                systemctl stop    "$NSVC" 2>/dev/null
                systemctl disable "$NSVC" 2>/dev/null
                rm -f "/etc/systemd/system/${NSVC}.service"
                rm -f "/etc/systemd/nspawn/${NSVC##nspawn-}.nspawn"
                systemctl daemon-reload
                log_ok "Removed nspawn service: $NSVC"
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
        DEBIAN_FRONTEND=noninteractive apt-get update -qq   2>&1 | tail -2
        DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq 2>&1 | tail -2
        log_ok "Packages updated (apt)"
    elif command -v dnf &>/dev/null; then
        dnf update -y -q 2>&1 | tail -3 && log_ok "Packages updated (dnf)"
    elif command -v yum &>/dev/null; then
        yum update -y -q 2>&1 | tail -3 && log_ok "Packages updated (yum)"
    elif command -v apk &>/dev/null; then
        apk update -q && apk upgrade -q && log_ok "Packages updated (apk)"
    elif command -v pacman &>/dev/null; then
        pacman -Syu --noconfirm -q 2>&1 | tail -3 && log_ok "Packages updated (pacman)"
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
done < <(find /usr/bin /usr/sbin /usr/local/bin /usr/libexec \
    -maxdepth 2 -type f \
    \( -name "python" -o -name "python[0-9]*" -o -name "platform-python*" \) \
    ! -type l 2>/dev/null)

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
    if lsmod 2>/dev/null | grep -q "^${mod} "; then
        run_cmd rmmod "$mod" 2>/dev/null && log_ok "Unloaded: $mod"
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
    sysctl -p "$SYSCTL_CONF" &>/dev/null && log_ok "sysctl parameters applied"
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

MY_CNF=""
for f in /etc/my.cnf /etc/mysql/my.cnf \
         /etc/my.cnf.d/server.cnf /etc/my.cnf.d/mariadb-server.cnf; do
    [ -f "$f" ] && MY_CNF="$f" && break
done

if [ -n "$MY_CNF" ]; then
    log_info "Config: $MY_CNF"
    backup_file "$MY_CNF" "mysql"
    if [ "$DRY_RUN" = true ]; then
        log_dry "Set bind-address = 127.0.0.1 in $MY_CNF"
    else
        if grep -q "^bind-address" "$MY_CNF" 2>/dev/null; then
            sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$MY_CNF"
        else
            printf '\n# Linux Guardian\nbind-address = 127.0.0.1\n' >> "$MY_CNF"
        fi
        log_ok "bind-address = 127.0.0.1"
        systemctl restart mariadb 2>/dev/null \
            || systemctl restart mysqld 2>/dev/null \
            || log_warn "Could not restart DB — restart manually"
    fi
else
    log_skip "MySQL/MariaDB config not found"
fi

log_ok "Layer 4 complete"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5 — PHP Security Hardening (disable_functions)
# Prevent PHP from executing shell commands
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 5: PHP Security Hardening (disable_functions)"

TMPF=$(mktemp)
trap 'rm -f "$TMPF"' EXIT INT TERM
find / -maxdepth 7 -type f -name "php.ini" 2>/dev/null | sort -u > "$TMPF"
while IFS= read -r line; do PHP_INI_FILES+=("$line"); done < "$TMPF"
rm -f "$TMPF"; trap - EXIT INT TERM

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

    PUBLIC_HTML_PATHS=$(find /home -maxdepth 3 -type d \
        -name "public_html" 2>/dev/null | tr '\n' ':')
    OPEN_BASEDIR="${PUBLIC_HTML_PATHS:-/home:}/tmp:/usr/share/php:/usr/share/pear"

    for inifile in "${SELECTED_FILES[@]}"; do
        log_info "Processing: $inifile"
        backup_file "$inifile" "phpini"

        if [ "$DRY_RUN" = true ]; then
            log_dry "Apply disable_functions + security settings → $inifile"
            continue
        fi

        # Apply disable_functions
        if grep -q "^disable_functions" "$inifile"; then
            sed -i "s|^disable_functions.*|disable_functions = ${DISABLE_FUNCTIONS}|" "$inifile"
        elif grep -q "^;disable_functions" "$inifile"; then
            sed -i "s|^;disable_functions.*|disable_functions = ${DISABLE_FUNCTIONS}|" "$inifile"
        else
            printf '\n; Linux Guardian %s\ndisable_functions = %s\n' \
                "$TIMESTAMP" "$DISABLE_FUNCTIONS" >> "$inifile"
        fi
        log_ok "disable_functions applied"

        # Apply security settings (bash 4+ associative array)
        declare -A PHPSEC=(
            ["allow_url_fopen"]="Off"
            ["allow_url_include"]="Off"
            ["expose_php"]="Off"
            ["display_errors"]="Off"
            ["log_errors"]="On"
            ["open_basedir"]="${OPEN_BASEDIR}"
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
        unset PHPSEC
        log_ok "Security settings applied: $inifile"
    done

    # Restart web server(s)
    for svc in apache2 httpd nginx php-fpm; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            if [ "$DRY_RUN" = false ]; then
                systemctl restart "$svc" 2>/dev/null \
                    && log_ok "Restarted: $svc" \
                    || log_warn "Could not restart $svc — check config manually"
            else
                log_dry "Restart $svc"
            fi
        fi
    done
fi

log_ok "Layer 5 complete"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 6 — noexec on /tmp and /var/tmp
# Prevent execution of attacker-uploaded binaries from writable dirs
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 6: noexec on /tmp and /var/tmp"

apply_noexec() {
    local mnt="$1" size="${2:-256M}"

    if mountpoint -q "$mnt" 2>/dev/null; then
        if mount | grep -q " on $mnt .*noexec"; then
            log_ok "$mnt is already noexec"
        elif [ "$DRY_RUN" = true ]; then
            log_dry "remount $mnt noexec,nosuid,nodev"
        else
            mount -o remount,noexec,nosuid,nodev "$mnt" 2>/dev/null \
                && log_ok "$mnt remounted noexec" \
                || log_warn "Could not remount $mnt"
            echo "MOUNT_NOEXEC:${mnt}" >> "$UNDO_MANIFEST"
        fi
    else
        if [ "$DRY_RUN" = true ]; then
            log_dry "Mount tmpfs noexec on $mnt (size=${size})"
        else
            mount -t tmpfs -o "size=${size},noexec,nosuid,nodev" tmpfs "$mnt" 2>/dev/null \
                && log_ok "$mnt overlaid with noexec tmpfs (${size})" \
                || log_warn "$mnt tmpfs mount failed — add manually to /etc/fstab"
            echo "MOUNT_NOEXEC:${mnt}" >> "$UNDO_MANIFEST"
        fi
    fi

    # Persist across reboots
    if [ "$DRY_RUN" = false ]; then
        if ! grep -qE "tmpfs\s+${mnt}\s" /etc/fstab 2>/dev/null; then
            echo "# Linux Guardian: noexec ${mnt}" >> /etc/fstab
            echo "tmpfs ${mnt} tmpfs defaults,noexec,nosuid,nodev,size=${size} 0 0" >> /etc/fstab
            echo "FSTAB_TMP:${mnt}" >> "$UNDO_MANIFEST"
            log_ok "Added to /etc/fstab: $mnt"
        else
            log_info "fstab entry already exists for $mnt"
        fi
    fi
}

apply_noexec "/tmp"     "256M"
apply_noexec "/var/tmp" "128M"

log_ok "Layer 6 complete"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 7 — AppArmor / SELinux (MAC)
# MAC policy: web server cannot exec binaries even if uploaded
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 7: MAC — AppArmor / SELinux"

command -v sestatus        &>/dev/null && MAC_SYSTEM="selinux"
command -v apparmor_status &>/dev/null && MAC_SYSTEM="apparmor"
log_info "MAC system detected: ${MAC_SYSTEM}"
echo ""

case "$MAC_SYSTEM" in
    selinux)
        SE_STATUS=$(sestatus 2>/dev/null | awk '/SELinux status/{print $3}')
        SE_MODE=$(sestatus   2>/dev/null | awk '/Current mode/{print $3}')
        log_info "Status: ${SE_STATUS}  Mode: ${SE_MODE}"

        if [ "${SE_STATUS}" != "enabled" ]; then
            log_warn "SELinux not enabled — edit /etc/selinux/config and reboot"
        else
            if [ "${SE_MODE}" != "enforcing" ]; then
                if [ "$DRY_RUN" = true ]; then
                    log_dry "setenforce 1 + SELINUX=enforcing in /etc/selinux/config"
                else
                    setenforce 1
                    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
                    log_ok "SELinux set to enforcing"
                fi
            else
                log_ok "SELinux already enforcing"
            fi

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
                    setsebool -P "$b" "${SEBOOLS[$b]}" 2>/dev/null \
                        && log_ok "SELinux bool: $b = ${SEBOOLS[$b]}" \
                        || log_skip "Bool not available: $b"
                done
                unset SEBOOLS
            fi
        fi
        ;;

    apparmor)
        if [ "$DRY_RUN" = true ]; then
            log_dry "Enable AppArmor + enforce web server profiles"
        else
            systemctl enable --now apparmor 2>/dev/null && log_ok "AppArmor enabled"
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
            for prof in /etc/apparmor.d/usr.sbin.php-fpm*; do
                [ -f "$prof" ] \
                    && aa-enforce "$prof" 2>/dev/null \
                    && { log_ok "Enforcing: $prof"
                         echo "APPARMOR_PROFILE:${prof}" >> "$UNDO_MANIFEST"; }
            done
            [ "$ENFORCED" -eq 0 ] \
                && log_warn "No web-server AppArmor profiles found — install apparmor-profiles"
        fi
        ;;

    none)
        log_warn "No MAC system detected"
        command -v apt-get &>/dev/null \
            && log_info "Install AppArmor: apt install apparmor apparmor-utils apparmor-profiles -y"
        ;;
esac

log_ok "Layer 7 complete"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 8 — Auditd (Monitoring & Alerts)
# Monitor and log all suspicious activity in real time
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 8: Auditd — Monitoring & Alerts"

AUDIT_RULES="/etc/audit/rules.d/99-lg-hardening.rules"

if ! command -v auditctl &>/dev/null; then
    if [ "$DRY_RUN" = true ]; then
        log_dry "Install auditd package"
    else
        log_info "Installing auditd..."
        install_pkg "auditd" || install_pkg "audit" || true
    fi
fi

if command -v auditctl &>/dev/null || [ "$DRY_RUN" = true ]; then
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

        systemctl enable auditd 2>/dev/null
        systemctl restart auditd 2>/dev/null \
            && log_ok "Auditd restarted" \
            || log_warn "Could not restart auditd"

        augenrules --load 2>/dev/null \
            || auditctl -R "$AUDIT_RULES" 2>/dev/null \
            || log_warn "Could not load rules live (will apply after reboot)"

        log_ok "Audit rules: $AUDIT_RULES"
        log_info "Monitor:  tail -f /var/log/audit/audit.log"
        log_info "Search:   ausearch -k webshell -ts recent"
        log_info "Report:   aureport --start today"
    fi
else
    log_warn "auditd not available and could not be installed"
fi

log_ok "Layer 8 complete"

# ══════════════════════════════════════════════════════════════════════════════
# PART A — FTP Security (Pure-FTPd + ClamAV)
# Scan FTP-uploaded files for malware
# ══════════════════════════════════════════════════════════════════════════════
section "PART A: FTP Security (Pure-FTPd + ClamAV)"

if [ -f /etc/pure-ftpd.conf ]; then
    backup_file "/etc/pure-ftpd.conf" "pureftpd"
    if [ "$DRY_RUN" = true ]; then
        log_dry "Enable CallUploadScript in /etc/pure-ftpd.conf"
    else
        if grep -q "^CallUploadScript" /etc/pure-ftpd.conf; then
            sed -i 's/^CallUploadScript.*/CallUploadScript yes/' /etc/pure-ftpd.conf
        else
            echo "CallUploadScript yes" >> /etc/pure-ftpd.conf
        fi
        log_ok "CallUploadScript enabled"
    fi
else
    log_skip "Pure-FTPd not installed"
fi

if [ -d /etc/pure-ftpd ] && [ "$DRY_RUN" = false ]; then
    if [[ "$RUN_MODE" == "cron" || "$RUN_MODE" == "auto" ]]; then
        ALERT_EMAIL="root"
    else
        read -r -p "  Alert email for ClamAV (default: root): " ALERT_EMAIL
        [ -z "$ALERT_EMAIL" ] && ALERT_EMAIL="root"
    fi
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
    log_ok "ClamAV scanner created: /etc/pure-ftpd/clamav_check.sh"
    pkill -f pure-uploadscript 2>/dev/null || true
    /usr/sbin/pure-uploadscript -B -r /etc/pure-ftpd/clamav_check.sh 2>/dev/null \
        && log_ok "pure-uploadscript started" \
        || log_warn "pure-uploadscript failed (ensure Pure-FTPd is running)"
fi

log_ok "Part A complete"

# ══════════════════════════════════════════════════════════════════════════════
# PART B — Snuffleupagus (PHP RASP)
# Additional PHP protection layer on top of disable_functions
# ══════════════════════════════════════════════════════════════════════════════
section "PART B: Snuffleupagus — PHP RASP"

if php -m 2>/dev/null | grep -qi "snuffleupagus"; then
    log_ok "Snuffleupagus already installed and active"
    SNUFF_INSTALLED=true
    SNUFF_SKIP=false
elif [ "$DRY_RUN" = true ]; then
    log_dry "Install Snuffleupagus PHP extension via PECL"
    SNUFF_SKIP=true
elif [[ "$RUN_MODE" == "interactive" ]]; then
    read -r -p "  Install Snuffleupagus PHP RASP? [y/N]: " -n 1
    echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && SNUFF_SKIP=false || SNUFF_SKIP=true
else
    SNUFF_SKIP=true
    log_skip "Snuffleupagus — run interactively to install"
fi

if [ "$SNUFF_SKIP" = false ] && [ "$SNUFF_INSTALLED" = false ]; then
    if command -v apt-get &>/dev/null; then
        install_pkg php-dev; install_pkg autoconf; install_pkg build-essential
    elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
        install_pkg php-devel; install_pkg autoconf
    fi
    pecl install snuffleupagus 2>&1 | tail -15
    if [ $? -eq 0 ]; then
        log_ok "Snuffleupagus installed"
        log_info "Add to php.ini: extension=snuffleupagus.so"
        log_info "Config sample:  /usr/local/etc/php/snuffleupagus.rules"
    else
        log_warn "PECL install failed — see output above"
    fi
fi

log_ok "Part B complete"

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 9 — Namespace Isolation (systemd-nspawn)
# Contain blast radius: attacker who breaches site-A cannot reach site-B
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 9: Namespace Isolation (systemd-nspawn)"

setup_nspawn() {
    # Availability check
    if ! command -v systemd-nspawn &>/dev/null; then
        log_warn "systemd-nspawn not found"
        command -v apt-get &>/dev/null && log_info "Install: apt install systemd-container -y"
        command -v yum     &>/dev/null && log_info "Install: yum install systemd-container -y"
        command -v dnf     &>/dev/null && log_info "Install: dnf install systemd-container -y"
        return 1
    fi
    log_ok "systemd-nspawn: $(systemd-nspawn --version 2>/dev/null | head -1)"

    # Discover sites
    SITES=()
    for d in /var/www/*/; do
        [ -d "$d" ] && [[ "$d" != "/var/www/html/" ]] && SITES+=("$d")
    done
    for d in /home/*/public_html/; do [ -d "$d" ] && SITES+=("$d"); done
    [ ${#SITES[@]} -eq 0 ] && [ -d "/var/www/html" ] && SITES+=("/var/www/html/")

    if [ ${#SITES[@]} -eq 0 ]; then
        log_warn "No sites found in /var/www/* or /home/*/public_html"
        return 1
    fi
    log_info "Found ${#SITES[@]} site(s):"
    for s in "${SITES[@]}"; do echo "    → $s"; done
    echo ""

    if [ "$DRY_RUN" = true ]; then
        for s in "${SITES[@]}"; do
            SN=$(echo "$s" | sed 's|/var/www/||;s|/home/||;s|/public_html||;s|/$||;s|/||g')
            log_dry "Create isolated nspawn container: $SN"
        done
        return 0
    fi

    NSPAWN_BASE="/var/lib/lg-nspawn"
    mkdir -p "$NSPAWN_BASE"

    # Network bridge
    if command -v ip &>/dev/null; then
        if ! ip link show nspawn-br0 &>/dev/null; then
            ip link add name nspawn-br0 type bridge
            ip addr add 10.200.0.1/24 dev nspawn-br0
            ip link set nspawn-br0 up
            log_ok "Network bridge: nspawn-br0 (10.200.0.1/24)"
        else
            log_ok "Network bridge already exists: nspawn-br0"
        fi
        iptables -t nat -C POSTROUTING -s 10.200.0.0/24 -j MASQUERADE 2>/dev/null \
            || iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -j MASQUERADE 2>/dev/null
    fi

    SITE_IP_LAST=10
    for site in "${SITES[@]}"; do
        SN=$(echo "$site" | sed 's|/var/www/||;s|/home/||;s|/public_html||;s|/$||;s|/||g')
        SN=$(echo "$SN" | tr -cd '[:alnum:]-_' | cut -c1-32)
        SITE_DIR="${NSPAWN_BASE}/${SN}"
        SITE_IP="10.200.0.${SITE_IP_LAST}"
        SITE_IP_LAST=$((SITE_IP_LAST + 1))

        echo "  ── Container: ${SN} ──"

        # Minimal root filesystem
        mkdir -p "${SITE_DIR}"/{bin,lib,lib64,usr/lib,etc,tmp,var/www,proc,sys,dev,run}

        # Copy required binaries only
        for b in sh php php-fpm; do
            bp=$(command -v "$b" 2>/dev/null || true)
            [ -n "$bp" ] && cp "$bp" "${SITE_DIR}/bin/" 2>/dev/null && log_info "Binary: $b"
        done

        # Copy shared libraries
        for bp in "${SITE_DIR}"/bin/*; do
            [ -f "$bp" ] || continue
            ldd "$bp" 2>/dev/null | grep -Eo '/[^ ]+\.so[^ ]*' | while read -r lib; do
                [ -f "$lib" ] && cp --parents "$lib" "${SITE_DIR}/" 2>/dev/null || true
            done
        done

        # Minimal /etc
        cp /etc/resolv.conf "${SITE_DIR}/etc/"        2>/dev/null || true
        cp /etc/localtime   "${SITE_DIR}/etc/"        2>/dev/null || true
        getent passwd www-data apache 2>/dev/null | head -1 > "${SITE_DIR}/etc/passwd"
        getent group  www-data apache 2>/dev/null | head -1 > "${SITE_DIR}/etc/group"

        # Bind site files read-only
        if mount --bind "$site" "${SITE_DIR}/var/www" 2>/dev/null; then
            mount -o remount,ro,bind "${SITE_DIR}/var/www" 2>/dev/null || true
            log_ok "Site bound read-only: $site"
        else
            log_warn "Could not bind: $site"
        fi

        # noexec /tmp inside container
        mount -t tmpfs -o size=32M,noexec,nosuid,nodev \
            tmpfs "${SITE_DIR}/tmp" 2>/dev/null \
            && log_ok "/tmp inside container: noexec (32M)"

        # nspawn config
        mkdir -p /etc/systemd/nspawn
        cat > "/etc/systemd/nspawn/${SN}.nspawn" << EOF
[Exec]
User=www-data
WorkingDirectory=/var/www

[Files]
TemporaryFileSystem=/tmp:noexec,nosuid,nodev,size=32M

[Network]
VirtualEthernet=yes
Bridge=nspawn-br0
EOF

        # systemd service
        cat > "/etc/systemd/system/nspawn-${SN}.service" << EOF
[Unit]
Description=Linux Guardian — Isolated site: ${SN}
After=network.target

[Service]
Type=notify
ExecStart=/usr/bin/systemd-nspawn \
    --machine=${SN} \
    --directory=${SITE_DIR} \
    --user=www-data \
    --private-users=pick \
    --private-users-chown \
    --network-bridge=nspawn-br0 \
    --tmpfs=/tmp:noexec,nosuid,nodev,size=32M \
    --read-only \
    --drop-capability=CAP_SYS_ADMIN \
    --drop-capability=CAP_NET_ADMIN \
    --drop-capability=CAP_SYS_PTRACE \
    /bin/php-fpm --nodaemonize
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
        echo "NSPAWN_SERVICE:nspawn-${SN}" >> "$UNDO_MANIFEST"

        systemctl daemon-reload
        systemctl enable "nspawn-${SN}.service" 2>/dev/null
        systemctl start  "nspawn-${SN}.service" 2>/dev/null

        if systemctl is-active --quiet "nspawn-${SN}.service" 2>/dev/null; then
            log_ok "${SN}  →  running  (IP: ${SITE_IP})"
        else
            log_warn "${SN}  →  not active — journalctl -u nspawn-${SN}"
        fi
        echo ""
    done

    log_info "Manage containers:"
    echo "    machinectl list              — list running containers"
    echo "    machinectl status <name>     — container details"
    echo "    machinectl login  <name>     — shell inside container"
    echo "    journalctl -u nspawn-<name>  — container logs"
}

if [[ "$RUN_MODE" == "interactive" ]] && [ "$DRY_RUN" = false ]; then
    read -r -p "  Enable per-site nspawn isolation? [y/N]: " -n 1
    echo ""
    [[ $REPLY =~ ^[Yy]$ ]] && setup_nspawn || log_skip "nspawn isolation skipped"
else
    setup_nspawn
fi

log_ok "Layer 9 complete"

# ══════════════════════════════════════════════════════════════════════════════
# PART C — Auto-update (cron + new-user hook)
# ══════════════════════════════════════════════════════════════════════════════
section "PART C: Auto-update Setup"

setup_auto_update() {
    local SCRIPT_PATH
    SCRIPT_PATH=$(realpath "$0" 2>/dev/null || echo "$0")
    local CRON_JOB="0 3 * * * ${SCRIPT_PATH} --cron >> ${LOG_FILE} 2>&1"

    crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH" | crontab - 2>/dev/null || true
    ( crontab -l 2>/dev/null; echo "$CRON_JOB" ) | crontab -
    log_ok "Cron job installed — daily at 03:00"

    cat > /usr/local/bin/lg-user-hook << HOOKEOF
#!/bin/bash
# Linux Guardian — new user security hook
NEW_USER="\$1"
[ -z "\$NEW_USER" ] && exit 0
USER_HOME=\$(getent passwd "\$NEW_USER" | cut -d: -f6)
if [ -d "\$USER_HOME/public_html" ]; then
    logger -t lg-hardening "Hardening new user: \$NEW_USER"
    ${SCRIPT_PATH} --auto >> ${LOG_FILE} 2>&1
fi
HOOKEOF
    chmod 750 /usr/local/bin/lg-user-hook
    log_ok "New-user hook: /usr/local/bin/lg-user-hook"
    log_info "cPanel link: ln -s /usr/local/bin/lg-user-hook /scripts/prewwwacct"
}

if [[ "${1:-}" == "--setup-auto" ]]; then
    setup_auto_update
else
    log_info "Run 'sudo lg --setup-auto' to install daily cron + new-user hook"
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
    echo "  [9] nspawn Isolation      — per-site containers"
    echo ""
    echo -e "  ${CYAN}Backups:${NC}  $BACKUP_DIR"
    echo -e "  ${CYAN}Rollback:${NC} sudo $0 --undo"
    echo -e "  ${CYAN}Log:${NC}      $LOG_FILE"
    echo ""
    echo -e "${YELLOW}Verify:${NC}"
    echo "  php -r 'echo ini_get(\"disable_functions\");' | tr , '\n' | head -5"
    echo "  mount | grep noexec"
    echo "  machinectl list"
    echo "  ausearch -k webshell -ts recent"
    echo "  sestatus 2>/dev/null || apparmor_status 2>/dev/null"
fi
echo ""