#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Linux Guardian v1.3 — Production-Ready Server Security Hardening
# By Mogbil Sourketti WondTech.com | info@wondtech.com
#
# Security Layers (Defence in Depth):
#   [1] Binary Lockdown       — Restrict dangerous tools
#   [2] Kernel Hardening      — Harden kernel + sysctl
#   [3] System Files          — Secure critical file permissions
#   [4.1] Apache httpd        — ServerTokens, ServerSignature off
#   [4.2] MySQL/MariaDB       — Bind to 127.0.0.1
#   [5] PHP disable_functions — Block shell_exec/system/exec + open_basedir (--php-strict adds limits/strict cookies)
#   [5.1] PHP-FPM Pools       — Isolate each site with open_basedir
#   [6] noexec /tmp /var/tmp  — Prevent uploaded binary execution
#   [7] AppArmor / SELinux    — MAC + Dovecot/vmail context fixes
#   [8] Auditd                — Real-time monitoring and alerting
#   [A] FTP + ClamAV          — Scan uploaded files for malware
#   [B] Snuffleupagus         — PHP RASP
#   [C] php2shell             — CVE-2026-109618/109619: find every PHP, report fixed/vulnerable, apply mitigation
#   [D] Recent CVEs           — Snuffleupagus, Roundcube, kernel reboot, pending security updates, CWP version
#
# Usage:
#   sudo lg                  Interactive — recommended for first run
#   sudo lg                  Second run  — shows security status dashboard
#   sudo lg --force          Re-apply all layers
#   sudo lg --auto           Auto mode — no prompts
#   sudo lg --dry-run        Preview changes without applying
#   sudo lg --undo           Rollback all changes from last run
#   sudo lg --reboot         Reboot at end to apply SELinux relabel (off by default)
#   sudo lg --watch          Watch for new sites and harden automatically
#   sudo lg --fixmail        Fix Dovecot/vmail SELinux contexts
#   sudo lg --scan [--path]  Scan for webshells (optionally under a specific path)
#   sudo lg --php2shell      Part C only — php2shell status of every PHP on the host + mitigation
#   sudo lg --cves           Part D only — check the host against the recent critical CVEs (report only)
#   sudo lg --auto-analyze   Start background behavior monitoring (daemon)
#   sudo lg --integrity      Check integrity of critical system files
#   sudo lg --update         Update to latest version from lg.wondtech.com
#   sudo lg --help, -h       Show full help
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Default values for all flags (must come before any usage) ─────────────────
RUN_MODE="interactive"
DRY_RUN=false
UNDO_MODE=false
FIXMAIL_MODE=false
PHP2SHELL_MODE=false
CVES_MODE=false
ANALYZE_MODE=false
SCAN_MODE=false
AUTO_ANALYZE_MODE=false
INTEGRITY_MODE=false
FORCE_MODE=false
UPDATE_MODE=false
HELP_MODE=false
WATCH_MODE=false
REBOOT_MODE=false
LG_STATE_FILE="/root/lg/.applied"
LG_SCAN_LOG="/var/log/lg-scan.log"
LG_ANALYZE_LOG="/var/log/lg-analyze.log"
LG_INTEGRITY_DB="/root/lg/integrity.db"
LOG_FILE="/var/log/lg-hardening.log"  # default; may be overridden at line 1547

# FIX: Dovecot log paths were inlined in 3 places. Now a single constant.
DOVECOT_LOG_PATHS=(
    /var/log/dovecot.log
    /var/log/dovecot-info.log
    /var/log/dovecot-debug.log
)

# FIX: PHP disable_functions + global security settings were inlined in
# LAYER 5. Promoted to globals so they're defined once and can be inspected
# (e.g., for `php -i` verification later).
DISABLE_FUNCTIONS="exec,passthru,shell_exec,system,popen,proc_open,proc_close,proc_get_status,proc_terminate,proc_nice,pcntl_exec,pcntl_fork,pcntl_signal,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wstopsig,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_alarm,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,posix_setgid,posix_seteuid,posix_setegid,stream_socket_server,socket_bind,socket_listen,socket_accept,phpinfo,show_source,highlight_file,symlink,link,dl,assert,create_function,opcache_get_status,opcache_reset,apache_setenv,posix_getuid,posix_getgid,posix_getpwuid,get_current_user"

# PHP global security settings — key=value list (FIX: was using bash
# associative array which can be unreliable in strict mode)
#
# These are hosting-grade: they close real attack surface without breaking
# Composer, Laravel/Symfony, WordPress plugins, PHPMailer or payment returns.
# Not here on purpose: Reflection*/Phar classes (Composer and every modern
# framework need them), socket/DNS functions (mail and HTTP libraries),
# allow_url_fopen, SameSite=Strict, cookie_secure and size/time limits —
# those live in PHPSEC_STRICT_PAIRS and are applied only with --php-strict.
PHPSEC_PAIRS=(
    "allow_url_include:Off"
    "expose_php:Off"
    "display_errors:Off"
    "log_errors:On"
    "disable_classes:Imagick,ImagickDraw,ImagickPixel,ImagickPixelIterator,Gmagick"
    "file_uploads:On"
    "session.cookie_httponly:1"
    "session.use_strict_mode:1"
    "session.use_only_cookies:1"
    "session.cookie_samesite:Lax"
    "enable_dl:Off"
)
# --php-strict: single-purpose boxes where you control every application.
# Never written into a CLI php.ini (Composer, WP-CLI, Drush need the room).
PHPSEC_STRICT_PAIRS=(
    "allow_url_fopen:Off"
    "disable_classes:Imagick,ImagickDraw,ImagickPixel,ImagickPixelIterator,Gmagick,Phar,PharData"
    "session.cookie_secure:1"
    "session.cookie_samesite:Strict"
    "upload_tmp_dir:/tmp"
    "upload_max_filesize:2M"
    "post_max_size:8M"
    "memory_limit:128M"
    "max_execution_time:30"
    "max_input_time:30"
)
PHP_STRICT=false

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
    echo "   ║  Linux Server Security Hardening  v1.3  |  WondTech.com          ║"
    echo "   ║  One Script · Defence in Depth · Zero Compromise                 ║"
    echo "   ╚══════════════════════════════════════════════════════════════════╝"
    echo "────────────────────────────────────────────────────────────────────────"
    echo -e "${NC}"
}

# ─── Logging helpers ─────────────────────────────────────────────────────────
log_ok()     { echo -e "  ${GREEN}[OK]${NC}      $*"; }
log_warn()   { echo -e "  ${YELLOW}[WARN]${NC}    $*"; }
# FIX: was missing ${NC} and color, inconsistent with siblings
log_skip()   { echo -e "  ${CYAN}[SKIP]${NC}    $*"; }
log_info()   { echo -e "  ${CYAN}[INFO]${NC}    $*"; }
log_error()  { echo -e "  ${RED}[ERROR]${NC}   $*"; }
log_dry()    { echo -e "  ${YELLOW}[DRY-RUN]${NC} Would: $*"; }
section()    { echo ""; echo -e "${BOLD}${GREEN}══ $* ══${NC}"; echo ""; }

# ─── run_cmd: execute or print in dry-run ────────────────────────────────────
run_cmd() {
    if [ "$DRY_RUN" = true ]; then log_dry "$*"
    else "$@"; fi
}
# ─── Detect Timezone ─────────────────────────────────────────────────────────
_detect_timezone() {
    local _tz=""
    _tz=$(timedatectl 2>/dev/null | awk '/Time zone/{print $3}' | head -1 || true)
    [ -z "$_tz" ] && \
        _tz=$(cat /etc/timezone 2>/dev/null | head -1 | tr -d '[:space:]' || true)
    [ -z "$_tz" ] && \
        _tz=$(readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||' || true)
    [ -z "$_tz" ] && _tz="UTC"
    echo "$_tz"
}
# ─── backup_file: copy + record in undo manifest ─────────────────────────────
backup_file() {
    local src="$1" tag="${2:-file}"
    if [ ! -f "$src" ]; then
        # the caller is about to create it: undo = remove it
        [ "$DRY_RUN" = false ] && echo "RMFILE:${src}" >> "$UNDO_MANIFEST"
        return 0
    fi
    # full path in the name: /etc/php/8.1/fpm/php.ini and .../cli/php.ini
    # used to collide and --undo restored the wrong one
    local dest="${BACKUP_DIR}/${tag}_$(printf '%s' "$src" | sed 's|^/||; s|/|_|g').${TIMESTAMP}"
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
            if chown root:root "$bin" 2>/dev/null && chmod 750 "$bin" 2>/dev/null; then
                log_ok "Secured: $bin  →  $(stat -c '%A %U:%G' "$bin")"
            else
                log_warn "Could not secure $bin (immutable or read-only?) — left as is"
            fi
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

# ─── detect_vmail_dir: find Dovecot vmail directory ───────────────────────────
# FIX: was duplicated in 3 places (_lg_fixmail, _lg_status, LAYER 7)
# Returns the first existing path, or empty string if none found.
detect_vmail_dir() {
    local _vp
    for _vp in /var/vmail /home/vmail /var/mail/vhosts /var/spool/mail; do
        [ -d "$_vp" ] && echo "$_vp" && return 0
    done
    return 1
}

# ─── detect_site_paths: enumerate all hosted site roots ──────────────────────
# FIX: was duplicated in LAYER 5 (CGI/mod_php open_basedir) and watch_mode.
# Prints one path per line. Paths are de-duplicated.
detect_site_paths() {
    local _paths=() _d _docroot _conf
    # Standard locations
    for _d in /var/www/*/; do
        [ -d "$_d" ] && [[ "$_d" != "/var/www/html/" ]] && _paths+=("${_d%/}")
    done
    for _d in /home/*/public_html/; do
        [ -d "$_d" ] && _paths+=("${_d%/}")
    done
    [ -d /var/www/html ] && _paths+=("/var/www/html")
    # Custom document roots from web server configs
    for _conf in /etc/apache2/sites-enabled/*.conf \
                 /etc/httpd/conf.d/*.conf \
                 /etc/nginx/sites-enabled/* \
                 /etc/nginx/conf.d/*.conf; do
        [ -f "$_conf" ] || continue
        while IFS= read -r _docroot; do
            [ -d "$_docroot" ] && _paths+=("$_docroot")
        done < <(grep -hEi \
            '^\s*(DocumentRoot|root)\s+"?([^";\s]+)"?' "$_conf" 2>/dev/null \
            | awk '{print $NF}' | tr -d '";')
    done
    [ ${#_paths[@]} -gt 0 ] && printf '%s\n' "${_paths[@]}" | sort -u
}

# ─── install_pkg: cross-distro package install ───────────────────────────────
# FIX: was sending 2>/dev/null on every package manager, hiding real errors
# (lock conflicts, repo unreachable, missing deps). Now logs to LOG_FILE so
# the user can debug failures.
install_pkg() {
    local pkg="$1" _log="${LOG_FILE:-/var/log/lg-hardening.log}"
    if command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" \
            >> "$_log" 2>&1
    elif command -v dnf &>/dev/null; then
        dnf install -y -q "$pkg" >> "$_log" 2>&1
    elif command -v yum &>/dev/null; then
        yum install -y -q "$pkg" >> "$_log" 2>&1
    elif command -v apk &>/dev/null; then
        apk add -q "$pkg" >> "$_log" 2>&1
    elif command -v pacman &>/dev/null; then
        pacman -S --noconfirm -q "$pkg" >> "$_log" 2>&1
    else
        log_warn "No supported package manager found for: $pkg"
        return 1
    fi
}

# ── detect_php_mode: returns fpm / cgi / mod_php ─────────────────────────────
detect_php_mode() {
    # Auto-detect any installed php-fpm binary
    while IFS= read -r b; do
        command -v "$b" &>/dev/null \
            || [ -x "/usr/sbin/${b}" ] \
            || [ -x "/usr/local/sbin/${b}" ] \
            && echo "fpm" && return
    done < <(compgen -c 2>/dev/null | grep -E "^php(-fpm|[0-9.]+-fpm)[0-9.]*$" | sort -u || \
             find /usr/sbin /usr/local/sbin /usr/bin /usr/local/bin \
                  -name "php-fpm*" -o -name "php*-fpm" 2>/dev/null \
             | xargs -I{} basename {} | sort -u || true)
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
    # Check standard fixed paths first
    for d in /etc/php-fpm.d /usr/local/etc/php-fpm.d; do
        [ -d "$d" ] && echo "$d" && return
    done
    # Auto-detect versioned pool directories
    local _d
    _d=$(find /etc/php /usr/local/etc/php \
              -maxdepth 4 -type d -name "pool.d" \
              2>/dev/null | sort -rV | head -1 || true)
    [ -n "$_d" ] && echo "$_d" && return
    echo ""
}

# ── detect_webserver_user: find the web server socket owner ──────────────────
detect_webserver_user() {
    # Returns the user that owns the web server process
    for _ws in nginx apache2 httpd lighttpd caddy; do
        if svc_running "$_ws" 2>/dev/null; then
            case "$_ws" in
                nginx)              echo "nginx";    return ;;
                apache2)            echo "www-data"; return ;;
                httpd)              echo "apache";   return ;;
                lighttpd)           echo "lighttpd"; return ;;
                caddy)              echo "caddy";    return ;;
            esac
        fi
    done
    # Fallback — read from process table
    local _u
    _u=$(ps aux 2>/dev/null | grep -E "nginx|apache2|httpd" \
        | grep -v grep | awk '{print $1}' | grep -v root | head -1 || true)
    [ -n "$_u" ] && echo "$_u" && return
    echo "apache"  # safe default
}
restart_php_services() {
    local mode="$1" _restarted=0 svc
    case "$mode" in
        fpm)
            # Auto-detect active php-fpm service
            while IFS= read -r svc; do
                systemctl is-active --quiet "$svc" 2>/dev/null && {
                    systemctl restart "$svc" 2>/dev/null \
                        && { log_ok "Restarted: $svc"; _restarted=1; } \
                        || log_warn "Failed to restart: $svc"
                }
            done < <({ systemctl list-units --type=service --state=active \
                            --no-legend 2>/dev/null \
                          | awk '{print $1}' \
                          | grep -E "^php.*fpm" | sort -rV
                        echo "php-fpm"
                      } | sort -u || true)
            [ "$_restarted" -eq 0 ] && \
                log_warn "No active php-fpm service — restart manually"
            ;;
        cgi|mod_php)
            # FIX: was inlined 13-line loop, now uses shared helper
            restart_active_webserver || log_warn "No active web server to restart"
            ;;
    esac
    return 0
}

# ── restart_active_webserver: restart the first active web server ─────────────
# FIX: extracted from watch_mode and LAYER 5 (was duplicated 2x).
# Iterates nginx/apache2/httpd/lighttpd/caddy; restarts the first one
# found active. Returns 0 if restarted, 1 otherwise.
restart_active_webserver() {
    local _svc _restarted=0
    while IFS= read -r _svc; do
        if systemctl is-active --quiet "$_svc" 2>/dev/null; then
            if systemctl restart "$_svc" 2>/dev/null; then
                log_ok "Restarted: ${_svc}"
                _restarted=1
                break
            else
                log_warn "Failed to restart: ${_svc}"
            fi
        fi
    done < <(systemctl list-units --type=service --state=active \
                 --no-legend 2>/dev/null \
             | awk '{print $1}' \
             | grep -E "^(nginx|apache2|httpd|lighttpd|caddy)\.service" \
             | sed 's/\.service//' \
             || printf 'apache2\nhttpd\nnginx\n')
    [ "$_restarted" -eq 0 ] && log_warn "No active web service found to restart"
    return $((1-_restarted))
}

# ── detect_panel: returns panel name and service name ────────────────────────
detect_panel() {
    # Returns: "PanelName:service_name" or "none:"
    { [ -d /usr/local/cwpsrv ] || [ -f /usr/local/cwp/php71/bin/php ]; } \
        && echo "CWP:cwpsrv"          && return
    [ -d /usr/local/cpanel ] \
        && echo "cPanel:cpanel"        && return
    { [ -d /usr/local/psa ] || [ -d /opt/psa ]; } \
        && echo "Plesk:psa"            && return
    [ -d /usr/local/directadmin ] \
        && echo "DirectAdmin:directadmin" && return
    { [ -d /usr/local/CyberPanel ] || [ -f /usr/bin/cyberpanel ]; } \
        && echo "CyberPanel:lsws"      && return
    { [ -d /usr/local/hestia ] || [ -f /usr/local/hestia/bin/v-list-users ]; } \
        && echo "HestiaCP:hestia"      && return
    { [ -d /usr/local/vesta ] || [ -f /usr/local/vesta/bin/v-list-users ]; } \
        && echo "VestaCP:vesta"        && return
    [ -d /usr/local/ispconfig ] \
        && echo "ISPConfig:ispconfig"  && return
    { [ -d /www/server/panel ] || [ -f /usr/bin/bt ]; } \
        && echo "aaPanel:bt"           && return
    { [ -d /usr/share/webmin ] || [ -f /usr/bin/webmin ]; } \
        && echo "Webmin:webmin"        && return
    [ -d /usr/local/interworx ] \
        && echo "InterWorx:iworx"      && return
    { [ -d /var/www/froxlor ] || [ -d /usr/share/froxlor ]; } \
        && echo "Froxlor:froxlor"      && return
    [ -d /etc/runcloud ] \
        && echo "RunCloud:runcloud-hub" && return
    [ -f /usr/bin/centmin ] \
        && echo "CentminMod:nginx"     && return
    echo "none:"
}

# ── _build_dovecot_lg_policy: write the .te file for a given vmail type ──────
# FIX: extracted from _lg_fixmail and LAYER 7 SELinux branch.
# Usage: _build_dovecot_lg_policy <te_file> <vmail_type>
# vmail_type must be either "dovecot_var_t" or "mail_spool_t".
_build_dovecot_lg_policy() {
    local _te_file="$1" _vmail_type="$2"
    if [ "$_vmail_type" = "dovecot_var_t" ]; then
        cat > "$_te_file" << 'DOVEPOL'
module dovecot_lg 1.1;
require {
    type dovecot_t; type mysqld_db_t; type var_t; type dovecot_var_t;
    class file { append create getattr link lock map open read rename unlink write };
    class dir  { add_name getattr read remove_name write };
    class sock_file write;
}
allow dovecot_t mysqld_db_t:sock_file write;
allow dovecot_t var_t:dir  { add_name getattr read remove_name write };
allow dovecot_t var_t:file { append create getattr link lock map open read rename unlink write };
allow dovecot_t dovecot_var_t:dir  { add_name getattr read remove_name write };
allow dovecot_t dovecot_var_t:file { append create getattr link lock map open read rename unlink write };
DOVEPOL
    else
        cat > "$_te_file" << 'DOVEPOL'
module dovecot_lg 1.1;
require {
    type dovecot_t; type mysqld_db_t; type var_t; type mail_spool_t;
    class file { append create getattr link lock map open read rename unlink write };
    class dir  { add_name getattr read remove_name write };
    class sock_file write;
}
allow dovecot_t mysqld_db_t:sock_file write;
allow dovecot_t var_t:dir  { add_name getattr read remove_name write };
allow dovecot_t var_t:file { append create getattr link lock map open read rename unlink write };
allow dovecot_t mail_spool_t:dir  { add_name getattr read remove_name write };
allow dovecot_t mail_spool_t:file { append create getattr link lock map open read rename unlink write };
DOVEPOL
    fi
}

# ── _install_dovecot_lg_policy: build + load the SELinux policy module ───────
# FIX: extracted from _lg_fixmail and LAYER 7 (was duplicated 2x, ~30 lines each).
# Usage: _install_dovecot_lg_policy <vmail_type>
_install_dovecot_lg_policy() {
    local _vmail_type="$1"
    if ! command -v checkmodule &>/dev/null || \
       ! command -v semodule_package &>/dev/null; then
        log_warn "checkmodule/semodule_package not found — install checkpolicy"
        return 1
    fi
    local _te _mod _pp _err
    _te=$(mktemp /tmp/dovecot_lg_XXXXXX.te)
    _mod="${_te%.te}.mod"
    _pp="${_te%.te}.pp"
    _build_dovecot_lg_policy "$_te" "$_vmail_type"
    _err=$(checkmodule -M -m -o "$_mod" "$_te" 2>&1) || {
        log_warn "dovecot_lg build failed: ${_err}"
        rm -f "$_te" "$_mod" "$_pp"
        return 1
    }
    _err=$(semodule_package -o "$_pp" -m "$_mod" 2>&1) || {
        log_warn "dovecot_lg package failed: ${_err}"
        rm -f "$_te" "$_mod" "$_pp"
        return 1
    }
    semodule -i "$_pp" 2>/dev/null && \
        log_ok "SELinux policy applied: dovecot_lg v1.1" || \
        log_warn "semodule -i failed — try: sudo lg --force"
    rm -f "$_te" "$_mod" "$_pp"
    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION: _lg_fixmail — Fix Dovecot/vmail SELinux contexts
# ══════════════════════════════════════════════════════════════════════════════
_lg_fixmail() {
    section "FIXMAIL: Dovecot / vmail SELinux Fix"

    # FIX: was inlined 4-line loop. Now uses shared helper.
    _FM_VMAIL=$(detect_vmail_dir 2>/dev/null) || _FM_VMAIL=""

    if [ -z "$_FM_VMAIL" ]; then
        log_warn "No vmail directory found — nothing to fix"
        return 0
    fi
    log_info "Mail storage: ${_FM_VMAIL}"

    # Detect correct SELinux type
    _FM_TYPE="mail_spool_t"
    grep -q "dovecot_var_t" \
        /etc/selinux/targeted/contexts/files/file_contexts 2>/dev/null \
        && _FM_TYPE="dovecot_var_t"
    log_info "SELinux type: ${_FM_TYPE}"

    # Register fcontext
    if command -v semanage &>/dev/null; then
        semanage fcontext -d "${_FM_VMAIL}(/.*)?" 2>/dev/null || true
        semanage fcontext -a -t "$_FM_TYPE" "${_FM_VMAIL}(/.*)?" 2>/dev/null || true
        semanage fcontext -l 2>/dev/null | grep -q "${_FM_VMAIL}.*${_FM_TYPE}" \
            && log_ok "fcontext registered: ${_FM_VMAIL} → ${_FM_TYPE}" \
            || log_warn "fcontext registration failed — applying chcon directly"
    fi

    # Remove stale lock files + relabel
    # FIX: was toggling SELinux on/off (setenforce 0/1) which opens a window
    # for rootkit escape. restorecon works fine with SELinux enabled —
    # it just adjusts labels on already-allowed operations.
    find "$_FM_VMAIL" -name "*.lock" -delete 2>/dev/null || true
    restorecon -RFv "$_FM_VMAIL" 2>/dev/null | tail -5 || true
    log_ok "restorecon applied: ${_FM_VMAIL}"

    # Fix Dovecot log contexts
    for _dlog in "${DOVECOT_LOG_PATHS[@]}"; do
        [ -f "$_dlog" ] || continue
        command -v semanage &>/dev/null && {
            semanage fcontext -a -t dovecot_var_log_t "$_dlog" 2>/dev/null \
                || semanage fcontext -m -t dovecot_var_log_t "$_dlog" 2>/dev/null || true
        }
        chcon -t dovecot_var_log_t "$_dlog" 2>/dev/null || true
        log_ok "Log context fixed: ${_dlog}"
    done

    # Apply dovecot_lg policy (FIX: was inlined ~40 lines, now uses helper)
    _install_dovecot_lg_policy "$_FM_TYPE" || log_warn "dovecot_lg policy not installed (checkmodule/semodule_package missing?)"

    setsebool -P domain_can_mmap_files 1 2>/dev/null \
        && log_ok "SELinux bool: domain_can_mmap_files = on" || true

    # NOTE: fcontext re-registration after semodule was removed — semodule -i
    # doesn't affect fcontext entries (they live in file_contexts.local, not
    # the policy module). Original re-registration was a no-op duplicate.

    # Restart Dovecot
    if systemctl is-active --quiet dovecot 2>/dev/null; then
        systemctl restart dovecot 2>/dev/null \
            && log_ok "Dovecot restarted successfully" \
            || log_warn "Dovecot restart failed"
    elif systemctl is-enabled --quiet dovecot 2>/dev/null; then
        systemctl start dovecot 2>/dev/null \
            && log_ok "Dovecot started successfully" \
            || log_warn "Dovecot failed to start"
    else
        log_skip "Dovecot not installed"
    fi

    log_ok "fixmail complete"
}

# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION: _lg_scan — Scan for webshells and reverse shells
# ══════════════════════════════════════════════════════════════════════════════
LG_SCAN_ALLOW="/root/lg/scan.allow"      # one path or glob per line, # comments

_lg_scan() {
    local SCAN_PATH="${1:-}"
    local PATHS=()
    # files that are exact copies of this script (a published lg.sh under a web
    # root) and anything the admin allow-listed are never reported
    local LG_SELF_SIZE LG_SELF_SHA _g
    LG_SELF_SIZE=$(stat -c %s "$0" 2>/dev/null || echo 0)
    LG_SELF_SHA=$(sha256sum "$0" 2>/dev/null | cut -d" " -f1)
    local SCAN_ALLOW=()
    if [ -f "$LG_SCAN_ALLOW" ]; then
        while IFS= read -r _g; do
            _g="${_g%%#*}"; _g="${_g#"${_g%%[![:space:]]*}"}"; _g="${_g%"${_g##*[![:space:]]}"}"
            [ -n "$_g" ] && SCAN_ALLOW+=("$_g")
        done < "$LG_SCAN_ALLOW"
    fi
    _scan_allowed() {
        local f="$1" g
        if [ "$(stat -c %s "$f" 2>/dev/null)" = "$LG_SELF_SIZE" ] && \
           [ "$(sha256sum "$f" 2>/dev/null | cut -d" " -f1)" = "$LG_SELF_SHA" ]; then return 0; fi
        for g in ${SCAN_ALLOW[@]+"${SCAN_ALLOW[@]}"}; do
            # shellcheck disable=SC2053
            [[ "$f" == $g ]] && return 0
        done
        return 1
    }
    if [ -n "$SCAN_PATH" ] && [ -d "$SCAN_PATH" ]; then
        PATHS=("$SCAN_PATH")
    else
        for d in /var/www /home/*/public_html /tmp /var/tmp /dev/shm; do
            [ -d "$d" ] && PATHS+=("$d")
        done
    fi

    section "SCAN: Malicious File Detection"
    log_info "Scanning: ${PATHS[*]}"
    log_info "Log: ${LG_SCAN_LOG}"
    log_info "Allow-list: ${LG_SCAN_ALLOW} (${#SCAN_ALLOW[@]} entries)"
    echo ""

    local FOUND=0
    local TS
    TS=$(date '+%Y-%m-%d %H:%M:%S')
    echo "# Linux Guardian Scan — ${TS}" >> "$LG_SCAN_LOG"

    local PHP_PATTERNS=(
        'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|rawurldecode)'
        'base64_decode[[:space:]]*\(.*eval|eval[[:space:]]*\(.*base64_decode'
        '@(eval|system|exec|passthru|shell_exec|popen|proc_open)[[:space:]]*\('
        '(system|exec|passthru|shell_exec|popen|proc_open|assert)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
        '\$[a-zA-Z_]\w*[[:space:]]*=[[:space:]]*["\x27](system|exec|passthru|shell_exec|popen)["\x27]'
        'function_exists[[:space:]]*\([[:space:]]*["\x27](exec|shell_exec|system|passthru|popen|proc_open)["\x27]'
        'preg_replace[[:space:]]*\(.*["\x27][^"]*\/e["\x27]'
        'file_put_contents[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST)'
        'move_uploaded_file[[:space:]]*\(.*\$_(FILES|GET|POST|REQUEST)'

    )

    local GENERAL_PATTERNS=(
        'use[[:space:]]+Socket.*connect.*STDOUT'
        'import[[:space:]]+socket.*subprocess|subprocess.*import[[:space:]]+socket'
        'os\.(system|popen|execve|execvp)[[:space:]]*\('
        'subprocess\.(call|Popen|run)[[:space:]]*\('
        '/dev/tcp/|/dev/udp/'
        'bash[[:space:]]+-i[[:space:]]*>&[[:space:]]*/dev/tcp'
        'python.*socket.*connect|perl.*socket.*connect'
        'nc[[:space:]]+-e[[:space:]]*/bin|ncat[[:space:]]+-e[[:space:]]*/bin'
        'bash.*>[[:space:]]*&.*tcp|sh.*>[[:space:]]*&.*tcp'
        'socket\.connect\([[:space:]]*\([[:space:]]*["\x27][0-9]'
        'IO::Socket::INET->new'
    )
    _scan_dir() {
        local dir="$1"
        [ -d "$dir" ] || return 0
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            _scan_allowed "$f" && continue
            for pat in "${PHP_PATTERNS[@]}"; do
                if grep -qiP "$pat" "$f" 2>/dev/null || \
                   grep -qiE "$pat" "$f" 2>/dev/null; then
                    echo -e "  ${RED}[WARN]${NC} PHP webshell: $f"
                    echo -e "         Pattern: $pat"
                    echo "[WARN] PHP webshell: $f | Pattern: $pat" \
                        >> "$LG_SCAN_LOG"
                    FOUND=$((FOUND+1))
                    break
                fi
            done
        done < <(find "$dir" -type f \
            \( -name "*.php" -o -name "*.php5" -o -name "*.php7" \
               -o -name "*.php8" -o -name "*.phtml" -o -name "*.phar" \) \
            -not -path "*/vendor/*" \
            -not -path "*/.git/*" \
            2>/dev/null)
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            _scan_allowed "$f" && continue
            for pat in "${GENERAL_PATTERNS[@]}"; do
                if grep -qiE "$pat" "$f" 2>/dev/null; then
                    echo -e "  ${RED}[WARN]${NC} Reverse shell: $f"
                    echo -e "         Pattern: $pat"
                    echo "[WARN] Reverse shell: $f | Pattern: $pat" \
                        >> "$LG_SCAN_LOG"
                    FOUND=$((FOUND+1))
                    break
                fi
            done
        done < <(find "$dir" -type f \
            \( -name "*.pl" -o -name "*.py" -o -name "*.sh" -o -name ".*" \) \
            -not -path "*/vendor/*" \
            -not -path "*/.git/*" \
            2>/dev/null)
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            _scan_allowed "$f" && continue
            echo -e "  ${YELLOW}[WARN]${NC} Executable in web dir: $f"
            echo "[WARN] Executable in web dir: $f" >> "$LG_SCAN_LOG"
            FOUND=$((FOUND+1))
        done < <(find "$dir" -type f \
            \( -name "*.sh" -o -name "*.pl" -o -name "*.py" -o -name "*.elf" \) \
            -not -path "*/vendor/*" \
            -not -path "*/.git/*" \
            2>/dev/null)
    }

    for p in ${PATHS[@]+"${PATHS[@]}"}; do
        log_info "Scanning: $p"
        _scan_dir "$p"
    done

    echo ""
    if [ "$FOUND" -gt 0 ]; then
        echo -e "  ${RED}[ALERT]${NC} ${FOUND} suspicious file(s) found — review: ${LG_SCAN_LOG}"
        command -v mail &>/dev/null && \
            echo "Linux Guardian SCAN ALERT: ${FOUND} suspicious files on $(hostname)" \
            | mail -s "[LG ALERT] Webshell scan: $(hostname)" \
              "${ALERT_EMAIL:-root}" 2>/dev/null || true
    else
        echo -e "  ${GREEN}[OK]${NC}      No suspicious files found"
    fi
    log_ok "Scan complete — ${FOUND} finding(s)"
}

# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION: _lg_analyze — Analyze system behavior for anomalies
# ══════════════════════════════════════════════════════════════════════════════
_lg_analyze() {
    section "ANALYZE: System Behavior Analysis"
    log_info "Log: ${LG_ANALYZE_LOG}"
    echo ""

    local TS ISSUES=0
    TS=$(date '+%Y-%m-%d %H:%M:%S')
    echo "# Linux Guardian Analysis — ${TS}" >> "$LG_ANALYZE_LOG"

    # ── 1. Suspicious outbound connections ────────────────────────────────────
    echo -e "  ${BOLD}[NET]${NC} Outbound connections:"
    local EXPECTED_PORTS="80|443|22|25|53|143|465|587|993|3306|5432|11371|873"
    # ports this host listens on: a connection whose LOCAL port is one of
    # them is inbound (a client talking to us) and is not judged here
    local LISTEN_PORTS
    LISTEN_PORTS=$(ss -Htln 2>/dev/null | awk '{print $4}' | rev | cut -d: -f1 | rev | sort -u | tr '\n' '|' | sed 's/|$//')
    while IFS= read -r conn; do
        local proc port lport
        # `ss -H ... state established` prints: Recv-Q Send-Q Local Peer Process
        proc=$(echo "$conn" | awk '{print $5}' | cut -d/ -f2 || true)
        lport=$(echo "$conn" | awk '{print $3}' | rev | cut -d: -f1 | rev || true)
        port=$(echo "$conn" | awk '{print $4}' | rev | cut -d: -f1 | rev || true)
        [ -n "$LISTEN_PORTS" ] && echo "$lport" | grep -qE "^(${LISTEN_PORTS})$" && continue
        if ! echo "$port" | grep -qE "^(${EXPECTED_PORTS})$"; then
            echo -e "    ${YELLOW}⚠${NC} Suspicious: $conn"
            echo "[WARN] Suspicious connection: $conn" >> "$LG_ANALYZE_LOG"
            ISSUES=$((ISSUES+1))
        fi
    done < <(ss -Htnp state established 2>/dev/null | grep -v "127.0.0.1\|::1" | tail -20 || true)
    [ "$ISSUES" -eq 0 ] && echo -e "    ${GREEN}✓${NC} No suspicious connections"

    # ── 2. Suspicious running processes ───────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}[PROC]${NC} Suspicious processes:"

    local PROC_ISSUES=0
    while IFS= read -r proc; do
        echo -e "    ${RED}⚠${NC} Process from /tmp|/dev: $proc"
        echo "[WARN] Suspicious process: $proc" >> "$LG_ANALYZE_LOG"
        PROC_ISSUES=$((PROC_ISSUES+1))
    done < <(
        # executable (or a deleted one) under a world-writable temp dir —
        # argument strings like --socket=/tmp/mysql.sock are not evidence
        for _pd in /proc/[0-9]*; do
            _pe=$(readlink "$_pd/exe" 2>/dev/null) || continue
            case "$_pe" in
                (/tmp/*|/var/tmp/*|/dev/shm/*|*"(deleted)") echo "${_pd#/proc/}  ${_pe}  $(tr '\0' ' ' < "$_pd/cmdline" 2>/dev/null | cut -c1-120)" ;;
            esac
        done 2>/dev/null \
        | head -10 || true
    )

    for pid_dir in /proc/[0-9]*; do
        pid="${pid_dir##*/}"
        [ -r "/proc/$pid/cmdline" ] || continue
        cmd=""
        if IFS= read -r -d '' cmd < "/proc/$pid/cmdline" 2>/dev/null; then
            :
        fi
        cmd=${cmd//[$'\n']/ }
        cmd=${cmd:0:50}
        [ -z "$cmd" ] && continue
        if [[ "$cmd" == .* ]]; then
            echo -e "    ${RED}⚠${NC} Hidden process (PID $pid): $cmd"
            echo "[WARN] Hidden process PID=$pid cmd=$cmd" >> "$LG_ANALYZE_LOG"
            PROC_ISSUES=$((PROC_ISSUES+1))
        fi
    done

    if [ "$PROC_ISSUES" -eq 0 ]; then
        echo -e "    ${GREEN}✓${NC} No suspicious processes"
    fi

    ISSUES=$((ISSUES+PROC_ISSUES))
    # ── 3. Recently modified system files ─────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}[FILES]${NC} System files modified in last 24h:"
    local FILE_ISSUES=0
    while IFS= read -r f; do
        echo -e "    ${YELLOW}⚠${NC} Modified: $f"
        echo "[WARN] System file modified: $f" >> "$LG_ANALYZE_LOG"
        FILE_ISSUES=$((FILE_ISSUES+1))
    done < <(find /etc /usr/bin /usr/sbin /bin /sbin \
        -mmin -1440 -type f 2>/dev/null \
        | grep -vE "\.pyc$|__pycache__|\.log$|/etc/pki/ca-trust/extracted/|/etc/ld\.so\.cache$|/etc/resolv\.conf$|/etc/mtab$|/etc/adjtime$|/etc/\.updated$|/etc/aliases\.db$|/etc/csf/|/etc/lg/" | head -10 || true)
    [ "$FILE_ISSUES" -eq 0 ] && echo -e "    ${GREEN}✓${NC} No system files modified"
    ISSUES=$((ISSUES+FILE_ISSUES))

    # ── 4. Failed login attempts ───────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}[AUTH]${NC} Failed logins (last 1h):"

    local FAIL_COUNT=0
    if command -v journalctl >/dev/null 2>&1; then
        FAIL_COUNT=$(journalctl --since "1 hour ago" 2>/dev/null \
            | grep -i "failed password" \
            | wc -l)
    else
        FAIL_COUNT=$((
            grep -h "Failed password" /var/log/auth.log /var/log/secure 2>/dev/null
        ) | wc -l)
    fi
    FAIL_COUNT=$(echo "$FAIL_COUNT" | tr -d '[:space:]')
    case "$FAIL_COUNT" in
        ''|*[!0-9]*) FAIL_COUNT=0 ;;
    esac
    if [ "$FAIL_COUNT" -gt 50 ]; then
        echo -e "    ${RED}⚠${NC} ${FAIL_COUNT} failed logins — possible brute force"
        echo "[WARN] ${FAIL_COUNT} failed logins in last hour" >> "$LG_ANALYZE_LOG"
        ISSUES=$((ISSUES+1))
    else
        echo -e "    ${GREEN}✓${NC} ${FAIL_COUNT} failed logins (normal)"
    fi

    # ── 5. Suspicious crontab entries ─────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}[CRON]${NC} Crontab entries:"
    local CRON_ISSUES=0
    while IFS= read -r entry; do
        if echo "$entry" | grep -qE "/tmp/|/dev/shm|wget|curl|bash -i|nc "; then
            echo -e "    ${RED}⚠${NC} Suspicious cron: $entry"
            echo "[WARN] Suspicious crontab: $entry" >> "$LG_ANALYZE_LOG"
            CRON_ISSUES=$((CRON_ISSUES+1))
        fi
    done < <({ crontab -l 2>/dev/null
                for f in /etc/cron* /var/spool/cron/crontabs/*; do
                    [ -f "$f" ] && cat "$f" 2>/dev/null
                done; } | grep -v "^#" || true)
    [ "$CRON_ISSUES" -eq 0 ] && echo -e "    ${GREEN}✓${NC} No suspicious cron entries"
    ISSUES=$((ISSUES+CRON_ISSUES))

    # ── 6. Listening ports check ──────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}[PORTS]${NC} Unexpected listening ports:"
    local PORT_ISSUES=0
    local KNOWN_PORTS="20|21|22|25|53|80|110|143|443|465|587|953|993|995|2812|3306|5432|8080|8443|8787|9000|9090|2030|2031|2082|2083|2086|2087|2095|2096|2302|2525|11211|6379"
    while IFS= read -r port_line; do
        local lport
        # `ss -Htlnp` prints: State Recv-Q Send-Q Local Peer Process
        lport=$(echo "$port_line" | awk '{print $4}' | rev | cut -d: -f1 | rev || true)
        if ! echo "$lport" | grep -qE "^(${KNOWN_PORTS})$"; then
            echo -e "    ${YELLOW}⚠${NC} Unexpected port: $port_line"
            echo "[INFO] Unexpected listening port: $port_line" >> "$LG_ANALYZE_LOG"
            PORT_ISSUES=$((PORT_ISSUES+1))
        fi
    done < <(ss -Htlnp 2>/dev/null || true)
    [ "$PORT_ISSUES" -eq 0 ] && echo -e "    ${GREEN}✓${NC} All listening ports look normal"

    echo ""
    echo "────────────────────────────────────────────────────────────────────────"
    if [ "$ISSUES" -gt 0 ]; then
        echo -e "  ${RED}[ALERT]${NC} ${ISSUES} anomalie(s) detected — review: ${LG_ANALYZE_LOG}"
        if command -v mail &>/dev/null; then
            echo "Linux Guardian ANALYZE ALERT: ${ISSUES} anomalies on $(hostname)" \
                | mail -s "[LG ALERT] Behavior analysis: $(hostname)" "${ALERT_EMAIL:-root}" \
                2>/dev/null || true
        fi
    else
        echo -e "  ${GREEN}[OK]${NC}      System behavior looks normal"
    fi
    log_ok "Analysis complete — ${ISSUES} anomalie(s)"
}

# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION: _lg_integrity — File integrity check
# ══════════════════════════════════════════════════════════════════════════════
_lg_integrity() {
    section "INTEGRITY: Critical File Integrity Check"

    local CRITICAL_FILES=(
        /etc/passwd /etc/shadow /etc/group /etc/gshadow
        /etc/ssh/sshd_config /etc/sudoers
        /boot/grub2/grub.cfg /boot/grub/grub.cfg
        /usr/bin/sudo /usr/bin/su /usr/sbin/sshd
        /usr/sbin/useradd /usr/sbin/userdel
    )

    if [ ! -f "$LG_INTEGRITY_DB" ]; then
        # First run — build database
        log_info "Building integrity database: ${LG_INTEGRITY_DB}"
        mkdir -p "$(dirname "$LG_INTEGRITY_DB")"
        : > "$LG_INTEGRITY_DB"
        for f in "${CRITICAL_FILES[@]}"; do
            [ -f "$f" ] || continue
            local hash
            hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}' || true)
            [ -n "$hash" ] && echo "${hash}  ${f}" >> "$LG_INTEGRITY_DB"
            log_ok "Recorded: $f"
        done
        chmod 600 "$LG_INTEGRITY_DB"
        log_ok "Integrity database created: ${LG_INTEGRITY_DB}"
        log_info "Run 'sudo lg --integrity' again to verify"
        return 0
    fi

    # Verify against database
    local CHANGES=0
    log_info "Verifying against: ${LG_INTEGRITY_DB}"
    echo ""
    while IFS= read -r line; do
        local stored_hash stored_file current_hash
        stored_hash=$(echo "$line" | awk '{print $1}')
        stored_file=$(echo "$line" | awk '{print $2}')
        [ -f "$stored_file" ] || {
            echo -e "  ${RED}[WARN]${NC} MISSING: ${stored_file}"
            echo "[WARN] File missing: ${stored_file}" >> "$LG_ANALYZE_LOG"
            CHANGES=$((CHANGES+1))
            continue
        }
        current_hash=$(sha256sum "$stored_file" 2>/dev/null | awk '{print $1}' || true)
        if [ "$current_hash" != "$stored_hash" ]; then
            echo -e "  ${RED}[WARN]${NC} MODIFIED: ${stored_file}"
            echo "[WARN] File modified: ${stored_file}" >> "$LG_ANALYZE_LOG"
            CHANGES=$((CHANGES+1))
        else
            echo -e "  ${GREEN}[OK]${NC}      ${stored_file}"
        fi
    done < "$LG_INTEGRITY_DB"

    echo ""
    if [ "$CHANGES" -gt 0 ]; then
        echo -e "  ${RED}[ALERT]${NC} ${CHANGES} file(s) changed since last check"
        if command -v mail &>/dev/null; then
            echo "Linux Guardian INTEGRITY ALERT: ${CHANGES} files changed on $(hostname)" \
                | mail -s "[LG ALERT] Integrity check: $(hostname)" "${ALERT_EMAIL:-root}" \
                2>/dev/null || true
        fi
    else
        echo -e "  ${GREEN}[OK]${NC}      All critical files intact"
    fi
    log_ok "Integrity check complete — ${CHANGES} change(s)"
}

# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION: _lg_auto_analyze — Background monitoring daemon
# ══════════════════════════════════════════════════════════════════════════════
_lg_auto_analyze() {
    local INTERVAL=300
    local PID_FILE="/var/run/lg-analyze.pid"

    # Stop any existing instance via PID file only
    if [ -f "$PID_FILE" ]; then
        _OLD=$(cat "$PID_FILE" 2>/dev/null || true)
        if [ -n "$_OLD" ]; then
            kill "$_OLD" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$PID_FILE"
    fi

    section "AUTO-ANALYZE: Starting background monitoring (every ${INTERVAL}s)"
    log_info "PID file: ${PID_FILE}"
    log_info "Log: ${LG_ANALYZE_LOG}"
    log_info "Stop with: kill \$(cat ${PID_FILE})"
    echo ""

    # Run as background daemon
    (
        set +euo pipefail
        echo "${BASHPID}" > "$PID_FILE"
        while true; do
            {
                echo "# ── Auto-analyze $(date '+%Y-%m-%d %H:%M:%S') ──"
                # 1. Suspicious processes — one mail per distinct command line
                #    per hour (mysqld --socket=/tmp/mysql.sock used to mail root
                #    every 5 minutes forever)
                _SEEN=/run/lg-analyze.seen; touch "$_SEEN"
                for _pd in /proc/[0-9]*; do
                    _pe=$(readlink "$_pd/exe" 2>/dev/null) || continue
                    case "$_pe" in (/tmp/*|/var/tmp/*|/dev/shm/*) echo "${_pd#/proc/} ${_pe} $(tr '\0' ' ' < "$_pd/cmdline" 2>/dev/null | cut -c1-120)" ;; esac
                done 2>/dev/null | while read -r p; do
                    echo "[AUTO-WARN] Suspicious process: $p"
                    _sig=$(printf '%s' "${p#* }" | md5sum | cut -c1-16)
                    _last=$(grep "^${_sig} " "$_SEEN" 2>/dev/null | cut -d" " -f2)
                    [ -n "$_last" ] && [ $(( $(date +%s) - _last )) -lt 3600 ] && continue
                    { grep -v "^${_sig} " "$_SEEN" 2>/dev/null; echo "${_sig} $(date +%s)"; } > "${_SEEN}.tmp" && mv "${_SEEN}.tmp" "$_SEEN"
                    command -v mail &>/dev/null && \
                        echo "$p" | mail \
                            -s "[LG AUTO-ALERT] Suspicious process: $(hostname)" \
                            "${ALERT_EMAIL:-root}" 2>/dev/null || true
                done
                # 2. Executables in /tmp
                find /tmp /var/tmp -type f -perm /111 2>/dev/null | \
                    while read -r f; do
                    echo "[AUTO-WARN] Executable in /tmp: $f"
                    command -v mail &>/dev/null && \
                        echo "$f" | mail \
                            -s "[LG AUTO-ALERT] Executable in /tmp: $(hostname)" \
                            "${ALERT_EMAIL:-root}" 2>/dev/null || true
                done
                # 3. New SUID files vs baseline (fixed: was using grep -vF with
                #    multi-line baseline which never matched as a single string,
                #    causing 100% false-positive alerts).
                if [ -s /root/lg/.suid_baseline ]; then
                    comm -23 \
                        <(find / -xdev -perm -4000 -type f 2>/dev/null | sort) \
                        <(sort /root/lg/.suid_baseline 2>/dev/null) | \
                        while read -r f; do
                            [ -z "$f" ] && continue
                            echo "[AUTO-WARN] New SUID file: $f"
                            command -v mail &>/dev/null && \
                                echo "$f" | mail \
                                    -s "[LG AUTO-ALERT] New SUID: $(hostname)" \
                                    "${ALERT_EMAIL:-root}" 2>/dev/null || true
                        done
                fi
            } >> "$LG_ANALYZE_LOG" 2>&1
            sleep "$INTERVAL"
        done
    ) &
    local _DAEMON_PID=$!
    disown "$_DAEMON_PID" 2>/dev/null || true
    sleep 0.5
    local _REAL_PID
    _REAL_PID=$(cat "$PID_FILE" 2>/dev/null || echo "$_DAEMON_PID")
    log_ok "Background monitoring started (PID: ${_REAL_PID})"

    # Build SUID baseline
    find / -xdev -perm -4000 -type f 2>/dev/null \
        > /root/lg/.suid_baseline || true
    log_ok "SUID baseline recorded"

    # ── Optional: enable auto-start on reboot via systemd ─────────────────────
    if [ "$RUN_MODE" = "interactive" ]; then
        echo ""
        read -r -t 15 \
            -p "  Enable auto-analyze on reboot? [y/N] (auto-skip in 15s): " \
            _REBOOT_CHOICE || true
        echo ""
    else
        _REBOOT_CHOICE="n"
    fi

    if [[ "${_REBOOT_CHOICE:-n}" =~ ^[Yy]$ ]]; then
        cat > /etc/systemd/system/lg-analyze.service << 'EOF'
[Unit]
Description=Linux Guardian Auto-Analyze
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c "/usr/local/bin/lg --watch && /usr/local/bin/lg --auto-analyze"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload 2>/dev/null \
            && systemctl enable lg-analyze 2>/dev/null \
            && log_ok "lg-analyze enabled — starts automatically on reboot" \
            || log_warn "Failed to enable systemd service"
    else
        log_info "Auto-start on reboot not enabled"
        log_info "Run 'sudo lg --auto-analyze' after reboot to start manually"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION: _lg_status — Security status dashboard
# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# PART C — php2shell (CVE-2026-109618 / CVE-2026-109619)
# ══════════════════════════════════════════════════════════════════════════════
# Unauthenticated RCE in PHP's request teardown, public 2026-10-21 and exploited
# in the wild. Fixed upstream in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; 8.1 and
# older get no upstream release — only distro backports, which Debian/Ubuntu/
# RHEL ship WITHOUT bumping the version, so the vendor changelog is consulted.
# Layer 5 deliberately skips panel-private PHP (CWP php71, cPanel ea-php*,
# CloudLinux alt-php, Plesk); this part covers every PHP executable found.
# The mitigation closes the confirmed session-upload-progress path only;
# updating PHP is the only complete fix.
PHP2SHELL_FIXED="8.5:8.5.12 8.4:8.4.27 8.3:8.3.36 8.2:8.2.35"
PHP2SHELL_INI="zz-lg-php2shell.ini"

# every PHP executable on the host (resolved, de-duplicated)
_php2shell_bins() {
    local b
    for b in /usr/bin/php /usr/bin/php-cgi /usr/sbin/php-fpm /usr/bin/php[5-8]* /usr/sbin/php-fpm[5-8]* \
             /usr/local/bin/php /usr/local/bin/php-cgi /usr/local/sbin/php-fpm /usr/local/php*/bin/php \
             /usr/local/cwp/php*/bin/php /opt/alt/php*/usr/bin/php /opt/cpanel/ea-php*/root/usr/bin/php \
             /opt/plesk/php/*/bin/php /opt/php*/bin/php /www/server/php/*/bin/php /opt/remi/php*/root/usr/bin/php \
             /usr/local/lsws/lsphp*/bin/php /usr/local/lsws/lsphp*/bin/lsphp; do
        [ -f "$b" ] && [ -x "$b" ] && readlink -f "$b"
    done 2>/dev/null | sort -u
}

# phpinfo as plain text (php-cgi prints HTML when not in a CGI request)
_php2shell_info() { "$1" -i 2>/dev/null | sed 's/<[^>]*>/ /g'; }

# prints "<version>|<state>"; state = fixed | vendor-patched | vulnerable | unknown
_php2shell_state() {
    local bin="$1" ver br fixed pkg
    ver=$("$bin" -n -v 2>/dev/null | sed -n 's/^PHP \([0-9][0-9.]*\).*/\1/p' | head -1)
    [ -n "$ver" ] || { echo "?|unknown"; return 0; }
    if command -v rpm >/dev/null 2>&1 && pkg=$(rpm -qf "$bin" 2>/dev/null) && [[ "$pkg" != *"not owned"* ]]; then
        local _cl; _cl=$(rpm -q --changelog "$pkg" 2>/dev/null || true)
        grep -q "CVE-2026-10961[89]" <<< "$_cl" && { echo "$ver|vendor-patched"; return 0; }
    elif command -v dpkg >/dev/null 2>&1 && pkg=$(dpkg -S "$bin" 2>/dev/null | head -1 | cut -d: -f1) && [ -n "$pkg" ]; then
        zgrep -q "CVE-2026-10961[89]" "/usr/share/doc/${pkg}/changelog.Debian.gz" 2>/dev/null \
            && { echo "$ver|vendor-patched"; return 0; }
    fi
    br="${ver%.*}"
    for fixed in $PHP2SHELL_FIXED; do
        [ "${fixed%%:*}" = "$br" ] || continue
        if [ "$(printf '%s\n%s\n' "${fixed#*:}" "$ver" | sort -V | head -1)" = "${fixed#*:}" ]; then
            echo "$ver|fixed"
        else
            echo "$ver|vulnerable"
        fi
        return 0
    done
    echo "$ver|vulnerable"        # 8.1 and older: no upstream fix exists
}

# the release that fixes this binary's branch, for the advice line
_php2shell_fixed_for() {
    local br="${1%.*}" fixed
    for fixed in $PHP2SHELL_FIXED; do [ "${fixed%%:*}" = "$br" ] && { echo "${fixed#*:}"; return 0; }; done
    echo "a supported branch (8.2.35+) or a vendor-patched package"
}

# where this binary reads extra .ini files ("dir|path"), else its php.ini ("ini|path")
_php2shell_target() {
    local bin="$1" info scan ini
    info=$(_php2shell_info "$bin")
    scan=$(printf '%s\n' "$info" | grep -m1 "Scan this dir for additional .ini files" | sed -E 's/.*\.ini files[ =>]*//; s/[[:space:]]*$//')
    if [ -n "$scan" ] && [ "$scan" != "(none)" ] && [ -d "$scan" ]; then echo "dir|$scan"; return 0; fi
    ini=$(printf '%s\n' "$info" | grep -m1 "Loaded Configuration File" | sed -E 's/.*Configuration File[ =>]*//; s/[[:space:]]*$//')
    if [ -n "$ini" ] && [ "$ini" != "(none)" ] && [ -f "$ini" ]; then echo "ini|$ini"; return 0; fi
    echo "none|"
}

# is the mitigation live for this binary?
_php2shell_mitigated() {
    # capture first, then test: with pipefail an early-closing grep -q makes
    # the whole pipeline report failure even when it matched
    local _line
    _line=$(_php2shell_info "$1" | grep -m1 "session.upload_progress.enabled" || true)
    printf '%s' "$_line" | grep -qiE 'enabled[ =>]*(off|0)'
}

_lg_php2shell() {
    local bins bin ver st kind path vuln=0 fixed=0 applied=0 seen=" " svc
    # standalone (--php2shell) runs before the main initialisation block
    TIMESTAMP="${TIMESTAMP:-$(date +%Y%m%d_%H%M%S)}"
    BACKUP_DIR="${BACKUP_DIR:-/root/lg/backups}"
    UNDO_MANIFEST="${UNDO_MANIFEST:-${BACKUP_DIR}/undo_manifest_${TIMESTAMP}.txt}"
    [ "$DRY_RUN" = true ] || mkdir -p "$BACKUP_DIR" 2>/dev/null || true

    mapfile -t bins < <(_php2shell_bins)
    if [ ${#bins[@]} -eq 0 ]; then log_warn "No PHP executable found — nothing to do"; return 0; fi
    log_info "php2shell (CVE-2026-109618 / CVE-2026-109619) — ${#bins[@]} PHP executable(s):"
    for bin in "${bins[@]}"; do
        IFS='|' read -r ver st <<< "$(_php2shell_state "$bin")"
        case "$st" in
            fixed|vendor-patched) fixed=$((fixed+1)); log_ok "  ${bin}  PHP ${ver}  (${st})" ;;
            *) vuln=$((vuln+1)); log_warn "  ${bin}  PHP ${ver}  VULNERABLE — update to $(_php2shell_fixed_for "$ver")" ;;
        esac
    done
    echo ""
    log_info "Mitigation: session.upload_progress.enabled = 0 — closes the confirmed upload-progress path; updating is the only complete fix"

    if [ "$DRY_RUN" = true ]; then
        for bin in "${bins[@]}"; do
            IFS='|' read -r kind path <<< "$(_php2shell_target "$bin")"
            case "$kind" in
                dir) log_dry "  ${path}/${PHP2SHELL_INI}  (for $bin)" ;;
                ini) log_dry "  ${path}: session.upload_progress.enabled = 0  (for $bin)" ;;
                *)   log_dry "  ${bin}: no scan dir / php.ini — manual" ;;
            esac
        done
        return 0
    fi
    if [ "$RUN_MODE" != "auto" ] && [ -t 0 ]; then
        read -r -p "  Apply the mitigation to all ${#bins[@]} PHP install(s)? [Y/n]: " -n 1; echo ""
        [[ $REPLY =~ ^[Nn]$ ]] && { log_skip "php2shell mitigation skipped"; return 0; }
    fi

    for bin in "${bins[@]}"; do
        IFS='|' read -r kind path <<< "$(_php2shell_target "$bin")"
        case "$kind" in
            dir)
                [[ "$seen" == *" ${path} "* ]] && continue; seen="${seen}${path} "
                if [ -f "${path}/${PHP2SHELL_INI}" ] && grep -q "upload_progress.enabled *= *0" "${path}/${PHP2SHELL_INI}"; then
                    log_info "  already present: ${path}/${PHP2SHELL_INI}"; continue
                fi
                printf '; Linux Guardian — php2shell (CVE-2026-109618 / CVE-2026-109619) mitigation\n; Closes the confirmed session-upload-progress path. Updating PHP is the fix.\nsession.upload_progress.enabled = 0\n' \
                    > "${path}/${PHP2SHELL_INI}"
                chmod 644 "${path}/${PHP2SHELL_INI}"
                echo "RMFILE:${path}/${PHP2SHELL_INI}" >> "$UNDO_MANIFEST"
                applied=$((applied+1)); log_ok "  ${path}/${PHP2SHELL_INI}"
                ;;
            ini)
                [[ "$seen" == *" ${path} "* ]] && continue; seen="${seen}${path} "
                backup_file "$path" "php2shell"
                if grep -qE '^\s*;?\s*session\.upload_progress\.enabled\s*=' "$path"; then
                    sed -i -E 's|^\s*;?\s*session\.upload_progress\.enabled\s*=.*|session.upload_progress.enabled = 0|' "$path"
                else
                    printf '\n; Linux Guardian — php2shell (CVE-2026-109618 / CVE-2026-109619) mitigation\nsession.upload_progress.enabled = 0\n' >> "$path"
                fi
                applied=$((applied+1)); log_ok "  ${path}: session.upload_progress.enabled = 0"
                ;;
            *) log_warn "  ${bin}: no scan dir and no php.ini — set session.upload_progress.enabled = 0 by hand" ;;
        esac
    done

    # the setting is read at process start: restart every FPM (sites and panels);
    # CGI/suPHP picks it up on the next request, mod_php needs the web server
    if [ "$applied" -gt 0 ]; then
        while IFS= read -r svc; do
            [ -n "$svc" ] || continue
            systemctl restart "$svc" 2>/dev/null && log_ok "  restarted: $svc" || log_warn "  restart failed: $svc"
        done < <(systemctl list-units --type=service --state=active --no-legend 2>/dev/null \
                   | awk '{print $1}' | grep -Ei 'php.*fpm|phpfpm|lshttpd|lsws' || true)
        [ "$(detect_php_mode 2>/dev/null || true)" = "mod_php" ] && restart_active_webserver
    fi

    echo ""
    for bin in "${bins[@]}"; do
        _php2shell_mitigated "$bin" && log_ok "  verified off: $bin" || log_warn "  NOT applied (check scan dir / php.ini): $bin"
    done
    log_info "php2shell: ${fixed} fixed, ${vuln} vulnerable, mitigation written to ${applied} target(s)"
    [ "$vuln" -gt 0 ] && log_warn "Vulnerable PHP remains — the mitigation is interim only; update or rebuild those binaries"
    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# PART D — Recent critical CVEs (report only)
# ══════════════════════════════════════════════════════════════════════════════
# Checks the host against the 2026 vulnerabilities that hit hosting servers
# hardest, beyond php2shell (Part C). It only reports and says what to update;
# it never swaps packages or binaries behind your back.
#   Snuffleupagus < 0.13.0            CVE-2026-22034       multipart uploads evaluated as PHP
#   Roundcube < 1.5.15/1.6.16/1.7.1   CVE-2026-35537..45   pre-auth file write, IMAP injection, XSS, SSRF
#   Kernel newest != running          reboot pending       installed fixes are not in effect
#   Pending distro security updates   dnf/yum/apt          e.g. openssl, apr-util, kernel
#   CWP panel behind the channel      centos-webpanel.com  panel RCE/auth fixes ship this way
CVE_ISSUES=0
CVE_LIST=""

# $1 < $2 (dotted versions)
_cve_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }

# _cve_report <ok|warn|info> <text>  — quiet mode (dashboard) only counts and collects
_cve_report() {
    local lvl="$1"; shift
    case "$lvl" in
        warn) CVE_ISSUES=$((CVE_ISSUES+1)); CVE_LIST="${CVE_LIST}      $*\\n"
              [ "${_CVE_QUIET:-0}" = 1 ] || log_warn "  $*" ;;
        ok)   [ "${_CVE_QUIET:-0}" = 1 ] || log_ok   "  $*" ;;
        *)    [ "${_CVE_QUIET:-0}" = 1 ] || log_info "  $*" ;;
    esac
}

_lg_cves() {
    local _q="${1:-}" bin v p ver br need inst latest run newest n names pkg
    [ "$_q" = quiet ] && _CVE_QUIET=1 || _CVE_QUIET=0
    CVE_ISSUES=0; CVE_LIST=""

    # ── Snuffleupagus — CVE-2026-22034 (fixed in 0.13.0) ───────────────────────
    local _sp_seen=0
    while IFS= read -r bin; do
        [ -n "$bin" ] || continue
        "$bin" -r 'exit(0);' >/dev/null 2>&1 || continue            # php-fpm has no -r
        v=$("$bin" -r 'echo phpversion("snuffleupagus") ?: "";' 2>/dev/null)
        [ -n "$v" ] || continue
        _sp_seen=1
        if _cve_lt "$v" "0.13.0"; then
            _cve_report warn "Snuffleupagus ${v} on ${bin} — CVE-2026-22034, rebuild/upgrade to 0.13.0+"
        else
            _cve_report ok "Snuffleupagus ${v} on ${bin} — CVE-2026-22034 fixed"
        fi
    done < <(_php2shell_bins)
    [ "$_sp_seen" = 1 ] || _cve_report info "Snuffleupagus not loaded in any PHP — CVE-2026-22034 not applicable"

    # ── Roundcube — CVE-2026-35537..35545 ───────────────────────────────────────
    local _rc_seen=0
    for p in /usr/local/cwpsrv/var/services/roundcube /usr/share/roundcube /usr/share/roundcubemail \
             /var/www/roundcube /var/www/html/roundcube /var/lib/roundcube /usr/local/cpanel/base/3rdparty/roundcube \
             /usr/share/psa-roundcube /www/server/roundcube /opt/roundcube /var/www/roundcubemail; do
        [ -f "$p/program/include/iniset.php" ] || continue
        _rc_seen=1
        ver=$(grep -m1 -oE "RCMAIL_VERSION'?,?\s*'[0-9][0-9.]*" "$p/program/include/iniset.php" | grep -oE '[0-9][0-9.]*$')
        br="${ver%.*}"
        case "$br" in
            1.5) need=1.5.15 ;; 1.6) need=1.6.16 ;; 1.7) need=1.7.1 ;; *) need=1.6.16 ;;
        esac
        if [ -z "$ver" ] || _cve_lt "$ver" "$need"; then
            _cve_report warn "Roundcube ${ver:-?} at ${p} — CVE-2026-35537..35545, update to ${need}+"
        else
            _cve_report ok "Roundcube ${ver} at ${p} — fixed (${need}+)$([ "$br" = 1.5 ] && echo '; 1.5 branch is end-of-life, plan the move to 1.6')"
        fi
    done
    [ "$_rc_seen" = 1 ] || _cve_report info "Roundcube not found — CVE-2026-3553x not applicable"

    # ── Kernel: newest installed vs running ─────────────────────────────────────
    run=$(uname -r); newest=""
    if command -v rpm >/dev/null 2>&1; then
        newest=$(rpm -q kernel --last 2>/dev/null | head -1 | awk '{print $1}' | sed 's/^kernel-//')
    fi
    [ -n "$newest" ] || newest=$(ls /boot/vmlinuz-* 2>/dev/null | sed 's|.*/vmlinuz-||' | grep -v rescue | sort -V | tail -1)
    if [ -f /var/run/reboot-required ] || { [ -n "$newest" ] && [ "$newest" != "$run" ]; }; then
        _cve_report warn "Kernel ${newest:-?} installed but ${run} running — reboot to activate the fixes"
    else
        _cve_report ok "Kernel ${run} — newest installed is running"
    fi

    # ── Pending distro security updates ─────────────────────────────────────────
    n=0; names=""
    if command -v dnf >/dev/null 2>&1; then
        names=$(dnf -q updateinfo list --security 2>/dev/null | awk '/\/Sec\.|Security/ {print $NF}' | sed -E 's/-[0-9][^ ]*$//' | sort -u | head -8 | tr '\n' ' ')
    elif command -v yum >/dev/null 2>&1; then
        names=$(yum -q updateinfo list security 2>/dev/null | awk '/\/Sec\.|Security/ {print $NF}' | sed -E 's/-[0-9][^ ]*$//' | sort -u | head -8 | tr '\n' ' ')
    elif command -v apt-get >/dev/null 2>&1; then
        names=$(apt-get -s upgrade 2>/dev/null | awk '/^Inst / && /-security/ {print $2}' | sort -u | head -8 | tr '\n' ' ')
    fi
    n=$(printf '%s' "$names" | wc -w)
    if [ "$n" -gt 0 ]; then
        _cve_report warn "${n} pending security update(s): ${names}— apply them"
    else
        _cve_report ok "No pending distro security updates"
    fi

    # ── CWP panel version vs the live channel ───────────────────────────────────
    if [ -f /usr/local/cwpsrv/htdocs/resources/admin/include/version.php ]; then
        inst=$(grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*' /usr/local/cwpsrv/htdocs/resources/admin/include/version.php | head -1)
        latest=$(curl -s --max-time 6 http://centos-webpanel.com/webpanel/versions/el7.txt 2>/dev/null | tr -d '\r' | tail -1 | awk '{print $1}')
        case "$latest" in
            ''|*[!0-9.]*) _cve_report info "CWP ${inst:-?} — version channel unreachable, could not compare" ;;
            *) if [ -n "$inst" ] && _cve_lt "$inst" "$latest"; then
                   _cve_report warn "CWP ${inst} installed, ${latest} available — panel updates carry security fixes"
               else
                   _cve_report ok "CWP ${inst} — up to date (channel: ${latest})"
               fi ;;
        esac
    fi

    if [ "$_CVE_QUIET" = 0 ]; then
        echo ""
        if [ "$CVE_ISSUES" -eq 0 ]; then log_ok "Recent CVEs: nothing outstanding"
        else log_warn "Recent CVEs: ${CVE_ISSUES} item(s) need attention (see above)"; fi
    fi
    return 0
}

_lg_status() {
    local _lg_status_old_flags="$-"
    set +euo pipefail
    local LAST_RUN="unknown"
    [ -f "$LG_STATE_FILE" ] && LAST_RUN=$(cat "$LG_STATE_FILE" 2>/dev/null || echo "unknown")

    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "────────────────────────────────────────────────────────────────────────"
    echo "   Linux Guardian v1.3 — Security Status Dashboard"
    printf "   Last applied: %s\n" "$LAST_RUN"
    echo "────────────────────────────────────────────────────────────────────────"
    echo -e "${NC}"

    # Helper: check result
    _st() { [ "$1" = "0" ] \
        && echo -e "  ${GREEN}✓${NC} $2" \
        || echo -e "  ${RED}✗${NC} $2"; }

    # [1] Binary Lockdown
    _BIN=1
    for _b in /usr/bin/socat /usr/bin/nc /usr/bin/ncat /usr/bin/gcc /usr/bin/perl /usr/bin/wget; do
        [ -e "$_b" ] && [ "$(stat -c %a "$_b" 2>/dev/null)" = "750" ] && { _BIN=0; break; }
    done
    _st "$_BIN" "[1] Binary Lockdown       — $([ $_BIN -eq 0 ] && echo 'active' || echo 'not applied')"

    # [2] Kernel Hardening
    [ -f /etc/sysctl.d/99-lg-hardening.conf ] && _KERN=0 || _KERN=1
    _st "$_KERN" "[2] Kernel Hardening      — $([ $_KERN -eq 0 ] && echo 'active' || echo 'not applied')"

    # [3] System Files
    local _shperm
    _shperm=$(stat -c '%a' /etc/shadow 2>/dev/null || echo "0")
    [ "$_shperm" = "600" ] && _SYS=0 || _SYS=1
    _st "$_SYS" "[3] System Files          — $([ $_SYS -eq 0 ] && echo 'hardened' || echo 'not hardened')"

    # [4.1] Apache
    local _httpd_ok=0 _httpd_total=0
    while IFS= read -r _f; do
        [ -f "$_f" ] || continue
        _httpd_total=$((_httpd_total+1))
        grep -q "ServerTokens Prod" "$_f" 2>/dev/null \
            && _httpd_ok=$((_httpd_ok+1))
    done < <(find /etc/httpd /etc/apache2 \
                  /usr/local/apache2 /usr/local/apache \
                  -maxdepth 3 \
                  \( -name "httpd.conf" -o -name "apache2.conf" \) \
                  ! -path "*/original/*" \
                  ! -path "*/backup*/*" \
                  ! -path "*/bak*/*" \
                  2>/dev/null | sort -u)

    if [ "$_httpd_total" -gt 0 ]; then
        [ "$_httpd_ok" -eq "$_httpd_total" ] \
            && echo -e "  ${GREEN}✓${NC} [4.1] Apache httpd.conf   — hardened"\
            || echo -e "  ${RED}✗${NC} [4.1] Apache httpd.conf   — not hardened"
    else
        echo -e "  ${CYAN}—${NC} [4.1] Apache httpd.conf   — not found"
    fi

    # [4.2] MySQL
    if command -v mysql &>/dev/null || command -v mysqld &>/dev/null; then
        local _bind
        _bind=$(grep "bind-address" /etc/my.cnf /etc/mysql/my.cnf 2>/dev/null | grep "127.0.0.1" || true)
        [ -n "$_bind" ] && _DB=0 || _DB=1
        _st "$_DB" "[4.2] MySQL/MariaDB       — $([ $_DB -eq 0 ] && echo 'bound to 127.0.0.1' || echo 'check bind-address')"
    else
        echo -e "  ${CYAN}—${NC} [4.2] MySQL/MariaDB       — not installed"
    fi

    # [5] PHP
    local _dfuncs
    _dfuncs=$(php -r 'echo ini_get("disable_functions");' 2>/dev/null \
        | tr ',' '\n' \
        | sed '/^\s*$/d' \
        | wc -l)
    [ "$_dfuncs" -gt 5 ] && _PHP=0 || _PHP=1
    _st "$_PHP" "[5] PHP disable_functions — $( [ $_PHP -eq 0 ] && echo "active (${_dfuncs} functions)" || echo 'not applied')"

    # [5.1] PHP-FPM (hosted sites)
    echo ""
    _PHP_MODE=$(detect_php_mode)
    _POOL_DIR=$(find_pool_dir)
    _POOL_COUNT=0
    [ -n "$_POOL_DIR" ] && \
        _POOL_COUNT=$(find "$_POOL_DIR" -name "*.conf" \
            ! -name "www.conf" 2>/dev/null | wc -l || echo 0)

    if [ "$_PHP_MODE" = "fpm" ]; then
        _FPMSERVICE=$(systemctl list-units --type=service \
            --state=active --no-legend 2>/dev/null \
            | awk '{print $1}' \
            | grep -E "^php.*fpm" \
            | sed 's/\.service//' \
            | head -1 || true)
        echo -e "  ${GREEN}✓${NC} [5.1] PHP-FPM (sites)    — running (${_FPMSERVICE:-php-fpm}) | ${_POOL_COUNT} pool(s)"
    elif [ "$_PHP_MODE" = "cgi" ]; then
        echo -e "  ${GREEN}✓${NC} [5.1] PHP mode            — CGI | ${_POOL_COUNT} pool(s)"
    else
        echo -e "  ${GREEN}✓${NC} [5.1] PHP mode            — mod_php | ${_POOL_COUNT} pool(s)"
    fi

    # [5.2] Panel
    local _PANEL_INFO _PANEL_NAME _PANEL_SVC _panel_php_status
        _PANEL_INFO=$(detect_panel)
        _PANEL_NAME="${_PANEL_INFO%%:*}"
        _PANEL_SVC="${_PANEL_INFO##*:}"

    if [ "$_PANEL_NAME" != "none" ]; then
        svc_running "$_PANEL_SVC" \
            && _panel_php_status="running" \
            || _panel_php_status="stopped"
        [ "$_panel_php_status" = "running" ] \
            && echo -e "  ${GREEN}✓${NC} [5.2] Panel               — (${_PANEL_NAME}) ${_panel_php_status}" \
            || echo -e "  ${RED}✗${NC} [5.2] Panel               — (${_PANEL_NAME}) ${_panel_php_status}"
    fi

    # [6] noexec
    mount 2>/dev/null | grep -q "on /tmp.*noexec" && _NX=0 || _NX=1
    _st "$_NX" "[6] noexec /tmp           — $([ $_NX -eq 0 ] && echo 'active' || echo 'not mounted')"

    # [7] SELinux/AppArmor
    local _mac_status="none"
    if command -v sestatus &>/dev/null; then
        _mac_status=$(sestatus 2>/dev/null | awk '/Current mode/{print $3}' || echo "unknown")
        [ "$_mac_status" = "enforcing" ] && _MAC=0 || _MAC=1
        _st "$_MAC" "[7] SELinux               — ${_mac_status}"
    elif command -v apparmor_status &>/dev/null; then
        _mac_status="active"
        echo -e "  ${GREEN}✓${NC} [7] AppArmor              — active"
    else
        echo -e "  ${RED}✗${NC} [7] MAC                   — not active"
    fi

    # [8] Auditd
    svc_running auditd && _AUD=0 || _AUD=1
    local _rules
    _rules=$(auditctl -l 2>/dev/null | wc -l || echo 0)
    _st "$_AUD" "[8] Auditd                — $([ $_AUD -eq 0 ] && echo "active (${_rules} rules)" || echo 'not running')"

    # [A] ClamAV
    if svc_installed clamscan clamdscan; then
        echo -e "  ${GREEN}✓${NC} [A] FTP + ClamAV          — installed"
    else
        echo -e "  ${CYAN}—${NC} [A] FTP + ClamAV          — not installed"
    fi

    # [B] Snuffleupagus
    if php -m 2>/dev/null | grep -qi snuffleupagus; then
        echo -e "  ${GREEN}✓${NC} [B] Snuffleupagus         — active"
    else
        echo -e "  ${CYAN}—${NC} [B] Snuffleupagus         — not installed"
    fi

    # [C] php2shell — every PHP executable, panels included
    local _c_total=0 _c_bad=0 _c_mit=0 _c_list="" _cb _cv _cs
    while IFS= read -r _cb; do
        [ -n "$_cb" ] || continue
        _c_total=$((_c_total+1))
        IFS='|' read -r _cv _cs <<< "$(_php2shell_state "$_cb")"
        case "$_cs" in
            fixed|vendor-patched) ;;
            *) _c_bad=$((_c_bad+1)); _c_list="${_c_list}      ${_cb}  PHP ${_cv}\n" ;;
        esac
        _php2shell_mitigated "$_cb" && _c_mit=$((_c_mit+1))
    done < <(_php2shell_bins)
    if [ "$_c_total" -eq 0 ]; then
        echo -e "  ${CYAN}—${NC} [C] php2shell             — no PHP found"
    elif [ "$_c_bad" -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} [C] php2shell             — all ${_c_total} PHP fixed · mitigation on ${_c_mit}/${_c_total}"
    elif [ "$_c_mit" -eq "$_c_total" ]; then
        echo -e "  ${YELLOW}!${NC} [C] php2shell             — ${_c_bad} of ${_c_total} PHP VULNERABLE (mitigated — update them)"
        printf "%b" "$_c_list"
    else
        echo -e "  ${RED}✗${NC} [C] php2shell             — ${_c_bad} of ${_c_total} PHP VULNERABLE, mitigation on ${_c_mit}/${_c_total} — run: lg --php2shell"
        printf "%b" "$_c_list"
    fi

    # [D] Recent CVEs (report only)
    _lg_cves quiet
    if [ "$CVE_ISSUES" -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} [D] Recent CVEs           — nothing outstanding"
    else
        echo -e "  ${RED}✗${NC} [D] Recent CVEs           — ${CVE_ISSUES} item(s) need attention — run: lg --cves"
        printf "%b" "$CVE_LIST"
    fi

    # Dovecot status
    echo ""
    if svc_running dovecot; then
        echo -e "  ${GREEN}✓${NC} Dovecot                  — running"
        # vmail context
        local _vmail_dir="" _vmail_ctx=""
        # FIX: was inlined 3-line loop, now uses shared helper
        _vmail_dir=$(detect_vmail_dir 2>/dev/null) || _vmail_dir=""
        if [ -n "$_vmail_dir" ]; then
            _vmail_ctx=$(stat -c '%C' "$_vmail_dir" 2>/dev/null \
                | grep -oE '[a-z_]+_t' \
                | head -1)
            if echo "$_vmail_ctx" | grep -qE "mail_spool_t|dovecot_var_t"; then
                echo -e "  ${GREEN}✓${NC} vmail context            — ${_vmail_ctx}"
            else
                echo -e "  ${RED}✗${NC} vmail context            — ${_vmail_ctx} (run: sudo lg --fixmail)"
            fi
        fi
        # dovecot_lg policy
        semodule -l 2>/dev/null | grep -q "dovecot_lg" \
            && echo -e "  ${GREEN}✓${NC} dovecot_lg policy        — loaded" \
            || echo -e "  ${YELLOW}!${NC} dovecot_lg policy        — not loaded (run: sudo lg --fixmail)"
    else
        echo -e "  ${CYAN}—${NC} Dovecot                  — not running"
    fi

    # Auto-analyze status
    echo ""
    local _pid_file="/var/run/lg-analyze.pid"
    if [ -f "$_pid_file" ] && kill -0 "$(cat "$_pid_file")" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Auto-analyze             — running (PID: $(cat "$_pid_file"))"
    else
        echo -e "  ${CYAN}—${NC} Auto-analyze             — stopped (start: sudo lg --auto-analyze)"
    fi

    echo ""
    echo "────────────────────────────────────────────────────────────────────────"

    # ── Inline scan + analyze + integrity ─────────────────────────────────────
    echo ""
    if [ -t 0 ]; then
        read -r -t 15 -p "  Run scan + analyze + integrity? [Y/n] (auto in 15s): " _RUN_CHECKS || true
        echo ""
    else
        _RUN_CHECKS="y"
    fi
    if [[ "${_RUN_CHECKS:-y}" =~ ^[Yy]?$ ]]; then
        _lg_scan
        echo ""
        _lg_analyze
        echo ""
        _lg_integrity
    else
        echo -e "  ${CYAN}Tips:${NC}"
        echo -e "   sudo lg --scan        # scan for webshells"
        echo -e "   sudo lg --analyze     # analyze system behavior"
        echo -e "   sudo lg --integrity   # check file integrity"
    fi

    echo ""
    echo "────────────────────────────────────────────────────────────────────────"
    echo -e "  ${CYAN}Run 'sudo lg --force'     to re-apply all layers${NC}"
    echo -e "  ${CYAN}Run 'sudo lg --fixmail'   to fix Dovecot/vmail${NC}"
    echo -e "  ${CYAN}Run 'sudo lg --undo'      to rollback${NC}"
    echo "────────────────────────────────────────────────────────────────────────"
    echo ""
    # Restore original shell flags
    set -euo pipefail
}
# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION: watch_mode Monitors new sites and isolates them automatically
# ══════════════════════════════════════════════════════════════════════════════
watch_mode() {
    local LOG_FILE="${LOG_FILE:-/var/log/lg-hardening.log}"
    section "WATCH MODE — Sync open_basedir with hosted sites"

    _W_PHP_MODE=$(detect_php_mode)

    # ── Collect current site paths (FIX: was inlined loops, now uses helper) ──
    _CURRENT_SITES=()
    while IFS= read -r _site_path; do
        _CURRENT_SITES+=("$_site_path")
    done < <(detect_site_paths)

    log_info "Sites found: ${#_CURRENT_SITES[@]}"
    for _s in ${_CURRENT_SITES[@]+"${_CURRENT_SITES[@]}"}; do
        log_info "  → ${_s}"
    done
    echo ""

    # ── Apply noexec/nosuid/nodev to /tmp, /var/tmp, and all site dirs ────────
    for _noexec_dir in /tmp /var/tmp ${_CURRENT_SITES[@]+"${_CURRENT_SITES[@]}"}; do
        [ -d "$_noexec_dir" ] || continue
        if mount 2>/dev/null | grep -qE " on ${_noexec_dir} .*noexec"; then
            log_skip "noexec already active: ${_noexec_dir}"
        else
            if mount --bind "$_noexec_dir" "$_noexec_dir" 2>/dev/null && \
               mount -o remount,noexec,nosuid,nodev,bind \
                   "$_noexec_dir" 2>/dev/null; then
                log_ok "noexec/nosuid/nodev applied: ${_noexec_dir}"
                echo "$(date '+%Y-%m-%d %H:%M:%S') [WATCH] noexec: ${_noexec_dir}" \
                    >> "$LOG_FILE"
            else
                log_warn "noexec failed: ${_noexec_dir}"
            fi
        fi
    done

    echo ""

    # ── Sync open_basedir (CGI/mod_php only) ──────────────────────────────────
    if [[ "$_W_PHP_MODE" != "cgi" && "$_W_PHP_MODE" != "mod_php" ]]; then
        log_info "PHP mode: ${_W_PHP_MODE} — open_basedir handled via PHP-FPM pools"
        return 0
    fi

    # ── Find php.ini files ────────────────────────────────────────────────────
    _PANEL_INFO=$(detect_panel)
    _PANEL_NAME="${_PANEL_INFO%%:*}"
    _W_TMPF=$(mktemp)
    { find / -maxdepth 7 -type f -name "php.ini" 2>/dev/null || true; } \
        | { grep -v "/cli/" || true; } | sort -u > "$_W_TMPF"

    _UPDATED=0
    while IFS= read -r inifile; do
        [ -f "$inifile" ] || continue
        # Skip panel php.ini
        case "$_PANEL_NAME" in
            CWP)        [[ "$inifile" == /usr/local/cwp/* ]]    && continue ;;
            cPanel)     [[ "$inifile" == /usr/local/cpanel/* ]] && continue ;;
            Plesk)      [[ "$inifile" == /opt/plesk/* ]]        && continue ;;
            DirectAdmin)[[ "$inifile" == /usr/local/php/* ]]    && continue ;;
            CyberPanel) [[ "$inifile" == /usr/local/lsws/* ]]   && continue ;;
            aaPanel)    [[ "$inifile" == /www/server/php/* ]]   && continue ;;
        esac

        # ── Read current open_basedir ─────────────────────────────────────────
        _CURRENT_OBD=""
        grep -qE "^\s*open_basedir\s*=" "$inifile" && \
            _CURRENT_OBD=$(grep -E "^\s*open_basedir\s*=" \
                "$inifile" | head -1 | sed 's/.*=\s*//' | tr -d ' ')

        # ── Build new open_basedir ────────────────────────────────────────────
        _NEW_OBD="/tmp:/usr/share/php:/usr/share/pear"
        for _site in ${_CURRENT_SITES[@]+"${_CURRENT_SITES[@]}"}; do
            [ -d "$_site" ] && _NEW_OBD="${_NEW_OBD}:${_site}"
        done

        # ── Compare and update ────────────────────────────────────────────────
        if [ "$_CURRENT_OBD" != "$_NEW_OBD" ]; then
            TS=$(date '+%Y-%m-%d %H:%M:%S')
            [ "$(tail -c1 "$inifile" | wc -l)" -eq 0 ] && echo "" >> "$inifile"
            if grep -qE "^\s*open_basedir\s*=" "$inifile"; then
                sed -i \
                    "s|^\s*open_basedir\s*=.*|open_basedir = ${_NEW_OBD}|" \
                    "$inifile"
            else
                echo "open_basedir = ${_NEW_OBD}" >> "$inifile"
            fi
            log_ok "open_basedir synced: $(basename "$inifile")"
            echo "${TS} [WATCH] open_basedir synced: ${inifile}" >> "$LOG_FILE"
            _UPDATED=$((_UPDATED+1))
        else
            log_skip "open_basedir already in sync: $(basename "$inifile")"
        fi
    done < "$_W_TMPF"
    rm -f "$_W_TMPF"

    # ── Restart web server if updated (FIX: was inlined 12-line loop) ────────
    if [ "$_UPDATED" -gt 0 ]; then
        restart_active_webserver || log_warn "No active web server to restart"
        log_ok "Watch complete — ${_UPDATED} file(s) updated"
    else
        log_ok "Watch complete — open_basedir already in sync"
    fi
}
# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION: _lg_update — Download and install latest version
# ══════════════════════════════════════════════════════════════════════════════
_lg_update() {
    local UPDATE_URL="https://lg.wondtech.com/lg.sh"
    local INSTALL_PATH
    INSTALL_PATH=$(readlink -f "$0" 2>/dev/null || echo "/usr/local/bin/lg")
    local TMP_FILE
    TMP_FILE=$(mktemp /tmp/lg_update_XXXXXX.sh)

    section "UPDATE: Linux Guardian"
    log_info "Current: ${INSTALL_PATH}"
    log_info "Source:  ${UPDATE_URL}"
    echo ""

    # Download
    if command -v curl &>/dev/null; then
        curl -fsSL --max-time 60 --retry 2 "$UPDATE_URL" -o "$TMP_FILE" 2>/dev/null \
            || { log_error "Download failed — check: ${UPDATE_URL}"; rm -f "$TMP_FILE"; exit 1; }
    elif command -v wget &>/dev/null; then
        wget -q --timeout=60 --tries=2 "$UPDATE_URL" -O "$TMP_FILE" 2>/dev/null \
            || { log_error "Download failed — check: ${UPDATE_URL}"; rm -f "$TMP_FILE"; exit 1; }
    else
        log_error "curl or wget required for update"
        rm -f "$TMP_FILE"
        exit 1
    fi

    # Verify downloaded file is valid bash
    if ! bash -n "$TMP_FILE" 2>/dev/null; then
        log_error "Downloaded file has syntax errors — aborting update"
        rm -f "$TMP_FILE"
        exit 1
    fi

    # Extract version from downloaded file
    local NEW_VER
    NEW_VER=$(grep -m1 "^# Linux Guardian v" "$TMP_FILE" 2>/dev/null \
        | grep -oE 'v[0-9]+(\.[0-9]+)+' | head -1 || echo "unknown")

    # Extract current version
    local CUR_VER
    CUR_VER=$(grep -m1 "^# Linux Guardian v" "$INSTALL_PATH" 2>/dev/null \
        | grep -oE 'v[0-9]+(\.[0-9]+)+' | head -1 || echo "unknown")

    log_info "Current version: ${CUR_VER}"
    log_info "New version:     ${NEW_VER}"
    echo ""
    if [ "$NEW_VER" = "unknown" ]; then
        log_error "Downloaded file is not a Linux Guardian release (no version header) — aborting update"
        rm -f "$TMP_FILE"
        exit 1
    fi

    if [ "$NEW_VER" = "$CUR_VER" ] && [ "$NEW_VER" != "unknown" ]; then
        log_ok "Already up to date (${CUR_VER})"
        rm -f "$TMP_FILE"
        exit 0
    fi
    # never replace a newer local build with an older download (mirror lag,
    # a rolled-back release): install only when the download sorts higher
    if [ "$NEW_VER" != "unknown" ] && [ "$CUR_VER" != "unknown" ] && \
       [ "$(printf '%s\n%s\n' "${NEW_VER#v}" "${CUR_VER#v}" | sort -V | tail -1)" = "${CUR_VER#v}" ]; then
        log_warn "Downloaded ${NEW_VER} is older than installed ${CUR_VER} — not installing"
        rm -f "$TMP_FILE"
        exit 0
    fi

    # Backup current version
    local BACKUP="${INSTALL_PATH}.backup.${CUR_VER}"
    cp "$INSTALL_PATH" "$BACKUP" 2>/dev/null \
        && log_ok "Backup saved: ${BACKUP}" \
        || log_warn "Could not backup current version"

    # Install new version
    chmod +x "$TMP_FILE"
    mv "$TMP_FILE" "$INSTALL_PATH" \
        && chmod +x "$INSTALL_PATH" \
        && log_ok "Updated: ${INSTALL_PATH} (${CUR_VER} → ${NEW_VER})" \
        || { log_error "Failed to install update"; rm -f "$TMP_FILE"; exit 1; }

    echo ""
    log_ok "Update complete — run 'sudo lg' to continue"
}

# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION: _lg_help — For help
# ══════════════════════════════════════════════════════════════════════════════
_lg_help() {
    echo -e "${BOLD}USAGE:${NC}"
    echo "   sudo lg [OPTIONS]"
    echo ""
    echo -e "${BOLD}OPTIONS:${NC}"
    echo "   (none)           Interactive mode — recommended for first run"
    echo "   --auto           Auto mode — no prompts, applies all layers"
    echo "   --force          Force re-apply all layers (even if already applied)"
    echo "   --dry-run        Preview every change without applying anything"
    echo "   --undo           Rollback all changes from the last run"
    echo "   --reboot         Reboot at end to apply SELinux relabel (off by default)"
    echo "   --watch          Monitor for new sites and harden automatically"
    echo "   --fixmail        Fix Dovecot/vmail SELinux contexts and policy"
    echo "   --scan [--path]  Scan for PHP/Perl/Python webshells and reverse shells"
    echo "   --auto-analyze   Start background behavior monitoring (daemon)"
    echo "   --integrity      Check integrity of critical system files"
    echo "   --update         Download and install latest version from wondtech.com"
    echo "   --help, -h       Show this help message"
    echo ""
    echo -e "${BOLD}SECURITY LAYERS:${NC}"
    echo "   [1] Binary Lockdown       Restrict dangerous tools to root only"
    echo "   [2] Kernel Hardening      Block unused modules + sysctl hardening"
    echo "   [3] System Files          Secure permissions on sensitive files"
    echo "   [4.1] Apache httpd        ServerTokens Prod, ServerSignature Off"
    echo "   [4.2] MySQL / MariaDB     Bind database to 127.0.0.1"
    echo "   [5] PHP Hardening         Disable 50+ dangerous functions globally (--php-strict: limits, Phar, Strict cookies)"
    echo "   [5.1] PHP-FPM Pools       Isolate each site with open_basedir"
    echo "   [6] noexec                Prevent binary execution from /tmp + sites"
    echo "   [7] AppArmor / SELinux    Enforce MAC + fix vmail/Dovecot contexts"
    echo "   [8] Auditd                Real-time alerts for webshells + privesc"
    echo "   [A] FTP + ClamAV          Scan uploaded files for malware"
    echo "   [B] Snuffleupagus         PHP RASP runtime protection"
    echo "   [C] php2shell             CVE-2026-109618/109619 — every PHP checked, mitigation applied"
    echo "   [D] Recent CVEs           Snuffleupagus, Roundcube, kernel reboot, security updates, CWP version"
    echo ""
    echo -e "${BOLD}EXAMPLES:${NC}"
    echo "   sudo lg                  # First run — interactive"
    echo "   sudo lg --dry-run        # Preview changes safely"
    echo "   sudo lg --php2shell      # php2shell status of every PHP + mitigation only"
    echo "   sudo lg --cves           # recent critical CVE check only (report, no changes)"
    echo "   sudo lg --auto --php-strict      # single-app box: also apply size/time limits + Strict cookies"
    echo "   sudo lg --auto --upgrade-packages # also run the distro package upgrade first"
    echo "   sudo lg --auto           # Apply all layers without prompts"
    echo "   sudo lg --force          # Re-apply all layers"
    echo "   sudo lg --fixmail        # Fix Dovecot/vmail SELinux only"
    echo "   sudo lg --scan           # Scan for webshells"
    echo "   sudo lg --scan --path /var/www/html"
    echo "   sudo lg --auto-analyze   # Start background monitoring"
    echo "   sudo lg --integrity      # Check file integrity"
    echo "   sudo lg --undo           # Rollback last run"
    echo ""
    echo -e "${BOLD}FILES:${NC}"
    echo "   Log:       /var/log/lg-hardening.log"
    echo "   Scan:      /var/log/lg-scan.log"
    echo "   Analyze:   /var/log/lg-analyze.log"
    echo "   Integrity: /root/lg/integrity.db"
    echo "   Backups:   /root/lg/backups/"
    echo ""
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# INITIALISATION
# ══════════════════════════════════════════════════════════════════════════════

# Root check
if [ "$(id -u)" -ne 0 ]; then
    log_error "Must be run as root.  Run: sudo $0"
    exit 1
fi

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --auto)           RUN_MODE="auto" ;;
        --dry-run)        DRY_RUN=true ;;
        --undo)           UNDO_MODE=true ;;
        --watch)          WATCH_MODE=true ;;
        --force)          FORCE_MODE=true ;;
        --reboot)         REBOOT_MODE=true ;;
        --fixmail)        FIXMAIL_MODE=true ;;
        --scan)           SCAN_MODE=true ;;
        --php2shell)      PHP2SHELL_MODE=true ;;
        --cves)           CVES_MODE=true ;;
        --auto-analyze)   AUTO_ANALYZE_MODE=true ;;
        --integrity)      INTEGRITY_MODE=true ;;
        --update)         UPDATE_MODE=true ;;
        --analyze)        ANALYZE_MODE=true ;;
        --php-strict)     PHP_STRICT=true ;;
        --version|-V)     grep -m1 "^# Linux Guardian v" "$0" | grep -oE 'v[0-9]+(\.[0-9]+)+'; exit 0 ;;
        --help|-h)        HELP_MODE=true ;;
        --cron|--setup-auto|--upgrade-packages|--path|--path=*) ;;   # handled elsewhere / positional
        --*)              echo "Unknown option: $arg  (see: lg --help)" >&2; exit 2 ;;
        *)                ;;                           # positional (scan path)
    esac
done

# ── Flags that run silently without banner ────────────────────────────────────
if [ "$HELP_MODE" = true ];         then print_banner; _lg_help; exit 0; fi
if [ "$UPDATE_MODE" = true ];       then _lg_update;       exit 0; fi
if [ "$FIXMAIL_MODE" = true ];      then _lg_fixmail;      exit 0; fi
if [ "$PHP2SHELL_MODE" = true ];    then print_banner; _lg_php2shell; exit 0; fi
if [ "$CVES_MODE" = true ];         then print_banner; _lg_cves;      exit 0; fi
if [ "$ANALYZE_MODE" = true ];      then print_banner; _lg_analyze;   exit 0; fi
if [ "$AUTO_ANALYZE_MODE" = true ]; then _lg_auto_analyze; exit 0; fi
if [ "$INTEGRITY_MODE" = true ];    then _lg_integrity;    exit 0; fi
if [ "$SCAN_MODE" = true ]; then
    _SCAN_PATH=""
    for _a in "$@"; do
        [[ "$_a" == --path=* ]] && _SCAN_PATH="${_a#--path=}" && break
        [[ "$_a" != --* ]] && [[ -n "$_a" ]] && _SCAN_PATH="$_a"
    done
    _lg_scan "$_SCAN_PATH"
    exit 0
fi

# ── Show banner for interactive/full modes ────────────────────────────────────
print_banner

# ── Second-run detection ──────────────────────────────────────────────────────
# watch new sites and harden automatically
if [ "$WATCH_MODE" = true ]; then
    watch_mode
    exit 0
fi
# If already applied AND not --force, show status dashboard
if [ -f "$LG_STATE_FILE" ] && \
   [ "$FORCE_MODE" = false ] && \
   [ "$DRY_RUN" = false ] && \
   [ "$UNDO_MODE" = false ]; then

    PHP_TIMEZONE=$(_detect_timezone)
    _lg_status
    exit 0
fi

# Globals
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/lg/backups"
LOG_FILE="/var/log/lg-hardening.log"
UNDO_MANIFEST="${BACKUP_DIR}/undo_manifest_${TIMESTAMP}.txt"
MAC_SYSTEM="none"
PHP_SKIP=false
PHPFPM_SKIP=false
PHP_INI_FILES=()
SELECTED_FILES=()
ALERT_EMAIL="root"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Redirect output
if [ "$DRY_RUN" = false ]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

PHP_TIMEZONE=$(_detect_timezone)

if [[ "$RUN_MODE" == "interactive" ]] && [ "$DRY_RUN" = false ] && [ "$UNDO_MODE" = false ]; then
    echo ""
    if [ -t 0 ]; then
        read -r -p "  Alert email for security notifications (default: root): " _INPUT_EMAIL || _INPUT_EMAIL=""
    else
        _INPUT_EMAIL=""
    fi
    [ -n "$_INPUT_EMAIL" ] && ALERT_EMAIL="$_INPUT_EMAIL"
    echo -e "  ${GREEN}[OK]${NC}      Alert email: ${ALERT_EMAIL}"
    echo ""
    echo -e "  ${CYAN}[INFO]${NC}    PHP date.timezone — detected: ${BOLD}${PHP_TIMEZONE}${NC}"
    echo -e "  ${CYAN}[INFO]${NC}    Examples: Asia/Riyadh  Asia/Dubai  UTC  America/New_York"
    echo ""
    if [ "$RUN_MODE" = "auto" ] || [ "$DRY_RUN" = true ] || [ ! -t 0 ]; then _INPUT_TZ=""; else
        read -r -p "  Enter timezone (press Enter to keep [${PHP_TIMEZONE}]): " _INPUT_TZ
    fi
    if [ -n "$_INPUT_TZ" ]; then
        if [ -f "/usr/share/zoneinfo/${_INPUT_TZ}" ]; then
            PHP_TIMEZONE="$_INPUT_TZ"
            echo -e "  ${GREEN}[OK]${NC}      Timezone set to: ${PHP_TIMEZONE}"
        else
            echo -e "  ${YELLOW}[WARN]${NC}    Not found in zoneinfo — keeping: ${PHP_TIMEZONE}"
        fi
    else
        echo -e "  ${GREEN}[OK]${NC}      Timezone kept as: ${PHP_TIMEZONE}"
    fi
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

    # Replay newest change first: a file backed up twice in one run (Layer 5,
    # then Part B) must end up as its Layer-5 copy — the original.
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        T="${line%%:*}"
        REST="${line#*:}"
        if [ "$DRY_RUN" = true ]; then log_dry "undo ${T}: ${REST}"; continue; fi
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
                MNT="${REST%%:*}"; HOW="${REST#*:}"; [ "$HOW" = "$REST" ] && HOW=remount
                case "$HOW" in
                    bind|tmpfs) umount "$MNT" 2>/dev/null && log_ok "Unmounted noexec layer: $MNT" \
                                    || log_warn "Could not unmount: $MNT (busy?)" ;;
                    *)          mount -o remount,exec,suid,dev "$MNT" 2>/dev/null && log_ok "Re-enabled exec: $MNT" \
                                    || log_warn "Could not remount: $MNT" ;;
                esac
                ;;
            FSTAB_LINE)
                # remove exactly the line we added (and our comment above it)
                _esc=$(printf '%s' "$REST" | sed 's/[][\\.*^$/]/\\&/g')
                sed -i "/^${_esc}\$/d; /^# Linux Guardian: noexec /d" /etc/fstab 2>/dev/null || true
                log_ok "Removed from /etc/fstab: ${REST%% *} ${REST#* }"
                ;;
            FSTAB_SUB)
                sed -i "/\s${REST//\//\\/}\s/ s/defaults,noexec,nosuid,nodev/defaults/" /etc/fstab 2>/dev/null || true
                log_ok "Reverted noexec options in /etc/fstab: $REST"
                ;;
            FSTAB_TMP)   # manifests written by lg <= 1.2
                sed -i '/Linux Guardian: noexec/d' /etc/fstab 2>/dev/null || true
                sed -i '/^tmpfs\s\+\(\/tmp\|\/var\/tmp\)\s\+tmpfs\s\+defaults,noexec,nosuid,nodev,size=/d' /etc/fstab 2>/dev/null || true
                log_ok "Removed lg noexec entries from /etc/fstab"
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
            SELINUX_MODULE)
                semodule -r "$REST" 2>/dev/null && log_ok "Removed SELinux module: $REST" || true
                ;;
            RMFILE)
                rm -f "$REST" 2>/dev/null && log_ok "Removed: $REST" || true
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
    done < <(tac "$LATEST")
    # a consumed manifest must not be replayed over newer edits
    [ "$DRY_RUN" = true ] || mv "$LATEST" "${LATEST}.done" 2>/dev/null || true

    echo ""
    log_ok "Undo complete — system restored to previous state"
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT: Update packages
# ══════════════════════════════════════════════════════════════════════════════
UPGRADE_PACKAGES=false
for _a in "$@"; do [ "$_a" = "--upgrade-packages" ] && UPGRADE_PACKAGES=true; done
if [ "$DRY_RUN" = false ] && [ "$UPGRADE_PACKAGES" = false ] && [ "$RUN_MODE" != "auto" ] && [ -t 0 ]; then
    echo ""
    read -r -p "  Upgrade all system packages first (kernel, PHP, MariaDB may restart)? [y/N]: " -n 1 _UPG || _UPG=""
    echo ""
    [[ "$_UPG" =~ ^[Yy]$ ]] && UPGRADE_PACKAGES=true
fi
if [ "$DRY_RUN" = false ] && [ "$UPGRADE_PACKAGES" = false ]; then
    log_info "Pre-flight: package upgrade skipped (run with --upgrade-packages, or answer y) — Part D reports what is pending"
fi
if [ "$DRY_RUN" = false ] && [ "$UPGRADE_PACKAGES" = true ]; then
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
    # Slub allocator hardening — prevents heap exploitation
    kernel.slab_nomerge = 1
EOF
    # Disable unprivileged user namespaces only if no container runtime detected
    # Affected: Docker, Podman, LXC/LXD, containerd, Chrome/Firefox sandbox,
    #           Flatpak, Snap, bubblewrap
    _NS_SKIP=false
    _NS_REASON=""
    command -v docker     &>/dev/null && _NS_SKIP=true && _NS_REASON="docker"
    command -v podman     &>/dev/null && _NS_SKIP=true && _NS_REASON="podman"
    command -v lxc        &>/dev/null && _NS_SKIP=true && _NS_REASON="lxc"
    command -v lxd        &>/dev/null && _NS_SKIP=true && _NS_REASON="lxd"
    command -v flatpak    &>/dev/null && _NS_SKIP=true && _NS_REASON="flatpak"
    command -v snap       &>/dev/null && _NS_SKIP=true && _NS_REASON="snap"
    command -v bwrap      &>/dev/null && _NS_SKIP=true && _NS_REASON="bubblewrap"
    systemctl is-active --quiet docker      2>/dev/null && _NS_SKIP=true && _NS_REASON="docker service"
    systemctl is-active --quiet containerd  2>/dev/null && _NS_SKIP=true && _NS_REASON="containerd"
    systemctl is-active --quiet lxd         2>/dev/null && _NS_SKIP=true && _NS_REASON="lxd service"
    systemctl is-active --quiet podman      2>/dev/null && _NS_SKIP=true && _NS_REASON="podman service"

    if [ "$_NS_SKIP" = false ]; then
        echo "# Disable unprivileged user namespaces (privilege escalation vector)" \
            >> "$SYSCTL_CONF"
        echo "user.max_user_namespaces = 0" >> "$SYSCTL_CONF"
        log_ok "user.max_user_namespaces = 0 (no container runtime detected)"
    else
        log_skip "user.max_user_namespaces — ${_NS_REASON} detected, keeping enabled"
    fi
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

unset SYSFILE_PERMS
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
# LAYER 4.1 — Apache Hardening
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 4.1: Apache / MariaDB Hardening"

# Locate all httpd.conf files
_HTTPD_CONFS=()
while IFS= read -r _f; do
    [ -f "$_f" ] && _HTTPD_CONFS+=("$_f")
    done < <(find /etc/httpd /etc/apache2 /usr/local/apache2 \
            /usr/local/apache /usr/local/cwpsrv/conf \
            -maxdepth 3 \
            \( -name "httpd.conf" -o -name "apache2.conf" \) \
            2>/dev/null | sort -u)

if [ ${#_HTTPD_CONFS[@]} -eq 0 ]; then
    log_skip "httpd.conf not found — skipping"
else
    # Interactive mode — let user choose
    if [ "$RUN_MODE" = "interactive" ] && [ ${#_HTTPD_CONFS[@]} -gt 1 ]; then
        echo ""
        echo -e "  ${BOLD}Select httpd.conf to harden:${NC}"
        for i in "${!_HTTPD_CONFS[@]}"; do
            echo "    [$((i+1))] ${_HTTPD_CONFS[$i]}"
        done
        echo "    [A] All"
        echo ""
        if [ "$RUN_MODE" = "auto" ] || [ "$DRY_RUN" = true ] || [ ! -t 0 ]; then _HTTPD_CHOICE=A; else
            read -r -p "  Choice (default: A): " _HTTPD_CHOICE
        fi
        case "${_HTTPD_CHOICE:-A}" in
            [Aa]|"") _SELECTED_CONFS=("${_HTTPD_CONFS[@]}") ;;
            [0-9]*)
                _IDX=$((_HTTPD_CHOICE-1))
                [ -n "${_HTTPD_CONFS[$_IDX]:-}" ] \
                    && _SELECTED_CONFS=("${_HTTPD_CONFS[$_IDX]}") \
                    || _SELECTED_CONFS=("${_HTTPD_CONFS[@]}")
                ;;
            *) _SELECTED_CONFS=("${_HTTPD_CONFS[@]}") ;;
        esac
    else
        _SELECTED_CONFS=("${_HTTPD_CONFS[@]}")
    fi

    _HTTPD_SETTINGS=$'# Linux Guardian — Apache hardening\nServerTokens Prod\nServerSignature Off\nUseCanonicalName Off'

    for _conf in "${_SELECTED_CONFS[@]}"; do
        if [ "$DRY_RUN" = true ]; then
            log_dry "Append hardening to: ${_conf}"
            continue
        fi
        backup_file "$_conf" "httpd_conf"
        # Skip if already applied
        if grep -q "ServerTokens Prod" "$_conf" 2>/dev/null; then
            log_skip "Already applied: ${_conf}"
            continue
        fi
        # Ensure newline before appending
        [ "$(tail -c1 "$_conf" | wc -l)" -eq 0 ] && echo "" >> "$_conf"
        echo "$_HTTPD_SETTINGS" >> "$_conf"
        log_ok "Hardened: ${_conf}"
    done
fi

# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4.2 — MySQL / MariaDB Hardening
# Harden database: bind to localhost only
# ══════════════════════════════════════════════════════════════════════════════
section "LAYER 4.2: MySQL / MariaDB Hardening"

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

    # fallback: system config dirs only (never a user's ~/.my.cnf under /home)
    if [ -z "$MY_CNF" ]; then
        MY_CNF=$(find /etc /usr/local/etc -maxdepth 3 -type f \( -name my.cnf -o -name server.cnf -o -name mariadb-server.cnf -o -name 50-server.cnf \) 2>/dev/null | head -1 || true)
    fi

    # already listening on loopback only? then there is nothing to edit and
    # nothing to restart — re-running lg must not bounce the database
    _DB_LISTEN=$(ss -Htln 2>/dev/null | awk '{print $4}' | grep -E ':3306$' | sed -E 's/:3306$//' | sort -u | tr '\n' ' ')
    _DB_PUBLIC=$(printf '%s' "$_DB_LISTEN" | tr ' ' '\n' | grep -vE '^(127\.0\.0\.1|\[::1\]|::1)$' | grep -v '^$' || true)
    if [ -n "$_DB_LISTEN" ] && [ -z "$_DB_PUBLIC" ]; then
        log_ok "MySQL/MariaDB already bound to localhost (${_DB_LISTEN}) — nothing to do"
        MY_CNF=""
    elif [ -z "$_DB_LISTEN" ]; then
        log_info "MySQL/MariaDB is not listening on TCP (socket only, or stopped) — bind-address left untouched"
        MY_CNF=""
    else
        log_warn "MySQL/MariaDB listens on ${_DB_LISTEN}— remote clients/replication will lose access once bound to 127.0.0.1"
        if [ "$DRY_RUN" = false ] && [ "$RUN_MODE" != "auto" ] && [ -t 0 ]; then
            read -r -p "  Bind the database to 127.0.0.1 and restart it now? [y/N]: " -n 1 _DBQ || _DBQ=""
            echo ""
            [[ "$_DBQ" =~ ^[Yy]$ ]] || { log_skip "Database bind-address left as is"; MY_CNF=""; }
        fi
    fi

    if [ -z "$MY_CNF" ]; then
        :
    else
        log_info "Config: $MY_CNF"
        backup_file "$MY_CNF" "mysql"

        if [ "$DRY_RUN" = true ]; then
            log_dry "Set bind-address=127.0.0.1 in $MY_CNF"
        else
            # ── Step 3: Apply change ─────────────────────────────────────────

            # Remove any existing bind-address lines to avoid duplicates
            sed -i '/^bind-address/d' "$MY_CNF"
            sed -i '/^# Linux Guardian/d' "$MY_CNF"

            # Add bind-address under [mysqld] section, or create section if missing
            if grep -q '^\[mysqld\]' "$MY_CNF" 2>/dev/null; then
                sed -i '/^\[mysqld\]/a bind-address=127.0.0.1' "$MY_CNF"
            else
                printf '\n[mysqld]\n# Linux Guardian\nbind-address=127.0.0.1\n' >> "$MY_CNF"
            fi

            log_ok "bind-address=127.0.0.1"

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

log_ok "Layer 4.2 complete"

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

# Never touch panel-private php.ini (the panel UI/webmail need exec) nor
# per-site/per-user php.ini under docroots (a combined open_basedir there
# would let one account read every other). Applies in every mode — the
# interactive "a=all" used to include them.
_PANEL_INFO=$(detect_panel); _PANEL_NAME="${_PANEL_INFO%%:*}"
_INI_KEEP=()
for _ini in ${PHP_INI_FILES[@]+"${PHP_INI_FILES[@]}"}; do
    case "$_ini" in
        /home/*|/var/www/*|/srv/*|/usr/share/*|/root/*|/tmp/*|/var/tmp/*|*/public_html/*|*/htdocs/*|*/httpdocs/*) continue ;;
    esac
    case "$_PANEL_NAME" in
        CWP)        [[ "$_ini" == /usr/local/cwp/* || "$_ini" == /opt/alt/* ]]          && continue ;;
        cPanel)     [[ "$_ini" == /usr/local/cpanel/* || "$_ini" == /opt/cpanel/* ]]   && continue ;;
        Plesk)      [[ "$_ini" == /opt/plesk/* || "$_ini" == /usr/local/psa/* ]]       && continue ;;
        CyberPanel) [[ "$_ini" == /usr/local/lsws/* ]]                                  && continue ;;
        aaPanel)    [[ "$_ini" == /www/server/php/* ]]                                  && continue ;;
        InterWorx)  [[ "$_ini" == /usr/local/interworx/* ]]                             && continue ;;
        CentminMod) [[ "$_ini" == /usr/local/lib/php* ]]                                && continue ;;
    esac
    _INI_KEEP+=("$_ini")
done
PHP_INI_FILES=(${_INI_KEEP[@]+"${_INI_KEEP[@]}"})

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

    if [[ "$RUN_MODE" == "auto" || "$DRY_RUN" == "true" ]]; then
        _PANEL_INFO=$(detect_panel)
        _PANEL_NAME="${_PANEL_INFO%%:*}"

        SELECTED_FILES=()
        for _ini in "${PHP_INI_FILES[@]}"; do
            case "$_PANEL_NAME" in
                CWP)        [[ "$_ini" == /usr/local/cwp/* ]]        && continue ;;
                cPanel)     [[ "$_ini" == /usr/local/cpanel/* ]]     && continue ;;
                Plesk)      [[ "$_ini" == /opt/plesk/* || "$_ini" == /usr/local/psa/* ]] && continue ;;
                CyberPanel) [[ "$_ini" == /usr/local/lsws/* ]]       && continue ;;
                HestiaCP)   [[ "$_ini" == /etc/php/* ]]              && continue ;;
                VestaCP)    [[ "$_ini" == /etc/php/* ]]              && continue ;;
                ISPConfig)  [[ "$_ini" == /etc/php/* ]]              && continue ;;
                aaPanel)    [[ "$_ini" == /www/server/php/* ]]       && continue ;;
                Webmin)     [[ "$_ini" == /etc/php/* ]]              && continue ;;
                InterWorx)  [[ "$_ini" == /usr/local/interworx/* ]]  && continue ;;
                Froxlor)    [[ "$_ini" == /etc/php/* ]]              && continue ;;
                RunCloud)   [[ "$_ini" == /etc/php/* ]]              && continue ;;
                CentminMod) [[ "$_ini" == /usr/local/lib/php* ]]     && continue ;;
            esac
            SELECTED_FILES+=("$_ini")
        done
        PHP_SKIP=false
    else
        echo "  Select php.ini files:  a=all  s=skip  1,3=specific"
        if [ "$RUN_MODE" = "auto" ] || [ "$DRY_RUN" = true ] || [ ! -t 0 ]; then choice=a; else
            read -r -p "  Your choice: " choice
        fi
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
                for n in ${nums[@]+"${nums[@]}"}; do
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

    # FIX: was redeclaring DISABLE_FUNCTIONS + declare -A PHPSEC inside
    # this block. Both are now globals at top of file, kept here for
    # backward-compat / readability. The actual data comes from the globals.
    for inifile in "${SELECTED_FILES[@]}"; do
        log_info "Processing: $inifile"
        backup_file "$inifile" "phpini"

        if [ "$DRY_RUN" = true ]; then
            log_dry "Apply global security settings → $inifile"
            log_dry "  disable_functions (global)"
            log_dry "  session + error settings (hosting-grade defaults)"
            [ "$PHP_STRICT" = true ] && [[ "$inifile" != *cli* ]] && log_dry "  --php-strict: upload/post/memory/time limits, Phar off, cookie_secure, SameSite=Strict"
            log_dry "  open_basedir → set per-site in PART 5.1"
            continue
        fi

        # Ensure file ends with newline before any append
        [ -s "$inifile" ] && \
            [ "$(tail -c1 "$inifile" | wc -l)" -eq 0 ] && \
            echo "" >> "$inifile"

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

        # ── date.timezone — prevents 502 errors on panels ─────────────────────
        if grep -qE "^\s*;*\s*date\.timezone" "$inifile"; then
            sed -i "s|^\s*;*\s*date\.timezone.*|date.timezone = ${PHP_TIMEZONE}|" "$inifile"
        else
            printf '\ndate.timezone = %s\n' "${PHP_TIMEZONE}" >> "$inifile"
        fi
        log_ok "date.timezone = ${PHP_TIMEZONE}: $(basename "$inifile")"

        # ── Global security settings (FIX: was using declare -A PHPSEC; now
        #    uses flat key:value pairs from global PHPSEC_PAIRS array) ────────
        _pair=""; _key=""; _val=""
        _PAIRS_NOW=("${PHPSEC_PAIRS[@]}")
        if [ "$PHP_STRICT" = true ] && [[ "$inifile" != *cli* ]]; then
            _PAIRS_NOW+=("${PHPSEC_STRICT_PAIRS[@]}")
            log_info "--php-strict: limits and strict cookie flags applied to $(basename "$(dirname "$inifile")")/$(basename "$inifile")"
        fi
        for _pair in "${_PAIRS_NOW[@]}"; do
            _key="${_pair%%:*}"
            _val="${_pair#*:}"
            if grep -qE "^\s*${_key}\s*=" "$inifile"; then
                sed -i "s|^\s*${_key}\s*=.*|${_key} = ${_val}|" "$inifile"
            elif grep -qE "^\s*;\s*${_key}\s*=" "$inifile"; then
                sed -i "s|^\s*;\s*${_key}\s*=.*|${_key} = ${_val}|" "$inifile"
            else
                printf '\n%s = %s\n' "${_key}" "${_val}" >> "$inifile"
            fi
        done
        log_ok "Global security settings applied: $inifile"
    done

    # Restart services based on PHP mode
    if [ "$DRY_RUN" = false ]; then
        _L5_MODE=$(detect_php_mode 2>/dev/null || echo "mod_php")

        # ── open_basedir for CGI / mod_php ────────────────────────────────────
        # For PHP-FPM: open_basedir is set per-site in PART 5.1 pool files
        # For CGI / mod_php: set it globally in php.ini per detected site
        if [[ "$_L5_MODE" == "cgi" || "$_L5_MODE" == "mod_php" ]]; then
            # FIX: was 50+ lines of inlined loops for each panel.
            # Now uses detect_site_paths() + extra panel paths.
            _SITES_OBD=()
            while IFS= read -r _site_path; do
                _SITES_OBD+=("$_site_path")
            done < <(detect_site_paths)

            # ── Panel-specific paths not covered by detect_site_paths ────────
            _panel_extra=(
                /usr/local/cwpsrv/htdocs
                /var/www/vhosts/*/httpdocs
                /var/www/vhosts/*/web
                /home/*/domains/*/public_html
                /home/*/web/*/public_html
                /var/www/clients/*/web*/web
                /www/wwwroot/*
                /home/*/html
                /home/*/htdocs
                /var/customers/webs/*
            )
            _pe=""
            for _pe in "${_panel_extra[@]}"; do
                # shellcheck disable=SC2086
                for _d in $_pe; do
                    [ -d "$_d" ] && _SITES_OBD+=("${_d%/}")
                done
            done

            # ── Deduplicate ───────────────────────────────────────────────────
            if [ ${#_SITES_OBD[@]} -gt 0 ]; then
                mapfile -t _SITES_OBD < <(printf '%s\n' "${_SITES_OBD[@]}" | sort -u)
            fi

            if [ ${#_SITES_OBD[@]} -gt 0 ]; then
                # Build combined open_basedir
                _OBD_VALUE=""
                for _s in "${_SITES_OBD[@]}"; do
                    _OBD_VALUE="${_OBD_VALUE}${_s}:"
                done
                _OBD_VALUE="${_OBD_VALUE}/tmp:/usr/share/php:/usr/share/pear"

                log_info "open_basedir paths detected (${#_SITES_OBD[@]} sites):"
                for _s in "${_SITES_OBD[@]}"; do
                    echo "    → ${_s}"
                done

                for inifile in "${SELECTED_FILES[@]}"; do
                    [[ "$inifile" == *cli* ]] && continue
                    if grep -qE "^\s*open_basedir\s*=" "$inifile"; then
                        sed -i "s|^\s*open_basedir\s*=.*|open_basedir = ${_OBD_VALUE}|" "$inifile"
                    elif grep -qE "^\s*;\s*open_basedir\s*=" "$inifile"; then
                        sed -i "s|^\s*;\s*open_basedir\s*=.*|open_basedir = ${_OBD_VALUE}|" "$inifile"
                    else
                        echo "open_basedir = ${_OBD_VALUE}" >> "$inifile"
                    fi
                    log_ok "open_basedir set (${_L5_MODE}): $(basename "$inifile")"
                done
            else
                log_skip "open_basedir: no site directories detected"
            fi
        else
            log_info "open_basedir: handled per-site in PART 5.1 (PHP-FPM pools)"
        fi

        restart_php_services "$_L5_MODE"
    else
        log_dry "open_basedir: set per-site for CGI/mod_php or per-pool for FPM"
        log_dry "Restart PHP/web services"
    fi
fi

log_ok "Layer 5 complete"

# PART 5.1 — PHP-FPM Pool per Site
# Auto-detects PHP-FPM config directory and creates isolated pool for each site
# Each site gets: own user, open_basedir, disable_functions, session, error_log
# ══════════════════════════════════════════════════════════════════════════════
section "PART 5.1: PHP-FPM Pool per Site (auto-detect)"

setup_phpfpm_pools() {

    # ── Detect php-fpm binary — auto-discover any version ─────────────────────
    PHPFPM_BIN=""
    while IFS= read -r _candidate; do
        [ -x "$_candidate" ] && PHPFPM_BIN="$_candidate" && break
    done < <(
        # From PATH
        compgen -c 2>/dev/null | grep -E "^php-fpm|^php[0-9].*fpm" | sort -rV | \
            while read -r b; do command -v "$b" 2>/dev/null; done
        # From common sbin/bin dirs
        find /usr/sbin /usr/local/sbin /usr/bin /usr/local/bin \
             -maxdepth 1 \( -name "php-fpm*" -o -name "php*fpm" \) \
             -executable 2>/dev/null | sort -rV
    )

    if [ -z "$PHPFPM_BIN" ]; then
        log_skip "php-fpm not found — skipping pool configuration"
        log_info "Install: dnf install php-fpm -y  (CentOS/RHEL)"
        log_info "Install: apt install php-fpm -y  (Ubuntu/Debian)"
        PHPFPM_SKIP=true
        return 0
    fi
    log_ok "php-fpm found: $PHPFPM_BIN"

    # ── Detect PHP-FPM pool directory — auto-discover ─────────────────────────
    POOL_DIR=$(find_pool_dir)

    if [ -z "$POOL_DIR" ]; then
        log_warn "PHP-FPM pool directory not found — trying to locate..."
        POOL_DIR=$("$PHPFPM_BIN" --test 2>&1 \
            | grep -oE 'include=[^*]+' | sed 's/include=//' \
            | head -1 | xargs dirname 2>/dev/null || true)
        [ -d "$POOL_DIR" ] || {
            log_warn "Cannot detect pool directory — skipping"
            PHPFPM_SKIP=true
            return 0
        }
    fi
    log_ok "PHP-FPM pool dir: $POOL_DIR"

    # ── Detect PHP-FPM service name — auto-discover ───────────────────────────
    PHPFPM_SVC=""
    while IFS= read -r _svc; do
        systemctl list-units --type=service --all 2>/dev/null \
            | grep -q "${_svc}" && PHPFPM_SVC="${_svc%.service}" && break
    done < <(
        systemctl list-units --type=service --all --no-legend 2>/dev/null \
            | awk '{print $1}' | grep -E "php.*fpm" | sort -rV || true
        echo "php-fpm.service"
    )
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

    _NEW_POOLS=()
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
        # the name lands in an unquoted heredoc and in file names: letters,
        # digits, dot, dash, underscore only; not the web server's own dirs
        SITE_NAME=$(printf '%s' "$SITE_NAME" | tr -c 'A-Za-z0-9_.-' '_')
        case "$SITE_NAME" in cgi-bin|html|icons|error|manual|"") continue ;; esac

        # SECURITY: refuse root-owned sites — running PHP-FPM as root
        # would defeat the entire pool-isolation layer.
        if [ "$SITE_USER" = "root" ] || [ "$SITE_USER" = "0" ]; then
            log_warn "Skipping root-owned site (PHP-FPM must NOT run as root): ${site}"
            log_info "Fix: chown -R <user>:${SITE_USER} ${site}"
            continue
        fi

        # Fallback user if system user doesn't exist
        id "$SITE_USER" &>/dev/null || SITE_USER="www-data"
        SITE_GROUP=$(id -gn "$SITE_USER" 2>/dev/null || echo "www-data")

        # Detect web server socket owner (FIX: was using same name for group)
        SOCK_OWNER=$(detect_webserver_user)
        SOCK_GROUP=$(id -gn "$SOCK_OWNER" 2>/dev/null || echo "$SOCK_OWNER")

        POOL_CONF="${POOL_DIR}/${SITE_NAME}.conf"
        # socket directory: whatever the distro's own pool uses (/run/php on
        # Debian/Ubuntu, /run/php-fpm on RHEL); fall back to /run/php-fpm
        SOCK_DIR=$(grep -hE '^\s*listen\s*=\s*/' "${POOL_DIR}"/www.conf 2>/dev/null | head -1 | sed -E 's/.*=\s*//; s|/[^/]*$||')
        [ -n "$SOCK_DIR" ] || SOCK_DIR=/run/php-fpm
        SOCK_PATH="${SOCK_DIR}/${SITE_NAME}.sock"
        SESSION_PATH="${SESSION_BASE}/${SITE_NAME}"
        ERROR_LOG="${LOG_BASE}/${SITE_NAME}-error.log"
        # the session dir and log dir MUST be inside open_basedir or every
        # session write fails and nobody can log in
        OPEN_BASEDIR="${SITE_ROOT}:${SESSION_PATH}:${LOG_BASE}:/tmp:/usr/share/php:/usr/share/pear"

        log_info "Pool: ${SITE_NAME}  user=${SITE_USER}  root=${SITE_ROOT}"

        if [ "$DRY_RUN" = true ]; then
            log_dry "Create ${POOL_CONF}"
            log_dry "  user=${SITE_USER}  open_basedir=${OPEN_BASEDIR}"
            continue
        fi

        mkdir -p "$SESSION_PATH" "$SOCK_DIR" 2>/dev/null || true
        chown "${SITE_USER}:${SITE_GROUP}" "$SESSION_PATH" 2>/dev/null || true
        chmod 700 "$SESSION_PATH" 2>/dev/null || true
        # survive reboots when the socket dir lives on tmpfs
        [ -d /etc/tmpfiles.d ] && printf 'd %s 0755 root root -\n' "$SOCK_DIR" > /etc/tmpfiles.d/lg-php-fpm.conf
        backup_file "$POOL_CONF" "phpfpm_pool"     # records FILE: or RMFILE: for undo
        _NEW_POOLS+=("$POOL_CONF")

        # SECURITY: quoted heredoc prevents command injection via $SITE_ROOT
        # (was: unquoted `<< EOF` evaluated $ and backticks in site paths).
        cat > "$POOL_CONF" << POOL_EOF
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
        listen.group = ${SOCK_GROUP}
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
POOL_EOF

        chmod 640 "$POOL_CONF"
        log_ok "Pool created: $POOL_CONF"
    done

    # ── Validate and restart php-fpm ──────────────────────────────────────────
    if [ "$DRY_RUN" = false ]; then
        echo ""
        # FIX: was unquoted — if $PHPFPM_BIN empty, would run bare "--test" as cmd.
        # FIX: was unquoted — paths with spaces would word-split.
        _FPM_OK=1
        if [ -x "$PHPFPM_BIN" ] && "$PHPFPM_BIN" --test 2>/dev/null; then
            log_ok "PHP-FPM config test passed"
        else
            _FPM_OK=0
            log_warn "PHP-FPM config test failed — the pools written in this run are being removed so existing sites keep working"
            [ -x "$PHPFPM_BIN" ] && { "$PHPFPM_BIN" --test 2>&1 | tail -10 || true; }
            for _pc in ${_NEW_POOLS[@]+"${_NEW_POOLS[@]}"}; do rm -f "$_pc"; done
        fi

        if [ -n "$PHPFPM_SVC" ] && [ "$_FPM_OK" = 1 ]; then
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
                && { log_ok "${mnt}  →  remounted noexec"; echo "MOUNT_NOEXEC:${mnt}:remount" >> "$UNDO_MANIFEST"; } \
                || { log_warn "${mnt}  →  remount failed"; true; }
        fi

        # Persist in /etc/fstab
        if [ "$DRY_RUN" = false ]; then
            if grep -qE "\s${mnt}\s" /etc/fstab 2>/dev/null; then
                if ! grep -E "\s${mnt}\s" /etc/fstab | grep -q "noexec"; then
                    backup_file /etc/fstab "fstab"
                    sed -i "/\s${mnt//\//\\/}\s/ s/defaults/defaults,noexec,nosuid,nodev/" \
                        /etc/fstab 2>/dev/null || true
                    if grep -E "\s${mnt}\s" /etc/fstab | grep -q "noexec"; then
                        echo "FSTAB_SUB:${mnt}" >> "$UNDO_MANIFEST"
                        log_ok "${mnt}  →  noexec persisted in /etc/fstab"
                    else
                        log_warn "${mnt}  →  fstab line has no 'defaults' option — add noexec,nosuid,nodev by hand"
                    fi
                fi
            fi
        fi

    elif [ "$allow_tmpfs" = "true" ]; then
        # Not a mountpoint (/tmp, /var/tmp on the root fs). On the LIVE system
        # bind-mount the directory onto itself and flip the flags, so nothing
        # already in it (mysql.sock, PHP sessions, screen sockets) disappears.
        # A fresh tmpfs is only configured for the next boot.
        if [ "$DRY_RUN" = true ]; then
            log_dry "bind-remount ${mnt} noexec now; tmpfs (size=${size}) from next boot"
        else
            if mount --bind "$mnt" "$mnt" 2>/dev/null && mount -o remount,bind,noexec,nosuid,nodev "$mnt" 2>/dev/null; then
                log_ok "${mnt}  →  noexec (bind, contents kept)"
                echo "MOUNT_NOEXEC:${mnt}:bind" >> "$UNDO_MANIFEST"
            else
                umount "$mnt" 2>/dev/null || true
                log_warn "${mnt}  →  bind-remount failed"
            fi
        fi

        # Persist in /etc/fstab
        if [ "$DRY_RUN" = false ]; then
            if ! grep -qE "tmpfs\s+${mnt}\s" /etc/fstab 2>/dev/null; then
                backup_file /etc/fstab "fstab"
                _fl="tmpfs ${mnt} tmpfs defaults,noexec,nosuid,nodev,size=${size} 0 0"
                echo "# Linux Guardian: noexec ${mnt}" >> /etc/fstab
                echo "$_fl" >> /etc/fstab
                echo "FSTAB_LINE:${_fl}" >> "$UNDO_MANIFEST"
                log_ok "${mnt}  →  tmpfs (${size}) in /etc/fstab for the next boot"
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
                    echo "MOUNT_NOEXEC:${mnt}:bind" >> "$UNDO_MANIFEST"
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

# ── Apply noexec to /tmp and /var/tmp ─────────────────────────────────────────
log_info "Applying noexec to temp directories..."
_apply_noexec_dir "/tmp"     "true"  "256M"
_apply_noexec_dir "/var/tmp" "true"  "128M"

# ── Auto-detect and apply noexec to site directories ─────────────────────────
log_info "Auto-detecting site directories..."
echo ""

# FIX: was using duplicate detect_site_roots() — now uses shared detect_site_paths()
SITE_ROOTS=()
while IFS= read -r root; do
    SITE_ROOTS+=("$root")
done < <(detect_site_paths)

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
    # FIX: was using a single sed for one variable name; failed silently on
    # GRUB_CMDLINE_LINUX_DEFAULT or empty GRUB_CMDLINE_LINUX. grub-mkconfig
    # was also unverified. Now handles both vars and verifies the rebuild.
    if command -v pacman &>/dev/null; then
        if [ -f /etc/default/grub ]; then
            if ! grep -qE "apparmor=1" /etc/default/grub; then
                cp /etc/default/grub "${BACKUP_DIR:-/tmp}/grub.lg.bak" 2>/dev/null || true
                for _grub_var in GRUB_CMDLINE_LINUX GRUB_CMDLINE_LINUX_DEFAULT; do
                    if grep -qE "^${_grub_var}=" /etc/default/grub; then
                        sed -i "s|^${_grub_var}=\"\(.*\)\"|${_grub_var}=\"\1 apparmor=1 security=apparmor |\"|" /etc/default/grub
                    else
                        echo "${_grub_var}=\"apparmor=1 security=apparmor\"" >> /etc/default/grub
                    fi
                done
                if grub-mkconfig -o /boot/grub/grub.cfg &>/dev/null; then
                    log_info "GRUB updated for AppArmor — reboot required"
                else
                    log_warn "grub-mkconfig failed — AppArmor won't activate on next boot"
                fi
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
                log_dry "Enable SELinux as PERMISSIVE in /etc/selinux/config + schedule a relabel (reboot)"
            else
                # booting an unlabelled box straight into enforcing is the
                # classic no-ssh / unbootable outcome: permissive + relabel
                # first, enforcing on a later run once ausearch -m avc is clean
                backup_file /etc/selinux/config "selinux"
                sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
                touch /.autorelabel 2>/dev/null || true
                log_warn "SELinux was disabled — set to PERMISSIVE and a full relabel is scheduled for the next reboot"
                log_warn "After the reboot check 'ausearch -m avc -ts boot', then run lg again to switch to enforcing"
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
                    # Ensure vmail fcontext survives the relabel
                    # Re-register after fixfiles to guarantee it's in the database
                    if [ -n "${_L7_VMAIL:-}" ] && command -v semanage &>/dev/null; then
                        semanage fcontext -d "${_L7_VMAIL}(/.*)?" 2>/dev/null || true
                        semanage fcontext -a -t dovecot_var_t \
                            "${_L7_VMAIL}(/.*)?" 2>/dev/null || true
                        log_ok "SELinux: vmail fcontext re-registered post-fixfiles (survives reboot)"
                    fi
                else
                    log_skip "fixfiles not found — install policycoreutils"
                fi
            fi

            # Harden httpd booleans
            # httpd booleans are REPORTED, never changed: turning them off
            # silently breaks WordPress updates/SMTP (can_network_connect),
            # ionCube and opcache.jit (execmem) and panel writes (unified).
            # The admin set them for a reason; lg shows what is on and why
            # it matters.
            _sebool_pairs=(
                "httpd_execmem:off:ionCube/opcache.jit need it on"
                "httpd_execute_tmp:off:nothing legitimate executes from /tmp"
                "httpd_unified:off:lets httpd write everything it can read"
                "httpd_can_network_connect:off:WordPress updates, SMTP, payment APIs need it on"
                "httpd_can_network_relay:off:only reverse proxies need it on"
            )
            _pair=""; _bname=""; _bval=""; _bwhy=""; _current=""
            for _pair in "${_sebool_pairs[@]}"; do
                _bname="${_pair%%:*}"; _rest="${_pair#*:}"; _bval="${_rest%%:*}"; _bwhy="${_rest#*:}"
                getsebool "$_bname" &>/dev/null || continue
                _current=$(getsebool "$_bname" 2>/dev/null | awk '{print $3}' || true)
                if [ "$_current" = "$_bval" ]; then
                    log_ok "SELinux bool: $_bname = $_current"
                else
                    log_info "SELinux bool: $_bname = $_current (hardened value: $_bval — $_bwhy; change by hand: setsebool -P $_bname $_bval)"
                fi
            done

            # ── Fix vmail + Dovecot SELinux contexts ──────────────────────────
            # This is the ONLY panel-specific fix in Layer 7
            _L7_VMAIL=""; _VMAIL_TYPE=""
            if [ "$DRY_RUN" = false ]; then
                # FIX: was inlined 4-line loop, now uses shared helper
                _L7_VMAIL=$(detect_vmail_dir 2>/dev/null) || _L7_VMAIL=""

                if [ -n "$_L7_VMAIL" ] && command -v semanage &>/dev/null; then
                    log_info "Mail storage detected: ${_L7_VMAIL}"
                    # Detect correct SELinux type for vmail on this system
                    # dovecot_var_t exists on newer policies, mail_spool_t on older
                    _VMAIL_TYPE=""
                    if grep -q "dovecot_var_t" \
                        /etc/selinux/targeted/contexts/files/file_contexts \
                        2>/dev/null; then
                        _VMAIL_TYPE="dovecot_var_t"
                    else
                        _VMAIL_TYPE="mail_spool_t"
                    fi
                    log_info "Using SELinux type: ${_VMAIL_TYPE}"
                    # Delete any existing rule first to avoid conflict
                    semanage fcontext -d "${_L7_VMAIL}(/.*)?" 2>/dev/null || true
                    semanage fcontext -a -t "$_VMAIL_TYPE" \
                        "${_L7_VMAIL}(/.*)?" 2>/dev/null || true
                    # Verify registration
                    if semanage fcontext -l 2>/dev/null | \
                       grep -q "${_L7_VMAIL}.*${_VMAIL_TYPE}"; then
                        log_ok "SELinux fcontext registered: ${_L7_VMAIL} → ${_VMAIL_TYPE}"
                    else
                        log_warn "fcontext registration failed — applying chcon directly"
                        find "$_L7_VMAIL" -exec chcon -t "$_VMAIL_TYPE" {} \; \
                            2>/dev/null || true
                    fi
                    find "$_L7_VMAIL" -name "*.lock" -delete 2>/dev/null || true
                    restorecon -RFv "$_L7_VMAIL" 2>/dev/null | tail -3 || true
                    log_ok "SELinux: ${_L7_VMAIL} → ${_VMAIL_TYPE}"
                fi

                # Dovecot log files
                for _dlog in "${DOVECOT_LOG_PATHS[@]}"; do
                    [ -f "$_dlog" ] || continue
                    command -v semanage &>/dev/null && {
                        semanage fcontext -a -t dovecot_var_log_t \
                            "$_dlog" 2>/dev/null \
                            || semanage fcontext -m -t dovecot_var_log_t \
                            "$_dlog" 2>/dev/null || true
                    }
                    chcon -t dovecot_var_log_t "$_dlog" 2>/dev/null || true
                    log_ok "SELinux: ${_dlog} → dovecot_var_log_t"
                done

                # Restart Dovecot to apply context fixes
                if systemctl is-active --quiet dovecot 2>/dev/null; then
                    systemctl restart dovecot 2>/dev/null \
                        && log_ok "Dovecot restarted" \
                        || log_warn "Dovecot restart failed"
                elif systemctl is-enabled --quiet dovecot 2>/dev/null; then
                    systemctl start dovecot 2>/dev/null \
                        && log_ok "Dovecot started" \
                        || log_warn "Dovecot failed to start"
                fi

                # ── Dovecot SELinux policy — MySQL socket + vmail access ──────
                # Install required tools if missing
                if ! command -v checkmodule &>/dev/null; then
                    log_info "Installing checkmodule..."
                    install_pkg "checkpolicy" 2>/dev/null || \
                    install_pkg "policycoreutils-devel" 2>/dev/null || true
                fi
                if ! command -v semodule_package &>/dev/null; then
                    log_info "Installing semodule_package..."
                    install_pkg "policycoreutils-python-utils" 2>/dev/null || \
                    install_pkg "policycoreutils" 2>/dev/null || true
                fi

                # FIX: was inlined ~55 lines, now uses shared helper
                if [ -n "${_VMAIL_TYPE:-}" ]; then
                    _install_dovecot_lg_policy "$_VMAIL_TYPE" || log_warn "dovecot_lg policy not installed (checkmodule/semodule_package missing?)"
                fi
                # Enable mmap for Dovecot index files
                setsebool -P domain_can_mmap_files 1 2>/dev/null \
                    && log_ok "SELinux bool: domain_can_mmap_files = on" || true
            else
                log_dry "Fix SELinux: vmail → dovecot_var_t, dovecot logs → dovecot_var_log_t"
                log_dry "Restart Dovecot"
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

        # ── webshell rule inputs ──────────────────────────────────────────
        # auditctl has no comm= filter, the exe= field of an execve event is
        # the NEW image, and a rule may carry only ONE exe filter. So:
        #  (A) a hosting account (uid>=1000) running anything outside a login /
        #      cron session (auid=unset) — i.e. spawned by the web server —
        #      except the PHP interpreter launch itself (suPHP/CGI do that
        #      on every request);
        #  (B) the web server user (nobody / www-data / apache) running
        #      anything except suPHP (or the PHP binary where there is no suPHP).
        WWWUSER=$(ps -eo user=,comm= 2>/dev/null | awk '$2 ~ /^(httpd|apache2|nginx|litespeed|lshttpd)$/ && $1 != "root" {print $1; exit}')
        WWWUID=$( { [ -n "$WWWUSER" ] && id -u "$WWWUSER" 2>/dev/null; } \
              || id -u www-data 2>/dev/null || id -u apache 2>/dev/null || id -u nobody 2>/dev/null || echo 65534)
        PHP_CGI=""; for b in /usr/local/bin/php-cgi /usr/bin/php-cgi /opt/alt/php*/usr/bin/php-cgi /usr/local/bin/php /usr/bin/php; do
            [ -x "$b" ] && { PHP_CGI=$(readlink -f "$b"); break; }; done
        SUPHP="";   for b in /usr/local/sbin/suphp /usr/sbin/suphp /usr/lib/apache2/suexec /usr/sbin/suexec; do
            [ -x "$b" ] && { SUPHP=$(readlink -f "$b"); break; }; done
        WEB_EXCL=${SUPHP:-$PHP_CGI}
        WEBSHELL_RULES="        -a always,exit -F arch=b64 -S execve -F auid=unset -F uid>=1000 -F uid!=${WWWUID}${PHP_CGI:+ -F exe!=$PHP_CGI} -k webshell
        -a always,exit -F arch=b64 -S execve -F auid=unset -F uid=${WWWUID}${WEB_EXCL:+ -F exe!=$WEB_EXCL} -k webshell
"

        # a b32 rule aborts the whole file on kernels without 32-bit compat
        # (aarch64, some cloud x86 builds) — probe first
        B32_RULE="        # (no 32-bit syscall ABI on this kernel)"
        if auditctl -a never,exit -F arch=b32 -S execve -F key=lg_probe >/dev/null 2>&1; then
            auditctl -d never,exit -F arch=b32 -S execve -F key=lg_probe >/dev/null 2>&1 || true
            B32_RULE="        -a always,exit -F arch=b32 -S execve -F dir=/tmp     -k tmp_exec"
        fi
        # PHP configuration lives in different places per distro; a watch on
        # a missing path fails the load at every boot
        PHP_CONF_RULES=""
        for _pc in /etc/php /etc/php.ini /etc/php.d /etc/php-fpm.d /usr/local/php/php.ini /usr/local/php/php.d /opt/alt /opt/cpanel/ea-php*/root/etc; do
            [ -e "$_pc" ] && PHP_CONF_RULES="${PHP_CONF_RULES}        -w ${_pc} -p wa -k php_config
"
        done
        [ -n "$PHP_CONF_RULES" ] || PHP_CONF_RULES="        # (no PHP configuration directory found)
"

        cat > "$AUDIT_RULES" << EOF
        ## Linux Guardian Audit Rules — ${TIMESTAMP}

        # Webshell execution — exec from writable dirs
        -a always,exit -F arch=b64 -S execve -F dir=/tmp     -k tmp_exec
${B32_RULE}
        -a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k tmp_exec

        # PHP/web spawning a process (webshell / RCE) — see "webshell rule
        # inputs" above. PHP mail() execs sendmail and will show up here too.
${WEBSHELL_RULES}

        # Critical file modifications
        -w /etc/passwd          -p wa -k passwd_change
        -w /etc/shadow          -p wa -k shadow_change
        -w /etc/sudoers         -p wa -k sudoers_change
        -w /etc/sudoers.d       -p wa -k sudoers_change
        -w /etc/ssh/sshd_config -p wa -k sshd_config
        -w /etc/crontab         -p wa -k cron_change
        -w /etc/cron.d          -p wa -k cron_change

        # Privilege escalation by a logged-in user (auid set). Without the
        # auid filter every setuid(2) by dbus/sshd/cron/suPHP fires an alert.
        -a always,exit -F arch=b64 -S setuid   -F auid>=1000 -F auid!=unset -k priv_esc
        -a always,exit -F arch=b64 -S setgid   -F auid>=1000 -F auid!=unset -k priv_esc
        -a always,exit -F arch=b64 -S setreuid -F auid>=1000 -F auid!=unset -k priv_esc

        # Exec from home directories
        -a always,exit -F arch=b64 -S execve -F dir=/home -k home_exec

        # PHP config changes
${PHP_CONF_RULES}
EOF
        chmod 640 "$AUDIT_RULES"
        echo "AUDITD_RULE:${AUDIT_RULES}" >> "$UNDO_MANIFEST"

        # ── Email alert script — triggered by audisp ──────────────────────────
        # auditd execs this path directly, so the shebang must be at column 0
        # (the heredoc body is deliberately NOT indented). auditd starts it once
        # and streams every event to stdin in "string" format, e.g.
        #   type=SYSCALL msg=audit(…): … pid=123 … comm="php-cgi" … key="webshell"
        # so it must loop for the lifetime of auditd — exiting makes auditd
        # disable the plugin. Emails are throttled per key (THROTTLE seconds);
        # every hit is still written to the log.
        AUDISP_ALERT="/etc/audit/lg-alert.sh"
        cat > "$AUDISP_ALERT" << ALERTEOF
#!/bin/bash
# Linux Guardian — auditd email alert (audisp plugin, format = string)
ALERT_EMAIL="${ALERT_EMAIL}"
LOG="${LOG_FILE}"
THROTTLE=300
STATE=/run/lg-alert; mkdir -p "\$STATE" 2>/dev/null
_ALERT_KEYS='webshell|tmp_exec|priv_esc|passwd_change|shadow_change|sudoers_change|home_exec'

while IFS= read -r LINE; do
    case "\$LINE" in *type=SYSCALL*) ;; *) continue ;; esac
    KEY=\$(printf '%s' "\$LINE" | sed -n 's/.* key="\([^"]*\)".*/\1/p')
    # several keys on one rule are hex-encoded, \001-separated
    [ -z "\$KEY" ] && KEY=\$(printf '%s' "\$LINE" | sed -n 's/.* key=\([0-9A-F][0-9A-F]*\).*/\1/p' | perl -pe 's/([0-9A-F]{2})/chr(hex(\$1))/ge' | tr '\001' ',')
    printf '%s' "\$KEY" | grep -qE "(^|,)(\$_ALERT_KEYS)(,|\$)" || continue
    TS=\$(date '+%Y-%m-%d %H:%M:%S')
    COMM=\$(printf '%s' "\$LINE" | sed -n 's/.* comm="\([^"]*\)".*/\1/p'); COMM=\${COMM:-unknown}
    PID=\$(printf '%s' "\$LINE" | sed -n 's/.* pid=\([0-9]*\).*/\1/p'); PID=\${PID:-?}
    # account maintenance run by root outside any login session (auid unset):
    # panel nightly jobs lock system users with passwd -l / usermod. Logged,
    # not mailed — a real intruder shows up first as webshell/priv_esc.
    EUID_=\$(printf '%s' "\$LINE" | sed -n 's/.* uid=\([^ ]*\).*/\1/p')
    AUID_=\$(printf '%s' "\$LINE" | sed -n 's/.* auid=\([^ ]*\).*/\1/p')
    case "\$COMM" in
        passwd|usermod|chpasswd|useradd|usermod|groupmod|chage|pwconv|grpconv)
            if [ "\$EUID_" = 0 ] && { [ "\$AUID_" = 4294967295 ] || [ "\$AUID_" = -1 ] || [ "\$AUID_" = unset ]; }; then
                echo "\$TS [INFO] \$KEY — \$COMM (PID \$PID) root maintenance, no mail" >> "\$LOG"
                continue
            fi ;;
    esac
    echo "\$TS [ALERT] \$KEY — \$COMM (PID \$PID)" >> "\$LOG"
    STAMP="\$STATE/\$(printf '%s' "\$KEY" | tr -c 'A-Za-z0-9_,' '_')"
    NOW=\$(date +%s); LAST=\$(cat "\$STAMP" 2>/dev/null || echo 0)
    [ \$(( NOW - LAST )) -ge "\$THROTTLE" ] || continue
    echo "\$NOW" > "\$STAMP"
    printf 'Linux Guardian Security Alert\n\nHost:    %s\nTime:    %s\nKey:     %s\nProcess: %s (PID %s)\n\nRaw event:\n%s\n\nLog: %s\n' \\
        "\$(hostname)" "\$TS" "\$KEY" "\$COMM" "\$PID" "\$LINE" "\$LOG" \\
        | mail -s "[LG ALERT] \$KEY detected on \$(hostname)" "\$ALERT_EMAIL" 2>/dev/null
done
exit 0
ALERTEOF
        chmod 750 "$AUDISP_ALERT"
        echo "AUDITD_RULE:${AUDISP_ALERT}" >> "$UNDO_MANIFEST"
        log_ok "Alert script: ${AUDISP_ALERT}  (email: ${ALERT_EMAIL})"

        # SELinux: auditd (auditd_t) can only launch plugins labelled
        # audisp_exec_t; with the default /etc/audit label the plugin is
        # killed at start ("plugin ... terminated unexpectedly", 10x, then
        # disabled). Persist the label so restorecon/relabels keep it.
        if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
            if command -v semanage >/dev/null 2>&1; then
                semanage fcontext -a -t audisp_exec_t "${AUDISP_ALERT//./\\.}" 2>/dev/null \
                  || semanage fcontext -m -t audisp_exec_t "${AUDISP_ALERT//./\\.}" 2>/dev/null || true
                restorecon "$AUDISP_ALERT" 2>/dev/null || true
            else
                chcon -t audisp_exec_t "$AUDISP_ALERT" 2>/dev/null || true
            fi
            log_ok "SELinux label: $(ls -Z "$AUDISP_ALERT" 2>/dev/null | awk '{print $1}' | cut -d: -f3)"

            # The stock policy lets auditd_t *execute* an audisp_exec_t file but
            # does not let the resulting audisp_t process *read* it — and a
            # shell script must be read by its interpreter (bash exits 126,
            # auditd logs "terminated unexpectedly" and disables the plugin).
            # One allow rule, shipped as a tiny policy module.
            if command -v semodule >/dev/null 2>&1; then
                command -v checkmodule >/dev/null 2>&1 || { command -v dnf >/dev/null 2>&1 && dnf -q -y install checkpolicy >/dev/null 2>&1; } || true
                if command -v checkmodule >/dev/null 2>&1; then
                    _SPD=$(mktemp -d /tmp/lg-audisp.XXXXXX)
                    cat > "$_SPD/lg-audisp.te" << SEEOF
module lg-audisp 1.3;
require {
    type audisp_t;
    type audisp_exec_t;
    type auditd_etc_t;
    type hostname_exec_t;
    type postfix_etc_t;
    type postfix_postdrop_exec_t;
    type postfix_public_t;
    type postfix_spool_t;
    type sendmail_exec_t;
    type tmp_t;
    type var_log_t;
    type var_run_t;
    class capability setgid;
    class dir { add_name remove_name write search getattr };
    class fifo_file { getattr open write };
    class file { create execute execute_no_trans getattr open read rename setattr unlink write };
}
# read its own script (the interpreter must open it) and traverse /etc/audit
allow audisp_t audisp_exec_t:file { read open getattr };
allow audisp_t auditd_etc_t:dir { search getattr };
# hostname(1) in the mail subject
allow audisp_t hostname_exec_t:file { execute execute_no_trans getattr open read };
# append to the hardening log and keep per-key throttle stamps under /run
allow audisp_t var_log_t:file open;
allow audisp_t var_run_t:file { create open read write };
# mail(1) -> sendmail -> postdrop (postfix); mail(1) also uses a temp file
allow audisp_t sendmail_exec_t:file { execute execute_no_trans open read };
allow audisp_t postfix_etc_t:file { getattr open read };
allow audisp_t postfix_postdrop_exec_t:file { execute execute_no_trans open read };
allow audisp_t postfix_public_t:fifo_file { getattr open write };
allow audisp_t postfix_spool_t:dir { add_name remove_name write };
allow audisp_t postfix_spool_t:file { create getattr open read rename setattr write };
allow audisp_t self:capability setgid;
allow audisp_t tmp_t:dir { add_name remove_name write };
allow audisp_t tmp_t:file { create setattr unlink };
SEEOF
                    if checkmodule -M -m -o "$_SPD/lg-audisp.mod" "$_SPD/lg-audisp.te" >/dev/null 2>&1 \
                       && semodule_package -o "$_SPD/lg-audisp.pp" -m "$_SPD/lg-audisp.mod" >/dev/null 2>&1 \
                       && semodule -i "$_SPD/lg-audisp.pp" >/dev/null 2>&1; then
                        log_ok "SELinux module lg-audisp installed (audisp_t may read the plugin)"
                        echo "SELINUX_MODULE:lg-audisp" >> "$UNDO_MANIFEST"
                    else
                        log_warn "could not build/install the lg-audisp policy module — the alert plugin will NOT start under SELinux enforcing"
                    fi
                    rm -rf "$_SPD"
                else
                    log_warn "checkmodule unavailable — alert plugin needs: allow audisp_t audisp_exec_t:file { read open getattr }"
                fi
            fi
        fi

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
format = string
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
        # FIX: was calling clamdscan up to 3 times on the same file.
        # Now scans once, captures output to a temp variable, then alerts/removes.
        cat > /etc/pure-ftpd/clamav_check.sh << CLAMAVEOF
#!/bin/bash
# Linux Guardian — ClamAV upload scanner
MAXSIZE=10485760
ALERT="${ALERT_EMAIL}"
[ -z "\$1" ] || [ ! -f "\$1" ] && exit 0
if [ "\${UPLOAD_SIZE:-0}" -le "\$MAXSIZE" ] && command -v clamdscan &>/dev/null; then
    # Single scan, capture full output once
    RESULT=\$(clamdscan --fdpass --no-summary --infected "\$1" 2>/dev/null)
    if printf '%s' "\$RESULT" | grep -q FOUND; then
        rm -f "\$1" 2>/dev/null
        printf "Infected upload removed:\n%s\n" "\$RESULT" \
            | mail -s "[LG] Infected Upload" "\$ALERT"
    fi
fi
CLAMAVEOF
        chmod 750 /etc/pure-ftpd/clamav_check.sh
        log_ok "ClamAV scanner: /etc/pure-ftpd/clamav_check.sh"

        # run the upload-script daemon as a service so it survives reboots
        # (CallUploadScript stays on in the config; without the daemon uploads
        # would queue to a dead socket)
        _UPS=$(command -v pure-uploadscript || echo /usr/sbin/pure-uploadscript)
        if [ -x "$_UPS" ] && [ -d /etc/systemd/system ]; then
            cat > /etc/systemd/system/lg-uploadscript.service << UPSEOF
[Unit]
Description=Linux Guardian — Pure-FTPd upload scanner (ClamAV)
After=pure-ftpd.service pure-ftpd-mysql.service clamd.service clamav-daemon.service
[Service]
Type=simple
ExecStart=${_UPS} -r /etc/pure-ftpd/clamav_check.sh
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
UPSEOF
            pkill -f pure-uploadscript 2>/dev/null || true
            systemctl daemon-reload 2>/dev/null || true
            systemctl enable --now lg-uploadscript.service 2>/dev/null \
                && log_ok "pure-uploadscript running as lg-uploadscript.service" \
                || log_warn "lg-uploadscript.service failed to start — ensure Pure-FTPd is running"
            echo "RMFILE:/etc/systemd/system/lg-uploadscript.service" >> "$UNDO_MANIFEST"
        else
            pkill -f pure-uploadscript 2>/dev/null || true
            "$_UPS" -B -r /etc/pure-ftpd/clamav_check.sh 2>/dev/null \
                && log_ok "pure-uploadscript started" \
                || log_warn "pure-uploadscript failed — ensure Pure-FTPd is running"
        fi

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

    # cookie encryption and unserialize HMAC refuse to start without a
    # secret key — and a missing key means PHP itself refuses to start
    if [ -f "$SNUFF_RULES" ] && grep -q '^sp.global.secret_key' "$SNUFF_RULES"; then
        SNUFF_KEY=$(grep -m1 '^sp.global.secret_key' "$SNUFF_RULES" | grep -oE '[0-9a-f]{32,}')
    fi
    [ -n "${SNUFF_KEY:-}" ] || SNUFF_KEY=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    backup_file "$SNUFF_RULES" "snuffleupagus"
    {
        printf '# Linux Guardian — Snuffleupagus rules (shared — all sites) — %s\n' "$TIMESTAMP"
        printf 'sp.global.secret_key("%s");\n' "$SNUFF_KEY"
        # the cookie-encryption key is derived from the secret + a request
        # variable; the User-Agent survives IP changes (mobile users), the
        # remote address does not
        printf 'sp.global.cookie_env_var("HTTP_USER_AGENT");\n'
        cat << 'RULESEOF'

# ── Dangerous execution functions ─────────────────────────────────────────────
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

# ── eval() is a language construct, not a hookable function: block the
#    dangerous functions INSIDE eval'd code instead
sp.eval_blacklist.list("system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec,assert,create_function");

# ── Uploads: PHP source must never be written by move_uploaded_file()
#    (positional parameter — PHP 8 renamed it, names no longer match)
sp.disable_function.function("move_uploaded_file").pos("1").value_r("\\.ph(p[0-9]?|tml|ar|t)$").drop();
sp.disable_function.function("move_uploaded_file").pos("1").value_r("\\.ht").drop();

# ── Cookies: the session cookie is encrypted (a stolen PHPSESSID is useless
#    elsewhere); every cookie gets SameSite=Lax (Strict breaks OAuth and
#    payment-gateway returns) and Secure on HTTPS. HttpOnly is set in php.ini.
sp.cookie.name("PHPSESSID").encrypt();
sp.cookie.name_r(".*").samesite("Lax");
sp.auto_cookie_secure.enable();

# ── XXE protection
sp.xxe_protection.enable();

# ── Unserialize HMAC — object injection
sp.unserialize_hmac.enable();

# ── Strict types for every file is opt-in: it breaks legacy sites
# sp.global_strict.enable();
RULESEOF
    } > "$SNUFF_RULES"

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
# PART C — php2shell (CVE-2026-109618 / CVE-2026-109619)
# Every PHP executable on the host (panel-private ones included), fixed-version
# check with vendor-backport awareness, interim mitigation. Helpers above.
# ══════════════════════════════════════════════════════════════════════════════
section "PART C: php2shell — CVE-2026-109618 / CVE-2026-109619"

_lg_php2shell || log_warn "Part C: php2shell check encountered an issue — check log for details"

log_ok "Part C complete"

# ══════════════════════════════════════════════════════════════════════════════
# PART D — Recent critical CVEs (report only). Helpers above.
# ══════════════════════════════════════════════════════════════════════════════
section "PART D: Recent critical CVEs — Snuffleupagus, Roundcube, kernel, updates, CWP"

_lg_cves || log_warn "Part D: CVE check encountered an issue — check log for details"

log_ok "Part D complete"

# ── Save state file (marks first run complete — triggers status on next run) ──
if [ "$DRY_RUN" = false ]; then
    mkdir -p "$(dirname "$LG_STATE_FILE")" 2>/dev/null || true
    date '+%Y-%m-%d %H:%M:%S' > "$LG_STATE_FILE"
    chmod 600 "$LG_STATE_FILE"
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
    echo "  [4.1] Apache httpd        — ServerTokens Prod, ServerSignature Off"
    echo "  [4.2] MySQL/MariaDB       — bound to 127.0.0.1"
    echo "  [5] PHP disable_functions — shell_exec/exec disabled"
    echo "  [6] noexec /tmp           — uploaded binaries won't execute"
    echo "  [7] ${MAC_SYSTEM^^} (MAC)           — web exec policy enforced"
    echo "  [8] Auditd                — monitoring active"
    echo "  [A] FTP + ClamAV          — $(svc_installed clamscan clamdscan && svc_installed pure-ftpd pure-ftpd-mysql && echo 'upload scanning enabled' || echo 'not installed (skipped)')"
    echo "  [B] Snuffleupagus         — $(php -m 2>/dev/null | grep -qi snuffleupagus && echo 'PHP RASP layer active' || echo 'not installed (skipped)')"
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
# Only runs if --reboot was explicitly passed. NEVER auto-reboots.
# ══════════════════════════════════════════════════════════════════════════════
if [ "$REBOOT_MODE" = true ] && [ "$DRY_RUN" = false ]; then
    _REBOOT_DELAY="${LG_REBOOT_DELAY:-10}"
    echo -e "${BOLD}${YELLOW}"
    echo "════════════════════════════════════════════════════════════════════"
    echo "  SERVER WILL REBOOT IN ${_REBOOT_DELAY} SECONDS TO APPLY SELinux RELABEL"
    echo "  Press Ctrl+C to cancel (or set LG_REBOOT_DELAY=0 to skip countdown)"
    echo "════════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    sleep "$_REBOOT_DELAY"
    reboot
fi
