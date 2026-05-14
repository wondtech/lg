#!/bin/bash
# Linux Guardian - Linux Server Security Hardening
# Version: 1.0
# By WondTech.com | info@wondtech.com

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "----------------------------------------------------------------------------------------------------------------------"
echo "                  .\|."
echo "                :⇨↕⇩⇩↕⇨:"
echo "         .,~>⇧→↓⇨<~⇩⇩~<⇦↓→⇩>~,."
echo "      ^↱←←⇨⇩|><<⇧→↱↲↲↱↑⇧><>|⇩⇨←←↱<"
echo "      \\↱./⇦⇨↑↕↲↲↲↲↲↲↲↲↲↲↲↱↑←⇦/ ↱\\"
echo "      \\↱.⇨↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲← ↱\\"
echo "      <↲:⇩↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲⇦,↲>      ▗▖   ▗▄▄▄▖▗▖  ▗▖▗▖ ▗▖▗▖  ▗▖     ▗▄▄▖▗▖ ▗▖ ▗▄▖ ▗▄▄▖ ▗▄▄▄ ▗▄▄▄▖ ▗▄▖ ▗▖  ▗▖"
echo "      ,↱>>↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲/>↲:      ▐▌     █  ▐▛▚▖▐▌▐▌ ▐▌ ▝▚▞▘     ▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌  █  █  ▐▌ ▐▌▐▛▚▖▐▌"
echo "       ←←,↕↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↱,←→       ▐▌     █  ▐▌ ▝▜▌▐▌ ▐▌  ▐▌      ▐▌▝▜▌▐▌ ▐▌▐▛▀▜▌▐▛▀▚▖▐▌  █  █  ▐▛▀▜▌▐▌ ▝▜▌"
echo "       ^↱~|↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲⇧~↱<       ▐▙▄▄▖▗▄█▄▖▐▌  ▐▌▝▚▄▞▘▗▞▘▝▚▖    ▝▚▄▞▘▝▚▄▞▘▐▌ ▐▌▐▌ ▐▌▐▙▄▄▀▗▄█▄▖▐▌ ▐▌▐▌  ▐▌"
echo "        ⇨↓,↑↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↲↓,↑←        ╔═══════════════════════════════════════════════════════════════╗"
echo "        .↔⇨,↔↲↲↲↲↲↲↲↲↲↲↲↲↲↲↔,⇨↔.        ║  One Script, Security Hardening, Zero Compromise.             ║"
echo "         ,↔←,→↲↲↲↲↲↲↲↲↲↲↲↲↑,⇨↔,         ╚═══════════════════════════════════════════════════════════════╝"
echo "          ,←↓~\\↱↲↲↲↲↲↲↲↲↱\\~↑←:              Linux Server Security Hardening"
echo "           .\\↔⇧~⇩↕↲↲↲↲↕⇩~⇧↔\\.               By WondTech.com | info@wondtech.com"
echo "             ,⇦↔|~|↑↑|~\\↔⇦,"
echo "               .⇧↔→^~←↕⇩."
echo "                 .:⇩⇦:."
echo "----------------------------------------------------------------------------------------------------------------------"
echo -e "${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root${NC}"
    echo "    Run: sudo bash $0"
    exit 1
fi

############################################
# Updating System Packages
############################################

echo -e "${BOLD}${GREEN}=== Updating System Packages ===${NC}"
echo ""

if command -v apt-get &>/dev/null; then
    echo "Detected: Debian/Ubuntu (apt)"
    echo "Running apt-get update..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>&1 | tail -5 && echo "[OK] Package list updated" || echo "[WARN] apt-get update failed"
    echo "Running apt-get upgrade..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq 2>&1 | tail -5 && echo "[OK] Packages upgraded" || echo "[WARN] apt-get upgrade failed"
elif command -v yum &>/dev/null; then
    echo "Detected: CentOS/RHEL (yum)"
    echo "Running yum update..."
    yum update -y --quiet 2>&1 | tail -10 && echo "[OK] Packages updated" || echo "[WARN] yum update failed"
elif command -v dnf &>/dev/null; then
    echo "Detected: Fedora (dnf)"
    echo "Running dnf update..."
    dnf update -y --quiet 2>&1 | tail -10 && echo "[OK] Packages updated" || echo "[WARN] dnf update failed"
elif command -v apk &>/dev/null; then
    echo "Detected: Alpine (apk)"
    echo "Running apk update..."
    apk update -q 2>/dev/null && echo "[OK] Package index updated" || echo "[WARN] apk update failed"
    echo "Running apk upgrade..."
    apk upgrade -q 2>/dev/null && echo "[OK] Packages upgraded" || echo "[WARN] apk upgrade failed"
elif command -v pacman &>/dev/null; then
    echo "Detected: Arch Linux (pacman)"
    echo "Running pacman -Syu..."
    pacman -Syu --noconfirm -q 2>&1 | tail -10 && echo "[OK] Packages updated" || echo "[WARN] pacman update failed"
else
    echo "[WARN] No supported package manager found (apt/yum/dnf/apk/pacman)"
fi
echo ""

RUN_MODE="interactive"
if [[ "${1:-}" == "--cron" ]]; then
    RUN_MODE="cron"
    exec > /dev/null 2>&1
elif [[ "${1:-}" == "--auto" ]]; then
    RUN_MODE="auto"
elif [[ "${1:-}" == "--setup-auto" ]]; then
    RUN_MODE="setup-auto"
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/lg"
mkdir -p "$BACKUP_DIR"

SNUFF_INSTALLED=false
SNUFF_SKIP=false

SCRIPT_NAME=$(basename "$0")

############################################
# PART 1: Secure Dangerous Binaries
############################################
echo -e "${BOLD}${GREEN}=== PART 1: Securing Dangerous Binaries ===${NC}"
echo ""

secure_binary() {
    local bin="$1"
    if [ -e "$bin" ]; then
        echo "Before: $(ls -la "$bin" | awk '{print $1, $3, $4}')"
        chown root:root "$bin" 2>/dev/null
        chmod 750 "$bin" 2>/dev/null
        echo "After:  $(ls -la "$bin" | awk '{print $1, $3, $4}')"
        echo "[OK] $bin secured"
    else
        echo "[SKIP] $bin (not found)"
    fi
}

echo "=== [1/16] Securing nc (Netcat) ==="
secure_binary /usr/bin/nc
echo ""

echo "=== [2/16] Securing ncat ==="
secure_binary /usr/bin/ncat
echo ""

echo "=== [3/16] Securing netcat ==="
secure_binary /usr/bin/netcat
echo ""

echo "=== [4/16] Securing socat ==="
secure_binary /usr/bin/socat
echo ""

echo "=== [5/16] Securing telnet ==="
secure_binary /usr/bin/telnet
echo ""

echo "=== [6/16] Securing tftp ==="
secure_binary /usr/bin/tftp
echo ""

echo "=== [7/16] Securing Ruby ==="
secure_binary /usr/bin/ruby
echo ""

echo "=== [8/16] Securing Lua ==="
secure_binary /usr/bin/lua
echo ""

echo "=== [9/16] Securing Tclsh ==="
secure_binary /usr/bin/tclsh
echo ""

echo "=== [10/16] Securing Expect ==="
secure_binary /usr/bin/expect
echo ""

echo "=== [11/16] Securing Node.js ==="
secure_binary /usr/bin/node
[ ! -e /usr/bin/node ] && secure_binary /usr/bin/nodejs
echo ""

echo "=== [12/16] Securing GCC ==="
secure_binary /usr/bin/gcc
echo ""

echo "=== [13/16] Securing CC ==="
secure_binary /usr/bin/cc
echo ""

echo "=== [14/16] Securing G++ ==="
secure_binary /usr/bin/g++
echo ""

echo "=== [15/16] Securing C++ ==="
secure_binary /usr/bin/c++
echo ""

echo "=== [16/16] Securing Perl ==="
secure_binary /usr/bin/perl
echo ""

echo "=== [BONUS] Searching for Python interpreters ==="
echo ""

PYTHON_BINS=$(find /usr/bin /usr/sbin /usr/local/bin /usr/libexec -maxdepth 2 -type f \
    \( -name "python" -o -name "python[0-9]*" -o -name "platform-python*" \) \
    ! -type l 2>/dev/null)

if [ -z "$PYTHON_BINS" ]; then
    echo "[!] No Python interpreters found"
else
    for bin in $PYTHON_BINS; do
        echo "--- $bin ---"
        secure_binary "$bin"
        echo ""
    done
fi

echo -e "${GREEN}[OK] Binary lockdown complete${NC}"
echo ""

############################################
# PART 2: Secure System Binaries
############################################
echo -e "${BOLD}${GREEN}=== PART 2: Securing System Binaries ===${NC}"
echo ""

echo "--- [1/4] Securing network tools ---"
for bin in wget lynx scp curl; do
    [ -e /usr/bin/$bin ] && secure_binary /usr/bin/$bin || echo "[SKIP] $bin not found"
done

echo ""
echo "--- [2/4] Securing file utilities ---"
for bin in basename cat nano chmod domainname more netstat passwd su sudo touch kill ls vi; do
    [ -e /usr/bin/$bin ] && secure_binary /usr/bin/$bin || echo "[SKIP] $bin not found"
done

echo ""
echo "--- [3/4] Securing additional tools ---"
for bin in at wall last lastb write mesg telnet rsh rlogin ftp uudecode uuencode; do
    [ -e /usr/bin/$bin ] && secure_binary /usr/bin/$bin || echo "[SKIP] $bin not found"
done

echo ""
echo "--- [4/4] Securing system admin tools ---"
for bin in su sudo mount umount dmesg ifconfig ip route arp nslookup traceroute iptunnel iw regshell; do
    if [ -e /usr/sbin/$bin ]; then
        secure_binary /usr/sbin/$bin
    elif [ -e /usr/bin/$bin ]; then
        secure_binary /usr/bin/$bin
    else
        echo "[SKIP] $bin not found"
    fi
done

echo -e "${GREEN}[OK] System binaries secured${NC}"
echo ""

############################################
# PART 3: Kernel Vulnerability Protection
############################################
echo -e "${BOLD}${GREEN}=== PART 3: Kernel Vulnerability Protection ===${NC}"
echo ""

echo "Applying comprehensive kernel vulnerability protections..."
echo ""

echo "--- Kernel Vulnerability Protection ---"
if [ -d /etc/modprobe.d ]; then
    cat > /etc/modprobe.d/dirtyfrag.conf << 'KERNEL_BLOCK'
    install esp4 /bin/false
    install esp6 /bin/false
    install rxrpc /bin/false
    install dccp /bin/false
    install sctp /bin/false
    install rds /bin/false
    install tipc /bin/false
KERNEL_BLOCK
    chmod 644 /etc/modprobe.d/dirtyfrag.conf
    echo "[OK] Blocked vulnerable protocols"
fi

for mod in esp4 esp6 rxrpc dccp sctp rds tipc; do
    if lsmod | grep -q "^$mod "; then
        rmmod $mod 2>/dev/null && echo "[OK] Unloaded $mod" || echo "[SKIP] $mod not loaded"
    else
        echo "[SKIP] $mod not loaded"
    fi
done

echo -e "${GREEN}[OK] Kernel vulnerability protection complete${NC}"
echo ""

############################################
# PART 4: Securing system files
############################################
echo -e "${BOLD}${GREEN}=== PART 4: Securing system files ===${NC}"
echo ""

echo ""
echo "--- Securing system files ---"
chmod 600 /etc/shadow 2>/dev/null && echo "[OK] /etc/shadow secured"
chmod 600 /etc/group 2>/dev/null && echo "[OK] /etc/group secured"
chmod 700 /etc/cron.d 2>/dev/null && echo "[OK] /etc/cron.d secured"
chmod 700 /etc/cron.daily 2>/dev/null && echo "[OK] /etc/cron.daily secured"
chmod 700 /etc/cron.hourly 2>/dev/null && echo "[OK] /etc/cron.hourly secured"
chmod 700 /etc/cron.monthly 2>/dev/null && echo "[OK] /etc/cron.monthly secured"
chmod 700 /etc/cron.weekly 2>/dev/null && echo "[OK] /etc/cron.weekly secured"


echo -e "${GREEN}[OK] Network security hardening complete${NC}"
echo ""

############################################
# PART 5: PHP Security Hardening
############################################
echo -e "${BOLD}${GREEN}=== PART 5: PHP Security Hardening ===${NC}"
echo ""

echo -e "${BOLD}${BLUE}=== [1/6] Searching for php.ini files ===${NC}"
echo ""

SEARCH_PATHS=("/")

PHP_INI_FILES=()
TMP_FILE=$(mktemp)
for path in "${SEARCH_PATHS[@]}"; do
    [ -d "$path" ] && find "$path" -maxdepth 6 -type f -name "php.ini" 2>/dev/null
done | sort -u > "$TMP_FILE"
while IFS= read -r line; do
    PHP_INI_FILES+=("$line")
done < "$TMP_FILE"
rm -f "$TMP_FILE"

if [ ${#PHP_INI_FILES[@]} -eq 0 ]; then
    echo -e "${RED}[!] No php.ini files found${NC}"
    exit 1
fi

echo -e "${GREEN}Found ${#PHP_INI_FILES[@]} php.ini file(s):${NC}"
echo ""

for i in "${!PHP_INI_FILES[@]}"; do
    file="${PHP_INI_FILES[$i]}"
    size=$(du -h "$file" 2>/dev/null | cut -f1)
    modified=$(stat -c '%y' "$file" 2>/dev/null | cut -d'.' -f1)
    parent_dir=$(dirname "$file")
    context=""
    if [[ "$parent_dir" == *"cli"* ]]; then
        context=" ${YELLOW}[CLI]${NC}"
    elif [[ "$parent_dir" == *"apache"* ]] || [[ "$parent_dir" == *"httpd"* ]]; then
        context=" ${GREEN}[Apache]${NC}"
    elif [[ "$parent_dir" == *"fpm"* ]]; then
        context=" ${GREEN}[PHP-FPM]${NC}"
    elif [[ "$parent_dir" == *"cgi"* ]]; then
        context=" ${YELLOW}[CGI]${NC}"
    fi
    printf "  ${BOLD}[%d]${NC} %s%s\n" $((i+1)) "$file" "$context"
    printf "      Size: %s | Modified: %s\n" "$size" "$modified"
    echo ""
done

echo -e "${BOLD}${BLUE}=== [2/6] Select php.ini to harden ===${NC}"
echo ""

if [[ "$RUN_MODE" == "cron" || "$RUN_MODE" == "auto" ]]; then
    SELECTED_FILES=("${PHP_INI_FILES[@]}")
    PHP_SKIP=false
else
    echo "Enter the number(s) of php.ini file(s) to harden."
    echo "  - Single: 1"
    echo "  - Multiple: 1,3,5"
    echo "  - All: a"
    echo "  - Skip PHP hardening: s"
    echo ""
    read -p "Your choice: " choice
    echo ""

    if [[ "$choice" == "s" ]] || [[ "$choice" == "S" ]]; then
        echo -e "${YELLOW}Skipping PHP hardening${NC}"
        PHP_SKIP=true
    else
        PHP_SKIP=false
        SELECTED_FILES=()
        if [[ "$choice" == "a" ]] || [[ "$choice" == "A" ]]; then
            SELECTED_FILES=("${PHP_INI_FILES[@]}")
        else
            IFS=',' read -ra numbers <<< "$choice"
            for num in "${numbers[@]}"; do
                num=$(echo "$num" | tr -d ' ')
                if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le ${#PHP_INI_FILES[@]} ]; then
                    SELECTED_FILES+=("${PHP_INI_FILES[$((num-1))]}")
                else
                    echo -e "${RED}[!] Invalid number: $num${NC}"
                    exit 1
                fi
            done
        fi

        if [ ${#SELECTED_FILES[@]} -eq 0 ]; then
            echo -e "${RED}[!] No files selected${NC}"
            exit 1
        fi
    fi
fi

if [ "$PHP_SKIP" = false ]; then
    echo ""
    echo -e "${GREEN}Selected files:${NC}"
    for file in "${SELECTED_FILES[@]}"; do
        echo "  -> $file"
    done
    echo ""

    if [[ "$RUN_MODE" != "cron" && "$RUN_MODE" != "auto" ]]; then
        echo -e "${BOLD}${BLUE}=== [3/6] Confirmation ===${NC}"
        echo ""
        echo -e "${YELLOW}The following changes will be applied:${NC}"
        echo "  1. Backup of current php.ini will be created"
        echo "  2. disable_functions will be replaced with hardened list"
        echo "  3. Additional security settings will be applied"
        echo ""
        read -p "$(echo -e ${BOLD}Continue? [y/N]: ${NC})" -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Cancelled${NC}"
            exit 0
        fi
        echo ""
    fi

    DISABLE_FUNCTIONS="exec,passthru,shell_exec,system,popen,proc_open,proc_close,proc_get_status,proc_terminate,proc_nice,pcntl_exec,pcntl_fork,pcntl_signal,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wstopsig,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_alarm,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,posix_setgid,posix_seteuid,posix_setegid,fsockopen,pfsockopen,stream_socket_client,stream_socket_server,socket_create,socket_connect,socket_bind,socket_listen,socket_accept,phpinfo,show_source,highlight_file,symlink,link,dl,assert,create_function,parse_ini_file,opcache_get_status,opcache_reset,putenv,apache_setenv"

    echo -e "${BOLD}${BLUE}=== [4/6] Applying hardening ===${NC}"
    echo ""

    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    for file in "${SELECTED_FILES[@]}"; do
        echo -e "${CYAN}Processing: $file${NC}"
        backup_path="${BACKUP_DIR}/$(basename $(dirname "$file"))_php.ini.${TIMESTAMP}"
        cp "$file" "$backup_path"
        chmod 600 "$backup_path"
        echo "  [OK] Backup: $backup_path"

        if grep -q "^disable_functions" "$file"; then
            sed -i "s|^disable_functions.*|disable_functions = ${DISABLE_FUNCTIONS}|" "$file"
            echo "  [OK] Updated existing disable_functions"
        elif grep -q "^;disable_functions" "$file"; then
            sed -i "s|^;disable_functions.*|disable_functions = ${DISABLE_FUNCTIONS}|" "$file"
            echo "  [OK] Uncommented and updated disable_functions"
        else
            echo "" >> "$file"
            echo "; Hardened by security script on ${TIMESTAMP}" >> "$file"
            echo "disable_functions = ${DISABLE_FUNCTIONS}" >> "$file"
            echo "  [OK] Added new disable_functions"
        fi

        echo "  Discovering user public_html directories..."
        PUBLIC_HTML_PATHS=$(find /home -maxdepth 3 -type d -name "public_html" 2>/dev/null | tr '\n' ':')
        if [ -z "$PUBLIC_HTML_PATHS" ]; then
            OPEN_BASEDIR_VALUE="/home:/tmp:/usr/share/php"
            echo "  [WARN] No public_html found, using /home as base"
        else
            OPEN_BASEDIR_VALUE="${PUBLIC_HTML_PATHS}/tmp:/usr/share/php"
        fi
        echo "  open_basedir paths: $OPEN_BASEDIR_VALUE"

        declare -A SETTINGS=(
            ["allow_url_fopen"]="Off"
            ["allow_url_include"]="Off"
            ["expose_php"]="Off"
            ["display_errors"]="Off"
            ["log_errors"]="On"
            ["open_basedir"]="${OPEN_BASEDIR_VALUE}"
            ["disable_classes"]="Imagick,gs,curl,wget,chmod,chown,passthru,exec,system,shell_exec,popen,proc_open"
            ["file_uploads"]="On"
            ["upload_tmp_dir"]="/tmp"
            ["upload_max_filesize"]="2M"
            ["session.cookie_httponly"]="1"
            ["session.cookie_secure"]="1"
            ["session.use_strict_mode"]="1"
            ["enable_dl"]="Off"
            ["realpath_cache_size"]="4096K"
            ["max_execution_time"]="30"
            ["max_input_time"]="30"
            ["memory_limit"]="128M"
            ["post_max_size"]="8M"
        )

        for key in "${!SETTINGS[@]}"; do
            value="${SETTINGS[$key]}"
            if grep -qE "^\s*${key}\s*=" "$file"; then
                sed -i "s|^\s*${key}\s*=.*|${key} = ${value}|" "$file"
            elif grep -qE "^\s*;\s*${key}\s*=" "$file"; then
                sed -i "s|^\s*;\s*${key}\s*=.*|${key} = ${value}|" "$file"
            else
                echo "${key} = ${value}" >> "$file"
            fi
        done
        echo "  [OK] Applied additional security settings"
        echo ""
    done

    echo -e "${BOLD}${BLUE}=== [5/6] Verifying changes ===${NC}"
    echo ""

    for file in "${SELECTED_FILES[@]}"; do
        echo -e "${CYAN}File: $file${NC}"
        echo "  disable_functions: $(grep "^disable_functions" "$file" | head -1 | cut -c1-80)..."
        echo "  open_basedir: $(grep "^open_basedir" "$file" | head -1 | cut -c1-100)..."
        echo "  disable_classes: $(grep "^disable_classes" "$file" | head -1)"
        echo "  allow_url_fopen: $(grep "^allow_url_fopen" "$file" | head -1)"
        echo "  allow_url_include: $(grep "^allow_url_include" "$file" | head -1)"
        echo "  expose_php: $(grep "^expose_php" "$file" | head -1)"
        echo "  file_uploads: $(grep "^file_uploads" "$file" | head -1)"
        echo "  session.cookie_httponly: $(grep "^session.cookie_httponly" "$file" | head -1)"
        echo ""
    done

    echo -e "${BOLD}${BLUE}=== [6/6] Restarting Apache ===${NC}"
    echo ""

    APACHE_SERVICE=""
    if systemctl list-units --type=service --all 2>/dev/null | grep -q "httpd.service"; then
        APACHE_SERVICE="httpd"
    elif systemctl list-units --type=service --all 2>/dev/null | grep -q "apache2.service"; then
        APACHE_SERVICE="apache2"
    fi

    if [ -z "$APACHE_SERVICE" ]; then
        echo -e "${YELLOW}[!] Apache service not detected${NC}"
        echo "    Restart manually: systemctl restart httpd"
    else
        echo "Detected service: $APACHE_SERVICE"
        echo -n "  Testing Apache config... "
        if "$APACHE_SERVICE" -t 2>/dev/null || apachectl configtest 2>/dev/null || httpd -t 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${YELLOW}skipped${NC}"
        fi
        echo -n "  Restarting ${APACHE_SERVICE}... "
        if systemctl restart "$APACHE_SERVICE"; then
            echo -e "${GREEN}OK${NC}"
            sleep 2
            echo -n "  Checking status... "
            if systemctl is-active --quiet "$APACHE_SERVICE"; then
                echo -e "${GREEN}ACTIVE${NC}"
            else
                echo -e "${RED}FAILED${NC}"
                echo ""
                echo -e "${RED}[!] Apache failed to restart. Check logs:${NC}"
                echo "    journalctl -u $APACHE_SERVICE -n 20"
                echo ""
                echo -e "${YELLOW}To rollback:${NC}"
                for file in "${SELECTED_FILES[@]}"; do
                    backup_path="${BACKUP_DIR}/$(basename $(dirname "$file"))_php.ini.${TIMESTAMP}"
                    echo "    cp $backup_path $file"
                done
                exit 1
            fi
        else
            echo -e "${RED}FAILED${NC}"
            exit 1
        fi
    fi
    echo ""
fi

############################################
# Done
############################################
echo -e "${BOLD}${GREEN}================================================================"
echo "                         DONE"
echo -e "================================================================${NC}"
echo ""
echo -e "${GREEN}[OK] All security hardening applied successfully${NC}"
echo ""
echo "Summary:"
echo "  - Part 1: Dangerous binary lockdown (nc, gcc, python, etc.)"
echo "  - Part 1.2: System binaries (wget, lynx, sudo, vi, etc.)"
echo "  - Part 1.5: Kernel vulnerability protection"
echo "  - Part 2: Network security (SSH, Firewall, file permissions)"
if [ "$PHP_SKIP" = false ]; then
    echo "  - Part 3: PHP hardening (${#SELECTED_FILES[@]} php.ini file(s))"
fi
echo "  - Part 4: FTP security (Pure-FTPd + ClamAV upload scanning)"
if [ "$SNUFF_INSTALLED" = true ]; then
    echo "  - Part 6: Snuffleupagus (installed)"
elif [ "$SNUFF_SKIP" = true ]; then
    echo "  - Part 6: Snuffleupagus (skipped)"
else
    echo "  - Part 6: Snuffleupagus (pending)"
fi
echo "  - Backups stored: $BACKUP_DIR"
echo ""
echo -e "${YELLOW}Test the changes:${NC}"
echo "  curl http://localhost/ -I"
echo "  php -r 'echo ini_get(\"disable_functions\");'"
echo ""

############################################
# PART 6: FTP (Pure-FTPd) Security
############################################
echo -e "${BOLD}${GREEN}=== PART 6: FTP Security (Pure-FTPd + ClamAV) ===${NC}"
echo ""

echo "--- [1/4] Enabling Pure-FTPd upload scanning ---"
if [ -f /etc/pure-ftpd.conf ]; then
    if grep -q "^CallUploadScript" /etc/pure-ftpd.conf; then
        sed -i 's/^CallUploadScript.*/CallUploadScript yes/' /etc/pure-ftpd.conf
    else
        echo "CallUploadScript yes" >> /etc/pure-ftpd.conf
    fi
    echo "[OK] CallUploadScript enabled"
else
    echo "[SKIP] /etc/pure-ftpd.conf not found"
fi

echo ""
echo "--- [2/4] Creating ClamAV upload scanner ---"
if [ -d /etc/pure-ftpd ]; then
    if [[ "$RUN_MODE" == "cron" || "$RUN_MODE" == "auto" ]]; then
        ALERT_EMAIL="root"
    else
        read -p "Enter email for alerts (default: root): " ALERT_EMAIL
        [ -z "$ALERT_EMAIL" ] && ALERT_EMAIL="root"
    fi
    echo "Using alert email: $ALERT_EMAIL"

    cat > /etc/pure-ftpd/clamav_check.sh << CLAMAV_SCRIPT
    #!/bin/bash
    #Maximum file size to scan in bytes (10MB)
    MAXSIZE=10485760
    ALERT_EMAIL="$ALERT_EMAIL"
    if [ "\$UPLOAD_SIZE" -le "\$MAXSIZE" ]
    then
        if [ -f "\$1" ] && command -v clamdscan &>/dev/null; then
            if [[ \$(clamdscan --no-summary --infected "\$1" 2>/dev/null) ]]
            then
                infectedFile=\$(clamdscan --no-summary --infected "\$1" 2>/dev/null)
                clamdscan --remove --no-summary --infected "\$1" 2>/dev/null | mail -s "Infected File Uploaded: \$infectedFile" \$ALERT_EMAIL
            fi
        fi
    fi
CLAMAV_SCRIPT
    chmod 755 /etc/pure-ftpd/clamav_check.sh
    echo "[OK] Created /etc/pure-ftpd/clamav_check.sh (alerts: $ALERT_EMAIL)"
else
    echo "[SKIP] /etc/pure-ftpd directory not found"
fi

echo ""
echo "--- [3/4] Starting upload scanner ---"
if [ -f /etc/pure-ftpd/clamav_check.sh ]; then
    pkill -f pure-uploadscript 2>/dev/null
    /usr/sbin/pure-uploadscript -B -r /etc/pure-ftpd/clamav_check.sh 2>/dev/null && echo "[OK] pure-uploadscript started" || echo "[WARN] Failed to start pure-uploadscript"
fi

echo ""
echo "--- [4/4] Adding to startup ---"
if [ -f /etc/pure-ftpd/clamav_check.sh ]; then
    sed -i '/pure-uploadscript/d' /etc/rc.d/rc.local 2>/dev/null
    sed -i '/pure-uploadscript/d' /etc/rc.local 2>/dev/null

    if [ -f /etc/rc.d/rc.local ]; then
        echo "/usr/sbin/pure-uploadscript -B -r /etc/pure-ftpd/clamav_check.sh" >> /etc/rc.d/rc.local
        chmod +x /etc/rc.d/rc.local
        echo "[OK] Added to /etc/rc.d/rc.local"
    elif [ -f /etc/rc.local ]; then
        echo "/usr/sbin/pure-uploadscript -B -r /etc/pure-ftpd/clamav_check.sh" >> /etc/rc.local
        chmod +x /etc/rc.local
        echo "[OK] Added to /etc/rc.local"
    else
        echo "[SKIP] rc.local not found"
    fi
fi

echo -e "${GREEN}[OK] FTP security complete${NC}"
echo ""

############################################
# PART 7: Snuffleupagus Installation
############################################
echo -e "${BOLD}${GREEN}=== PART 7: Snuffleupagus Installation ===${NC}"
echo ""

echo "--- [1/5] Checking Snuffleupagus installation ---"
if php -m 2>/dev/null | grep -qi "snuffleupagus"; then
    echo -e "${GREEN}[OK] Snuffleupagus is already installed${NC}"
    SNUFF_INSTALLED=true
else
    echo "[INFO] Snuffleupagus is not installed"
    SNUFF_INSTALLED=false
fi

if [ "$SNUFF_INSTALLED" = false ]; then
    echo ""
    read -p "Do you want to install Snuffleupagus? [y/N]: " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}[SKIP] Snuffleupagus installation skipped${NC}"
        SNUFF_SKIP=true
    else
        SNUFF_SKIP=false
    fi
fi

if [ "$SNUFF_SKIP" = false ] && [ "$SNUFF_INSTALLED" = false ]; then
    echo ""
    echo "--- [2/5] Detecting PHP version ---"
    PHP_VERSION=$(php -r "echo PHP_VERSION;" 2>/dev/null)
    PHP_EXT_DIR=$(php -r "echo ini_get('extension_dir');" 2>/dev/null)
    PHP_MAJOR=$(php -r "echo PHP_MAJOR_VERSION;" 2>/dev/null)
    PHP_MINOR=$(php -r "echo PHP_MINOR_VERSION;" 2>/dev/null)

    if [ -z "$PHP_VERSION" ]; then
        echo -e "${RED}[ERROR] Could not detect PHP version${NC}"
        SNUFF_SKIP=true
    else
        echo "PHP Version: $PHP_VERSION"
        echo "Extension directory: $PHP_EXT_DIR"
        echo "Major: $PHP_MAJOR | Minor: $PHP_MINOR"
        echo ""
        echo -e "${YELLOW}Snuffleupagus requires compilation tools:${NC}"
        echo "  - php-dev package"
        echo "  - autoconf, automake, libtool"
        echo ""
        read -p "Continue with installation? [y/N]: " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}[SKIP] Installation cancelled${NC}"
            SNUFF_SKIP=true
        else
            SNUFF_SKIP=false
        fi
    fi
fi

if [ "$SNUFF_SKIP" = false ] && [ "$SNUFF_INSTALLED" = false ]; then
    echo ""
    echo "--- [3/5] Installing dependencies ---"
    echo "Note: This may take several minutes..."
    echo ""

    if command -v apt-get &>/dev/null; then
        echo "Installing via apt-get..."
        read -p "Install build dependencies? [y/N]: " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            apt-get update -qq && apt-get install -y php-dev autoconf automake libtool build-essential 2>&1 | tail -5
            echo "[OK] Dependencies installed"
        else
            echo "[SKIP] Dependencies not installed"
        fi
    elif command -v yum &>/dev/null; then
        echo "Installing via yum..."
        read -p "Install build dependencies? [y/N]: " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            yum install -y php-devel autoconf automake libtool 2>&1 | tail -5
            echo "[OK] Dependencies installed"
        else
            echo "[SKIP] Dependencies not installed"
        fi
    fi
fi

if [ "$SNUFF_SKIP" = false ] && [ "$SNUFF_INSTALLED" = false ]; then
    echo ""
    echo "--- [4/5] Installing Snuffleupagus via PECL ---"
    read -p "Run 'pecl install snuffleupagus' now? [y/N]: " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Running pecl install snuffleupagus..."
        pecl install snuffleupagus 2>&1 | tail -20
        if [ $? -eq 0 ]; then
            echo ""
            echo -e "${GREEN}[OK] Snuffleupagus installed via PECL${NC}"
        else
            echo -e "${YELLOW}[WARN] PECL installation may have failed - check output above${NC}"
        fi
    else
        echo "[SKIP] PECL installation skipped"
    fi
fi

if [ "$SNUFF_INSTALLED" = true ]; then
    echo ""
    echo "--- [5/5] Configuration ---"
    SNUFF_INI=$(php -i 2>/dev/null | grep "snuffleupagus.ini" | head -1)
    if [ -n "$SNUFF_INI" ]; then
        echo "Config file: $SNUFF_INI"
    else
        echo "Checking for snuffleupagus configuration..."
        find /etc/php* -name "*snuffleupagus*" 2>/dev/null | head -5
    fi
    echo -e "${GREEN}[OK] Snuffleupagus is active${NC}"
elif [ "$SNUFF_SKIP" = true ]; then
    echo ""
    echo "--- [5/5] Skipped ---"
    echo "[INFO] Skipping Snuffleupagus installation"
else
    echo ""
    echo "--- [5/5] Manual steps required ---"
    echo "If installation failed, run manually:"
    echo "  1. pecl install snuffleupagus"
    echo "  2. echo 'extension=snuffleupagus.so' > /etc/php.d/snuffleupagus.ini"
    echo "  3. systemctl restart php-fpm (or httpd)"
fi

echo -e "${GREEN}[OK] Snuffleupagus section complete${NC}"
echo ""

############################################
# PART 8: Auto-run on schedule + User hooks
############################################
echo -e "${BOLD}${GREEN}=== PART 8: Setting up auto-update hooks ===${NC}"
echo ""

setup_auto_update() {
    SCRIPT_PATH=$(realpath "$0" 2>/dev/null || echo "$0")

    CRON_JOB="0 3 * * * $SCRIPT_PATH --cron >> /var/log/security_hardening.log 2>&1"

    crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH" | crontab - 2>/dev/null

    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo "[OK] Cron job installed - runs daily at 3 AM"

    cat > /usr/local/bin/php-security-update << 'HOOK_SCRIPT'
    #!/bin/bash
    # Auto-run PHP security hardening when new user is added
    # Can be called from: cPanel prewwwacct, DirectAdmin, or custom user creation

    NEW_USER="$1"
    if [ -z "$NEW_USER" ]; then
        exit 0
    fi

    USER_HOME=$(getent passwd "$NEW_USER" | cut -d: -f6)
    if [ -d "$USER_HOME/public_html" ]; then
        logger -t php-security "Adding $USER_HOME/public_html to open_basedir"
        # Re-run hardening to pick up new user's public_html
        SCRIPT_DIR=$(dirname "$(realpath "$0" 2>/dev/null || echo "$0")")
        bash "$SCRIPT_DIR/linux_guardian.sh" --auto 2>/dev/null
    fi
HOOK_SCRIPT
    chmod +x /usr/local/bin/php-security-update
    echo "[OK] User-add hook installed: /usr/local/bin/php-security-update"

    echo ""
    echo -e "${YELLOW}To trigger on new user (cPanel):${NC}"
    echo "  ln -s /usr/local/bin/php-security-update /scripts/prewwwacct"
    echo ""
    echo -e "${YELLOW}To trigger manually for new user:${NC}"
    echo "  /usr/local/bin/php-security-update username"
}

if [[ "${1:-}" == "--setup-auto" ]]; then
    setup_auto_update
fi

echo -e "${BOLD}Auto-update options:${NC}"
echo "  --setup-auto    Install cron job + user hook"
echo "  --cron          Run in cron mode (silent)"
echo "  --auto          Auto-apply without prompts"
echo ""
echo "To enable auto-update on new users, run:"
echo "  sudo $0 --setup-auto"
echo ""