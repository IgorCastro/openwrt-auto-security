#!/bin/sh
# OpenWRT Auto-Security System Installer - Radxa E24C Custom Edition
# Advanced automated intrusion detection and blocking for OpenWRT
# Version: 2.0
# Customized for: Radxa E24C (OpenWRT 24.10.0, R25.05.07 by flippy)
# Hardware: 1GB RAM, NVMe 117GB, Dual-WAN, AdGuard Home, netdata, mwan3

set -e

VERSION="2.0-radxa"
INSTALL_DIR="/opt/auto-security"
CONFIG_FILE="$INSTALL_DIR/auto-security.conf"
LOG_FILE="/tmp/auto-security-install.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}"
    echo "================================================================"
    echo "  OpenWRT Auto-Security System v${VERSION}"
    echo "  Radxa E24C Custom Edition"
    echo "  Enterprise-Grade Automated Threat Protection"
    echo "================================================================"
    echo -e "${NC}"
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "$(date): $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "$(date): WARNING: $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$(date): ERROR: $1" >> "$LOG_FILE"
    exit 1
}

check_radxa_e24c() {
    log "Checking Radxa E24C compatibility..."
    
    if [ ! -f /etc/openwrt_release ]; then
        error "This installer is designed for OpenWRT systems only"
    fi
    
    . /etc/openwrt_release
    log "Detected OpenWRT ${DISTRIB_RELEASE} on ${DISTRIB_TARGET}"
    
    # Check for Radxa E24C specific hardware
    if [ -f /proc/device-tree/model ]; then
        MODEL=$(cat /proc/device-tree/model 2>/dev/null || echo "Unknown")
        log "Hardware: $MODEL"
    fi
    
    # Check memory
    MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    MEM_MB=$((MEM_KB / 1024))
    log "Memory: ${MEM_MB}MB"
    
    # Check NVMe
    if ls /dev/nvme* 2>/dev/null | grep -q nvme; then
        log "NVMe storage detected"
    fi
    
    # Check dual-WAN interfaces
    WAN_COUNT=$(uci show network 2>/dev/null | grep -c "wan.*=" || echo "0")
    log "WAN interfaces configured: $WAN_COUNT"
}

check_firewall4() {
    if ! which nft >/dev/null 2>&1; then
        error "This system requires firewall4 (nftables). Please upgrade to OpenWRT 22.03+"
    fi
    log "Firewall4 (nftables) detected"
}

check_dependencies() {
    log "Checking required dependencies..."
    
    for cmd in nft logread awk sed grep sort uniq crontab logger ip timeout curl; do
        if ! which $cmd >/dev/null 2>&1; then
            warn "Optional dependency missing: $cmd"
        fi
    done
    
    # Check for optional tools
    for cmd in geoiplookup sqlite3; do
        if which $cmd >/dev/null 2>&1; then
            log "Optional tool found: $cmd"
        fi
    done
}

detect_existing_services() {
    log "Detecting existing services for correlation..."
    
    # mwan3
    if command -v mwan3 >/dev/null 2>&1; then
        log "mwan3 detected - will enable correlation"
        MWAN3_DETECTED=1
    fi
    
    # AdGuard Home
    if [ -f /etc/AdGuardHome.yaml ] && pgrep -f "AdGuardHome" >/dev/null; then
        log "AdGuard Home detected - will enable correlation"
        ADGUARD_DETECTED=1
    fi
    
    # netdata
    if pgrep -f "netdata" >/dev/null; then
        log "netdata detected - will enable correlation"
        NETDATA_DETECTED=1
    fi
    
    # Docker
    if command -v docker >/dev/null 2>&1; then
        log "Docker detected"
        DOCKER_DETECTED=1
    fi
}

create_directories() {
    log "Creating installation directories..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/logs"
    mkdir -p "$INSTALL_DIR/config"
    mkdir -p "$INSTALL_DIR/backup"
    mkdir -p "/etc/auto-security"
}

install_auto_ban_script() {
    log "Installing auto-ban detection script (v2.0)..."
    
    # The auto_ban.sh is now a separate file - copy it
    if [ -f "auto_ban.sh" ]; then
        cp auto_ban.sh "$INSTALL_DIR/auto_ban.sh"
        chmod +x "$INSTALL_DIR/auto_ban.sh"
    else
        error "auto_ban.sh not found in installation directory"
    fi
}

install_monitoring_script() {
    log "Installing monitoring and reporting script (v2.0)..."
    
    if [ -f "monitor.sh" ]; then
        cp monitor.sh "$INSTALL_DIR/monitor.sh"
        chmod +x "$INSTALL_DIR/monitor.sh"
    else
        error "monitor.sh not found in installation directory"
    fi
}

create_radxa_configuration() {
    log "Creating Radxa E24C optimized configuration..."
    
    cat > "$CONFIG_FILE" << 'EOF'
# OpenWRT Auto-Security Configuration v2.0 - Radxa E24C Edition
# Optimized for: Radxa E24C, OpenWRT 24.10.0, Dual-WAN, AdGuard, netdata, mwan3

# ============================================================
# CORE DETECTION SETTINGS (Optimized for Radxa E24C)
# ============================================================

# Attack detection threshold - Lower for exposed SSH (port 22)
ATTACK_THRESHOLD=3

# Scan interval - More frequent for active dual-WAN
SCAN_INTERVAL=10

# Ban duration (0 = permanent, 86400 = 24h, 3600 = 1h)
BAN_DURATION=0

# Log retention
LOG_RETENTION=30

# ============================================================
# IPV6 SUPPORT (Enabled - Radxa has IPv6 on both WANs)
# ============================================================
ENABLE_IPV6=1

# ============================================================
# CIDR-BASED BANNING (Enabled for botnet protection)
# ============================================================
ENABLE_CIDR_BAN=1
CIDR_THRESHOLD=8
CIDR_PREFIX=24

# ============================================================
# FEATURE FLAGS (All enabled for full protection)
# ============================================================
ENABLE_AUTO_BAN=1
ENABLE_MONITORING=1
ENABLE_ALERTS=1
ENABLE_CORRELATION=1

# ============================================================
# ALERT SETTINGS (Log only by default - configure webhook for external)
# ============================================================
ALERT_METHODS="log"
ALERT_ON_NEW_BAN=1
ALERT_ON_CIDR_BAN=1
ALERT_ON_HIGH_VOLUME=50

# ============================================================
# SERVICE CORRELATION (Auto-detected: mwan3, AdGuard, netdata)
# ============================================================
ENABLE_MWAN3_CORRELATION=1
ENABLE_ADGUARD_CORRELATION=1
ENABLE_NETDATA_CORRELATION=1

# mwan3 interfaces (adjust to your actual interface names)
MWAN3_INTERFACES="wan wanb"

# AdGuard Home (default port 3000, admin user)
ADGUARD_API_URL="http://127.0.0.1:3000"
ADGUARD_API_USER="admin"
ADGUARD_API_PASS_FILE="/root/adguard-admin.txt"

# Netdata (default port 19999)
NETDATA_API_URL="http://127.0.0.1:19999"

# ============================================================
# LIVE MONITORING
# ============================================================
LIVE_TIMEOUT=300

# ============================================================
# LOGGING
# ============================================================
LOGFILE="/opt/auto-security/logs/banned_ips.log"
BANLIST_FILE="/opt/auto-security/logs/banlist.txt"
CIDR_BANLIST_FILE="/opt/auto-security/logs/cidr_banlist.txt"
CORRELATION_LOG="/opt/auto-security/logs/correlation.log"
LOG_FORMAT="text"

# ============================================================
# BACKUP/RESTORE (Critical for persistence across reboots)
# ============================================================
BACKUP_DIR="/opt/auto-security/backup"
AUTO_SAVE_ON_SHUTDOWN=1
AUTO_RESTORE_ON_STARTUP=1

# ============================================================
# PER-SERVICE THRESHOLDS (Optimized for typical Radxa exposure)
# ============================================================
SSH_THRESHOLD=3
HTTP_THRESHOLD=15
HTTPS_THRESHOLD=10
RDP_THRESHOLD=2
DNS_THRESHOLD=30
SMTP_THRESHOLD=5

# ============================================================
# ADVANCED SETTINGS
# ============================================================
NFT_CHAIN="input_wan"
NFT_TABLE="inet fw4"
LOG_PREFIX="Log-Blocked-WAN-Access"
MAX_LOG_ENTRIES=5000
EOF
}

setup_radxa_logging() {
    log "Configuring firewall logging for Radxa E24C dual-WAN..."
    
    # Check if logging rules already exist
    if ! nft list chain inet fw4 input_wan 2>/dev/null | grep -q "Log-Blocked-WAN"; then
        warn "Firewall logging rules not found in nftables."
        echo ""
        echo "======================================================"
        echo "REQUIRED: Add these rules to /etc/config/firewall:"
        echo "======================================================"
        echo ""
        cat << 'FWCONFIG'

config rule
    option name 'Log-Blocked-WAN-TCP'
    option src 'wan'
    option proto 'tcp'
    option target 'DROP'
    option log '1'
    option log_limit '5/minute'
    option log_prefix 'Log-Blocked-WAN-TCP '

config rule
    option name 'Log-Blocked-WAN-UDP'
    option src 'wan'
    option proto 'udp'
    option target 'DROP'
    option log '1'
    option log_limit '5/minute'
    option log_prefix 'Log-Blocked-WAN-UDP '

# If you have a second WAN (wanb), add similar rules:
# config rule
#     option name 'Log-Blocked-WANB-TCP'
#     option src 'wanb'
#     option proto 'tcp'
#     option target 'DROP'
#     option log '1'
#     option log_limit '5/minute'
#     option log_prefix 'Log-Blocked-WANB-TCP '

FWCONFIG
        echo ""
        echo "Then restart firewall: /etc/init.d/firewall restart"
        echo ""
        read -p "Press Enter to continue after adding firewall rules..." dummy
    else
        log "Firewall logging rules already configured"
    fi
}

create_whitelist() {
    log "Creating default whitelist for Radxa E24C..."
    
    mkdir -p "$INSTALL_DIR/config"
    
    # Create whitelist with common safe ranges
    cat > "$INSTALL_DIR/config/whitelist.txt" << 'EOF'
# Auto-Security Whitelist - Radxa E24C
# Add trusted IPs/CIDRs here (one per line)
# Lines starting with # are comments

# Local management IPs (CHANGE TO YOUR ACTUAL MANAGEMENT IPs)
# 192.168.1.100          # Your desktop/laptop
# 192.168.1.50           # Your phone

# RFC1918 Private Networks (safe to whitelist if not exposed)
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# IPv6 ULA (Unique Local Addresses)
fc00::/7
fd00::/8

# Link-local (should never be routed anyway)
fe80::/10
169.254.0.0/16

# Docker networks (if using Docker)
# 172.17.0.0/16
# 172.18.0.0/16
# 172.19.0.0/16
# 172.20.0.0/16
# 172.21.0.0/16
# 172.22.0.0/16
# 172.23.0.0/16
# 172.24.0.0/16
# 172.25.0.0/16
# 172.26.0.0/16
# 172.27.0.0/16
# 172.28.0.0/16
# 172.29.0.0/16
# 172.28.0.0/16
# 172.29.0.0/16
# 172.30.0.0/16
# 172.31.0.0/16

# Documentation/test ranges
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
2001:db8::/32

# IMPORTANT: Add your actual management IPs above and uncomment them!
# Example:
# 192.168.1.50   # Your laptop
# 192.168.1.60   # Your phone
EOF
    
    log "Whitelist created at $INSTALL_DIR/config/whitelist.txt"
    warn "IMPORTANT: Edit $INSTALL_DIR/config/whitelist.txt and add your management IPs!"
}

setup_cron() {
    log "Setting up automated scanning (every ${SCAN_INTERVAL:-10} minutes)..."
    
    # Backup existing crontab
    crontab -l 2>/dev/null > /tmp/crontab.backup.$(date +%s) 2>/dev/null || true
    
    # Remove any existing auto-security entries
    crontab -l 2>/dev/null | grep -v "auto_ban.sh" | grep -v "monitor.sh" | crontab -
    
    # Add auto-ban cron (every SCAN_INTERVAL minutes)
    (crontab -l 2>/dev/null; echo "*/${SCAN_INTERVAL:-10} * * * * $INSTALL_DIR/auto_ban.sh >/dev/null 2>&1") | crontab -
    
    # Add daily ban save (at 3 AM)
    (crontab -l 2>/dev/null; echo "0 3 * * * $INSTALL_DIR/monitor.sh save >/dev/null 2>&1") | crontab -
    
    # Add log rotation (weekly)
    (crontab -l 2>/dev/null; echo "0 4 * * 0 $INSTALL_DIR/auto_ban.sh --rotate-logs >/dev/null 2>&1") | crontab -
    
    log "Cron jobs installed: auto-ban every ${SCAN_INTERVAL:-10} min, daily save at 3AM, weekly log rotation"
}

create_init_service() {
    log "Creating init.d service for persistence..."
    
    cat > /etc/init.d/auto-security << 'EOF'
#!/bin/sh /etc/rc.common
# Auto-Security init script for OpenWRT

START=99
STOP=10
USE_PROCD=1

INSTALL_DIR="/opt/auto-security"
CONFIG_FILE="$INSTALL_DIR/auto-security.conf"

start_service() {
    procd_open_instance
    procd_set_param command /bin/sh -c "
        # Restore bans on startup
        if [ -f $INSTALL_DIR/backup/nftables_bans.nft ]; then
            logger -t AUTO-SECURITY 'Restoring bans from backup...'
            nft -f $INSTALL_DIR/backup/nftables_bans.nft
        fi
        
        # Start periodic save (every hour)
        while true; do
            sleep 3600
            $INSTALL_DIR/monitor.sh save >/dev/null 2>&1
        done
    "
    procd_set_param respawn
    procd_close_instance
}

stop_service() {
    # Save bans before stopping
    if [ "$AUTO_SAVE_ON_SHUTDOWN" = "1" ]; then
        logger -t AUTO-SECURITY 'Saving bans before shutdown...'
        $INSTALL_DIR/monitor.sh save >/dev/null 2>&1
    fi
}

reload_service() {
    stop_service
    start_service
}
EOF
    
    chmod +x /etc/init.d/auto-security
    /etc/init.d/auto-security enable
    log "Init service created and enabled"
}

create_management_commands() {
    log "Creating management commands..."
    
    cat > "/usr/bin/auto-security" << 'EOF'
#!/bin/sh
# OpenWRT Auto-Security Management Command v2.0

INSTALL_DIR="/opt/auto-security"

case "$1" in
    "status"|"report")
        $INSTALL_DIR/monitor.sh report
        ;;
    "correlation")
        $INSTALL_DIR/monitor.sh correlation
        ;;
    "live")
        $INSTALL_DIR/monitor.sh live
        ;;
    "banned")
        $INSTALL_DIR/monitor.sh banned
        ;;
    "whitelist")
        $INSTALL_DIR/monitor.sh whitelist
        ;;
    "whitelist-add")
        $INSTALL_DIR/monitor.sh whitelist-add "$2"
        ;;
    "whitelist-remove")
        $INSTALL_DIR/monitor.sh whitelist-remove "$2"
        ;;
    "scan")
        echo "🔍 Running manual threat scan..."
        $INSTALL_DIR/auto_ban.sh
        ;;
    "unban")
        if [ -z "$2" ]; then
            echo "Usage: auto-security unban <IP>"
            exit 1
        fi
        $INSTALL_DIR/monitor.sh unban "$2"
        ;;
    "reset")
        $INSTALL_DIR/monitor.sh reset
        ;;
    "save")
        $INSTALL_DIR/monitor.sh save
        ;;
    "restore")
        $INSTALL_DIR/monitor.sh restore
        ;;
    "install")
        echo "🚀 Auto-Security v2.0-radxa already installed!"
        echo "Location: $INSTALL_DIR"
        echo "Config: $INSTALL_DIR/auto-security.conf"
        ;;
    "version")
        echo "Auto-Security v2.0-radxa"
        echo "Built for Radxa E24C"
        ;;
    *)
        echo "OpenWRT Auto-Security System v2.0-radxa"
        echo "Customized for Radxa E24C (OpenWRT 24.10)"
        echo ""
        echo "Usage: auto-security {command}"
        echo ""
        echo "📊 Reporting:"
        echo "  status       - Show security status report"
        echo "  correlation  - Show correlation with mwan3/AdGuard/netdata"
        echo "  live         - Monitor attacks in real-time (5 min timeout)"
        echo "  banned       - List currently banned IPs with details"
        echo ""
        echo "✅ Whitelist Management:"
        echo "  whitelist          - Show whitelist entries"
        echo "  whitelist-add IP   - Add IP/CIDR to whitelist"
        echo "  whitelist-remove IP- Remove IP/CIDR from whitelist"
        echo ""
        echo "🔨 Ban Management:"
        echo "  scan        - Run manual threat detection"
        echo "  unban IP    - Remove specific IP from ban list"
        echo "  reset       - Remove all bans"
        echo "  save        - Save bans to persistent storage"
        echo "  restore     - Restore bans from backup"
        echo ""
        echo "🔧 Service:"
        echo "  /etc/init.d/auto-security start|stop|restart|enable|disable"
        echo ""
        echo "Examples:"
        echo "  auto-security status"
        echo "  auto-security live"
        echo "  auto-security whitelist-add 192.168.1.100"
        echo "  auto-security whitelist-add 10.0.0.0/8"
        echo "  auto-security unban 1.2.3.4"
        echo "  auto-security correlation"
        ;;
esac
EOF
    
    chmod +x "/usr/bin/auto-security"
}

main() {
    print_banner
    
    log "Starting Radxa E24C Auto-Security installation..."
    
    check_radxa_e24c
    check_firewall4
    check_dependencies
    detect_existing_services
    create_directories
    install_auto_ban_script
    install_monitoring_script
    create_radxa_configuration
    create_whitelist
    setup_radxa_logging
    setup_cron
    create_init_service
    create_management_commands
    
    echo ""
    echo -e "${GREEN}================================================================"
    echo "✅ Radxa E24C Auto-Security Installation Complete!"
    echo "================================================================${NC}"
    echo ""
    echo -e "${CYAN}🎯 QUICK START:${NC}"
    echo "   auto-security status       - View security report"
    echo "   auto-security correlation  - View mwan3/AdGuard/netdata correlation"
    echo "   auto-security live         - Monitor live attacks"
    echo "   auto-security scan         - Run manual scan"
    echo ""
    echo -e "${CYAN}🔧 SERVICE CONTROL:${NC}"
    echo "   /etc/init.d/auto-security start|stop|restart"
    echo ""
    echo -e "${CYAN}📁 KEY FILES:${NC}"
    echo "   Config:        $INSTALL_DIR/auto-security.conf"
    echo "   Whitelist:     $INSTALL_DIR/config/whitelist.txt  ⚠️  EDIT THIS!"
    echo "   Logs:          $INSTALL_DIR/logs/"
    echo "   Backup:        $INSTALL_DIR/backup/"
    echo ""
    echo -e "${YELLOW}⚠️  CRITICAL NEXT STEPS:${NC}"
    echo "   1. Edit whitelist: vi $INSTALL_DIR/config/whitelist.txt"
    echo "      Add your management IPs (laptop, phone, etc.)"
    echo "   2. Verify firewall logging rules in /etc/config/firewall"
    echo "   3. Restart firewall: /etc/init.d/firewall restart"
    echo "   4. Test: auto-security status"
    echo ""
    echo -e "${CYAN}🔗 SERVICE INTEGRATION DETECTED:${NC}"
    [ "$MWAN3_DETECTED" = "1" ] && echo "   ✅ mwan3 - Dual-WAN correlation enabled"
    [ "$ADGUARD_DETECTED" = "1" ] && echo "   ✅ AdGuard Home - DNS correlation enabled"
    [ "$NETDATA_DETECTED" = "1" ] && echo "   ✅ netdata - Performance correlation enabled"
    [ "$DOCKER_DETECTED" = "1" ] && echo "   ✅ Docker - Network awareness enabled"
    echo ""
    echo -e "${GREEN}🛡️  Auto-ban active - scanning every ${SCAN_INTERVAL:-10} minutes${NC}"
    echo -e "${GREEN}📈 Run 'auto-security status' to see protection level${NC}"
    echo ""
    
    log "Radxa E24C installation completed successfully"
}

main "$@"