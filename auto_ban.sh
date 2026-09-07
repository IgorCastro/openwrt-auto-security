#!/bin/sh
# Auto-Ban Script - Detects and blocks repeat attackers
# Part of OpenWRT Auto-Security System
# Version: 2.0 - IPv6, Whitelist, Validation, CIDR Support

CONFIG_FILE="/opt/auto-security/auto-security.conf"
LOGFILE="/opt/auto-security/logs/banned_ips.log"
WHITELIST_FILE="/opt/auto-security/config/whitelist.txt"
BANLIST_FILE="/opt/auto-security/logs/banlist.txt"
CIDR_BANLIST_FILE="/opt/auto-security/logs/cidr_banlist.txt"

# Load configuration
if [ -f "$CONFIG_FILE" ]; then
    . "$CONFIG_FILE"
else
    # Default configuration
    ATTACK_THRESHOLD=5
    BAN_DURATION=0
    SCAN_PERIOD="$(date +'%b %d')"
    CIDR_THRESHOLD=10
    CIDR_PREFIX=24
    ENABLE_IPV6=1
    ENABLE_CIDR_BAN=1
fi

DATE="$SCAN_PERIOD"

# Logging function
log_ban() {
    echo "$(date): $1" | tee -a "$LOGFILE"
    logger -t AUTO-SECURITY "$1"
}

# Validate IPv4 address
validate_ipv4() {
    local ip=$1
    case $ip in
        *[!0-9.]*|*..*|*.*.*.*.*) return 1 ;;
    esac
    local IFS=.
    set -- $ip
    [ $# -eq 4 ] &&
    [ $1 -le 255 ] && [ $2 -le 255 ] && [ $3 -le 255 ] && [ $4 -le 255 ]
}

# Validate IPv6 address (basic)
validate_ipv6() {
    local ip=$1
    # Basic IPv6 validation - accepts compressed and full forms
    echo "$ip" | grep -qE '^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
}

# Validate IP (v4 or v6)
validate_ip() {
    local ip=$1
    validate_ipv4 "$ip" || validate_ipv6 "$ip"
}

# Check if IP is whitelisted
is_whitelisted() {
    local ip=$1
    [ -f "$WHITELIST_FILE" ] || return 1
    # Check exact IP match
    grep -q "^$ip$" "$WHITELIST_FILE" 2>/dev/null && return 0
    # Check CIDR match
    while read -r line; do
        [ -z "$line" ] && continue
        case "$line" in
            */*)
                # CIDR notation - check if IP in range
                local cidr_ip="${line%/*}"
                local cidr_mask="${line#*/}"
                if ip_in_cidr "$ip" "$cidr_ip" "$cidr_mask"; then
                    return 0
                fi
                ;;
        esac
    done < "$WHITELIST_FILE"
    return 1
}

# Check if IPv4 is in CIDR range
ip_in_cidr() {
    local ip=$1
    local cidr_ip=$2
    local cidr_mask=$3
    # Convert to integers for comparison
    local ip_int=$(ipv4_to_int "$ip")
    local cidr_int=$(ipv4_to_int "$cidr_ip")
    local mask_int=$((0xffffffff << (32 - cidr_mask) & 0xffffffff))
    [ $((ip_int & mask_int)) -eq $((cidr_int & mask_int)) ]
}

# Convert IPv4 to integer
ipv4_to_int() {
    local IFS=.
    set -- $1
    echo $(( (($1 * 256 + $2) * 256 + $3) * 256 + $4 ))
}

# Get CIDR prefix from IP
get_cidr_prefix() {
    local ip=$1
    local prefix=${CIDR_PREFIX:-24}
    local IFS=.
    set -- $ip
    # For /24, zero out last octet
    if [ "$prefix" -eq 24 ]; then
        echo "$1.$2.$3.0/$prefix"
    elif [ "$prefix" -eq 16 ]; then
        echo "$1.$2.0.0/$prefix"
    else
        echo "$ip/$prefix"
    fi
}

# Main detection logic
log_ban "=== Auto-Security Scan Started ==="
log_ban "Scanning for repeat attackers (threshold: $ATTACK_THRESHOLD attacks)..."

# Create temp file for attack data
TMP_ATTACKS="/tmp/auto-security-attacks.$$"
trap "rm -f $TMP_ATTACKS" EXIT

# Collect attacks from logread (IPv4)
logread | grep "Log-Blocked-WAN-Access" | grep "$DATE" | \
sed -n 's/.*SRC=\([0-9.]*\).*/\1/p' | sort | uniq -c | \
awk -v threshold="$ATTACK_THRESHOLD" '$1 > threshold {print $2, $1}' > "$TMP_ATTACKS"

# Also check for IPv6 attacks if enabled
if [ "$ENABLE_IPV6" -eq 1 ]; then
    logread | grep "Log-Blocked-WAN-Access" | grep "$DATE" | \
    sed -n 's/.*SRC=\([0-9a-fA-F:]*\).*/\1/p' | grep ':' | sort | uniq -c | \
    awk -v threshold="$ATTACK_THRESHOLD" '$1 > threshold {print $2, $1}' >> "$TMP_ATTACKS"
fi

# Process each attacking IP
while read IP COUNT; do
    [ -z "$IP" ] && continue
    
    # Validate IP
    if ! validate_ip "$IP"; then
        log_ban "WARNING: Invalid IP format skipped: $IP"
        continue
    fi
    
    # Check whitelist
    if is_whitelisted "$IP"; then
        log_ban "SKIPPED: $IP is whitelisted ($COUNT attacks)"
        continue
    fi
    
    # Determine nftables family and address
    if validate_ipv6 "$IP"; then
        FAMILY="ip6"
        ADDR="$IP"
    else
        FAMILY="ip"
        ADDR="$IP"
    fi
    
    # Check if already banned
    if nft list ruleset | grep -q "${FAMILY} saddr $ADDR drop"; then
        log_ban "ALREADY BANNED: $IP ($COUNT attacks)"
        continue
    fi
    
    # Ban the IP
    log_ban "THREAT DETECTED: Banning $IP ($FAMILY) after $COUNT attacks"
    
    # Insert at TOP of chain (before logging rules)
    nft insert rule inet fw4 input_wan ${FAMILY} saddr $ADDR counter drop comment "auto-banned-$IP" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        # Add to banlist with timestamp
        echo "$(date '+%Y-%m-%d %H:%M:%S') $IP $COUNT ${FAMILY}" >> "$BANLIST_FILE"
        log_ban "SUCCESS: $IP blocked"
    else
        log_ban "ERROR: Failed to ban $IP"
    fi
done < "$TMP_ATTACKS"

# CIDR-based banning (if enabled)
if [ "$ENABLE_CIDR_BAN" -eq 1 ]; then
    log_ban "Checking for CIDR-based attacks (threshold: $CIDR_THRESHOLD, prefix: /$CIDR_PREFIX)..."
    
    # Count attacks per /24 CIDR
    CIDR_TMP="/tmp/auto-security-cidr.$$"
    logread | grep "Log-Blocked-WAN-Access" | grep "$DATE" | \
    sed -n 's/.*SRC=\([0-9.]*\).*/\1/p' | \
    while read ip; do
        validate_ipv4 "$ip" && get_cidr_prefix "$ip"
    done | sort | uniq -c | \
    awk -v threshold="$CIDR_THRESHOLD" '$1 > threshold {print $2, $1}' > "$CIDR_TMP"
    
    while read CIDR COUNT; do
        [ -z "$CIDR" ] && continue
        
        # Check if CIDR already banned
        if nft list ruleset | grep -q "ip saddr $CIDR drop"; then
            log_ban "CIDR ALREADY BANNED: $CIDR ($COUNT attacks)"
            continue
        fi
        
        # Check whitelist for CIDR
        if [ -f "$WHITELIST_FILE" ] && grep -q "^$CIDR$" "$WHITELIST_FILE"; then
            log_ban "CIDR SKIPPED: $CIDR is whitelisted ($COUNT attacks)"
            continue
        fi
        
        log_ban "CIDR THREAT DETECTED: Banning $CIDR after $COUNT attacks"
        nft insert rule inet fw4 input_wan ip saddr $CIDR counter drop comment "auto-banned-cidr-$CIDR" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') $CIDR $COUNT CIDR" >> "$CIDR_BANLIST_FILE"
            log_ban "SUCCESS: CIDR $CIDR blocked"
        fi
    done < "$CIDR_TMP"
    rm -f "$CIDR_TMP"
fi

# Cleanup expired bans if BAN_DURATION > 0
if [ "$BAN_DURATION" -gt 0 ]; then
    cleanup_expired_bans
fi

# Summary
TOTAL_BANNED=$(nft list ruleset | grep -c "auto-banned")
log_ban "Auto-ban scan complete. Active bans: $TOTAL_BANNED"
log_ban "=== Auto-Security Scan Finished ==="

# Cleanup expired bans function
cleanup_expired_bans() {
    local now=$(date +%s)
    local cutoff=$((now - BAN_DURATION))
    
    # This is a simplified version - in production would need proper timestamp tracking
    log_ban "Ban duration cleanup not fully implemented - bans are permanent when BAN_DURATION=0"
}