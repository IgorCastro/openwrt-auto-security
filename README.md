# OpenWRT Auto-Security System

**Enterprise-grade automated intrusion detection and blocking for OpenWRT routers**

[![OpenWRT Compatible](https://img.shields.io/badge/OpenWRT-22.03%2B-blue.svg)](https://openwrt.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Firewall](https://img.shields.io/badge/Firewall-nftables-red.svg)](https://netfilter.org/projects/nftables/)
[![Version](https://img.shields.io/badge/Version-2.0--radxa-orange.svg)](https://github.com/IgorCastro/openwrt-auto-security/releases)

## 🛡️ What is Auto-Security?

Auto-Security transforms your OpenWRT router into a professional-grade security appliance with automated threat detection and blocking capabilities. Based on real-world enterprise security research, it provides:

- **Real-time attack detection** and automated blocking
- **Clean threat intelligence** with noise reduction
- **Zero-configuration** automated protection
- **Enterprise-grade logging** and reporting
- **Resource-optimized** performance

## 🔥 Key Features (v2.0)

### 🚀 Automated Protection
- ✅ **Auto-ban repeat attackers** (configurable threshold, per-service overrides)
- ✅ **IPv6 support** - Full detection and blocking of IPv6 attackers
- ✅ **CIDR-based banning** - Auto-ban entire /24 ranges when botnets attack
- ✅ **Whitelist management** - Protect management IPs and internal networks
- ✅ **Input validation** - Strict IP validation prevents injection attacks
- ✅ **Silent dropping** of banned IPs (no resource waste)
- ✅ **Persistent bans** across reboots with auto-save/restore

### 🌐 Service Correlation (NEW)
- 📡 **mwan3 integration** - Correlate attacks with WAN interface status
- 🛡️ **AdGuard Home integration** - DNS query correlation
- 📊 **netdata integration** - Performance impact correlation
- 🔍 **Interface analysis** - Which WAN interface receives attacks

### 🖥️ Web Interface (LUCI) (NEW)
- 📊 **Dashboard** - Real-time security overview
- 🚫 **Banned IPs management** - View, unban with one click
- ✅ **Whitelist management** - Add/remove IPs and CIDRs via web
- ⚙️ **Settings panel** - Full configuration via web UI
- 📋 **Logs viewer** - Ban logs, CIDR logs, correlation logs
- 🔗 **Correlation report** - mwan3/AdGuard/netdata analysis

### 📊 Professional Monitoring
- 📊 **Real-time attack monitoring** (5-min timeout, auto-refresh)
- 📈 **Security status reports** with threat intelligence
- 🎯 **Threat intelligence analysis** with country detection
- 📋 **Port/service targeting analysis** with service names
- 🌐 **Protocol & interface breakdown**

### ⚙️ Enterprise Management
- 🔧 **Per-service thresholds** - SSH=3, HTTP=15, HTTPS=10, RDP=2, etc.
- 📂 **Comprehensive logging** with rotation
- 🔄 **Easy ban management** - unban, reset, save, restore
- ✅ **Whitelist with CIDR support** - Protect entire subnets
- 📧 **Alert system** - Log, webhook (Slack/Discord), email, Telegram

### 💾 Persistence & Reliability
- 💾 **Auto-save bans** on shutdown
- 🔄 **Auto-restore bans** on startup
- 💾 **Daily backup** via cron
- 🔄 **Init.d service** with procd respawn

## 🚀 Zero Dependencies

Unlike heavy solutions like fail2ban, Auto-Security is purpose-built for OpenWRT:

- **No external packages** required
- **No Python runtime** needed
- **No complex configuration** files
- **Pure shell scripts** using OpenWRT's built-in tools

**Requirements:** Just OpenWRT 22.03+ with firewall4 (standard installation)

## 🔥 Why Not fail2ban?

This solution was born from the limitations of fail2ban on OpenWRT:

- **fail2ban compatibility issues** with OpenWRT's logging system
- **Heavy Python dependencies** not suitable for resource-constrained routers
- **Complex configuration** requiring manual setup
- **Generic rules** not optimized for OpenWRT's firewall4/nftables

**Our solution is purpose-built for OpenWRT** with zero external dependencies!

## 🚀 Quick Installation

### Radxa E24C Custom Edition (Recommended)
```bash
curl -fsSL https://raw.githubusercontent.com/IgorCastro/openwrt-auto-security/main/install-radxa.sh | sh
```

### Standard One-Line Install
```bash
curl -fsSL https://raw.githubusercontent.com/IgorCastro/openwrt-auto-security/main/install.sh | sh
```

### Manual Installation
```bash
wget https://raw.githubusercontent.com/IgorCastro/openwrt-auto-security/main/install-radxa.sh
chmod +x install-radxa.sh
./install-radxa.sh
```

### With LUCI Web Interface
```bash
opkg update
opkg install luci-app-auto-security
```

## 📋 Requirements

- **OpenWRT 22.03+** (firewall4/nftables required)
- **Logging enabled** in firewall configuration
- **Basic familiarity** with OpenWRT administration

### Firewall Configuration Required

Add these rules to `/etc/config/firewall` for attack logging:

```bash
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

# For second WAN (wanb) if using mwan3 dual-WAN:
# config rule
#     option name 'Log-Blocked-WANB-TCP'
#     option src 'wanb'
#     option proto 'tcp'
#     option target 'DROP'
#     option log '1'
#     option log_limit '5/minute'
#     option log_prefix 'Log-Blocked-WANB-TCP '
```

Then restart firewall: `/etc/init.d/firewall restart`

## 🎯 Usage

### Command Line Interface

```bash
# Quick status check
auto-security status

# Correlation report (mwan3/AdGuard/netdata)
auto-security correlation

# Monitor live attacks (5 min timeout)
auto-security live

# View banned IPs with details
auto-security banned

# Whitelist management
auto-security whitelist
auto-security whitelist-add 192.168.1.100
auto-security whitelist-add 10.0.0.0/8
auto-security whitelist-remove 192.168.1.100

# Manual threat scan
auto-security scan

# Unban specific IP
auto-security unban 1.2.3.4

# Reset all bans
auto-security reset

# Save/restore bans
auto-security save
auto-security restore
```

### Web Interface (LUCI)

Access via: `http://router-ip/cgi-bin/luci/admin/services/auto_security`

- **Overview** - Security dashboard with live stats
- **Banned IPs** - View and unban with one click
- **Whitelist** - Add/remove IPs and CIDRs
- **Settings** - Full configuration via UCI
- **Logs** - Ban logs, CIDR logs, correlation logs
- **Correlation** - mwan3/AdGuard/netdata analysis

### Service Control

```bash
/etc/init.d/auto-security start
/etc/init.d/auto-security stop
/etc/init.d/auto-security restart
/etc/init.d/auto-security enable
/etc/init.d/auto-security disable
```

## ⚙️ Configuration

Edit `/opt/auto-security/auto-security.conf` or via LUCI:

```bash
# Core Detection
ATTACK_THRESHOLD=3          # Attacks before auto-ban (default: 3)
SCAN_INTERVAL=10            # Scan every N minutes (default: 10)
BAN_DURATION=0              # 0=permanent, 3600=1h, 86400=24h
LOG_RETENTION=30            # Days to keep logs

# IPv6 & CIDR
ENABLE_IPV6=1               # Enable IPv6 detection
ENABLE_CIDR_BAN=1           # Enable CIDR range banning
CIDR_THRESHOLD=8            # Attacks per /24 before CIDR ban
CIDR_PREFIX=24              # CIDR prefix length

# Per-Service Thresholds (override global)
SSH_THRESHOLD=3
HTTP_THRESHOLD=15
HTTPS_THRESHOLD=10
RDP_THRESHOLD=2
DNS_THRESHOLD=30
SMTP_THRESHOLD=5

# Service Correlation
ENABLE_MWAN3_CORRELATION=1
MWAN3_INTERFACES="wan wanb"
ENABLE_ADGUARD_CORRELATION=1
ADGUARD_API_URL="http://127.0.0.1:3000"
ENABLE_NETDATA_CORRELATION=1
NETDATA_API_URL="http://127.0.0.1:19999"

# Alerts
ALERT_METHODS="log"         # log,webhook,email,telegram
ALERT_WEBHOOK_URL=""        # Slack/Discord/custom
ALERT_ON_NEW_BAN=1
ALERT_ON_CIDR_BAN=1
```

## 📊 Example Output

### Security Status Report
```
🛡️  PROTECTION STATUS:
   Active banned IPs: 23
   Total attacks today: 156
   Unique IPv4 attackers: 18
   Unique IPv6 attackers: 3

🎯 TOP THREAT SOURCES (Last 24 hours):
   45.142.193.92: 27 attacks (US)
   54.247.211.213: 24 attacks (JP)
   52.16.124.44: 18 attacks (DE)

🌐 TOP IPv6 THREATS:
   2001:db8::1: 5 attacks

🔍 TARGET PORT ANALYSIS:
   Port 22 (SSH): 45 attempts
   Port 443 (HTTPS): 32 attempts
   Port 3389 (RDP): 28 attempts

🌐 PROTOCOL BREAKDOWN:
   TCP: 142
   UDP: 14

📡 INTERFACE BREAKDOWN:
   eth0.2 (wan): 120
   eth0.3 (wanb): 36

🚫 CURRENTLY BANNED IPs:
   45.142.193.92 (ipv4) - 27 attacks - 2024-01-15 14:30:00
   2001:db8::1 (ipv6) - 5 attacks - 2024-01-15 14:35:00

🌐 BANNED CIDR RANGES:
   45.142.193.0/24

✅ WHITELIST: 12 entries
```

### Correlation Report
```
🔗 SERVICE CORRELATION REPORT
==============================================

📡 MWAN3 Status:
   Interface wan is online (tracking active)
   Interface wanb is online (tracking active)

🛡️  AdGuard Home:
   Status: Running
   "dns_queries": 15420
   "blocked": 342

📊 Netdata:
   Status: Running on port 19999
   "version": "1.37.1"
   "uptime": 86400

🔍 Attack Source Interface Analysis:
   eth0.2 (wan): 120 attacks
   eth0.3 (wanb): 36 attacks
```

## 🏢 Business/Enterprise Use

### Multi-Site Deployment
```bash
# Deploy to multiple OpenWRT routers
for router in router1.local router2.local router3.local; do
    scp install-radxa.sh root@$router:/tmp/
    ssh root@$router "/tmp/install-radxa.sh"
done
```

### Centralized Monitoring
```bash
# Collect reports from multiple routers
ssh root@router1.local "auto-security status" > router1-report.txt
ssh root@router2.local "auto-security status" > router2-report.txt

# Export banned IPs for SIEM integration
auto-security banned | cut -d' ' -f2 > banned-ips.txt
```

### Centralized Configuration (UCI)
```bash
# Configure via UCI (persists across updates)
uci set auto_security.core.attack_threshold='3'
uci set auto_security.core.scan_interval='10'
uci set auto_security.thresholds.ssh_threshold='3'
uci commit auto_security
/etc/init.d/auto-security reload
```

## 🔧 Advanced Configuration

### Custom Ban Rules
```bash
# Manually ban entire subnets
nft add rule inet fw4 input_wan ip saddr 192.168.1.0/24 drop comment "manual-ban-subnet"

# Ban by country (requires geoip/xt_geoip)
nft add rule inet fw4 input_wan ip saddr @country-blocklist drop
```

### Integration with External Systems
```bash
# Export banned IPs for SIEM integration
auto-security banned | cut -d' ' -f2 > banned-ips.txt

# Custom alerting via webhook
ALERT_WEBHOOK_URL="https://hooks.slack.com/services/XXX/XXX/XXX"
```

## 📁 File Structure

```
/opt/auto-security/
├── auto_ban.sh           # Core detection engine (v2.0)
├── monitor.sh            # Monitoring & reporting (v2.0)
├── auto-security.conf    # Configuration file
├── logs/
│   ├── banned_ips.log    # Ban activity log
│   ├── banlist.txt       # Historical ban database
│   ├── cidr_banlist.txt  # CIDR ban database
│   └── correlation.log   # Correlation logs
├── config/
│   └── whitelist.txt     # Whitelist (IPs/CIDRs)
└── backup/               # Persistent ban backups
    ├── nftables_bans.nft
    ├── banlist.txt
    └── cidr_banlist.txt

/etc/init.d/auto-security    # Init service
/usr/bin/auto-security       # Management command
/etc/config/auto_security    # UCI configuration
```

## 🐛 Troubleshooting

### Common Issues

**Auto-ban not working:**
```bash
# Check if firewall logging is enabled
logread | grep "Log-Blocked-WAN-Access"

# Verify nftables rules
nft list chain inet fw4 input_wan
```

**No attacks being logged:**
```bash
# Check firewall configuration
uci show firewall | grep log

# Restart firewall
/etc/init.d/firewall restart
```

**Commands not found:**
```bash
# Reinstall management commands
/opt/auto-security/install.sh
```

**LUCI not showing:**
```bash
# Install luci-app-auto-security
opkg update && opkg install luci-app-auto-security
# Or restart uhttpd
/etc/init.d/uhttpd restart
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on real-world enterprise security research
- Inspired by the OpenWRT community's commitment to security
- Based on proven nftables/firewall4 architecture
- Radxa E24C optimizations by Igor Castro

## 📞 Support

- **Documentation**: [Wiki](https://github.com/IgorCastro/openwrt-auto-security/wiki)
- **Issues**: [GitHub Issues](https://github.com/IgorCastro/openwrt-auto-security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/IgorCastro/openwrt-auto-security/discussions)

---

**⚠️ Important**: This system provides automated protection but should be part of a comprehensive security strategy. Regular updates and monitoring are recommended.

**🛡️ Made with ❤️ for the OpenWRT community**

---

## 📈 Real-World Performance (Radxa E24C)

Based on production deployment:
- **Attacks blocked per day**: 400+
- **Unique attackers banned**: 21+
- **Most targeted ports**: SSH (22), RDP (3389), PostgreSQL (5432)
- **Attack reduction**: 95% noise eliminated
- **Resource impact**: <1% CPU usage, <5MB RAM

## 📦 Package Installation (OpenWRT)

```bash
# Add custom feed
echo "src-git auto_security https://github.com/IgorCastro/openwrt-auto-security" >> feeds.conf.default
./scripts/feeds update auto_security
./scripts/feeds install auto-security luci-app-auto-security
make menuconfig  # Select Network > Firewall > auto-security + LuCI > Applications > luci-app-auto-security
make package/auto-security/compile V=s
make package/luci-app-auto-security/compile V=s
```

---

*Version 2.0-radxa - Optimized for Radxa E24C with OpenWRT 24.10 (R25.05.07 by flippy)*
*Dual-WAN, AdGuard Home, netdata, mwan3, Docker ready*