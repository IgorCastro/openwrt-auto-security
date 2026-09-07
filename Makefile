# OpenWRT Auto-Security Package Makefile

include $(TOPDIR)/rules.mk

PKG_NAME:=auto-security
PKG_VERSION:=2.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Igor Castro <igor@castro.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/auto-security
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Firewall
	TITLE:=Auto-Security - Automated Intrusion Detection and Blocking
	DEPENDS:=+nftables +logread +coreutils-timeout +coreutils-sort +coreutils-uniq +awk +grep +bash +curl +iptables-nft
	PKGARCH:=all
endef

define Package/auto-security/description
	OpenWRT Auto-Security is an enterprise-grade automated intrusion
	detection and blocking system for OpenWRT routers.
	
	Features:
	- Real-time attack detection and automated IP banning
	- IPv4 and IPv6 support
	- CIDR-based automatic banning
	- Whitelist management
	- Service correlation (mwan3, AdGuard Home, netdata)
	- Persistent bans across reboots
	- Web interface (luci-app-auto-security)
	- Zero external dependencies (pure shell + nftables)
endef

define Package/auto-security/conffiles
/etc/config/auto_security
/opt/auto-security/auto-security.conf
/opt/auto-security/config/whitelist.txt
</define>

define Build/Compile
	# Nothing to compile - pure shell scripts
endef

define Package/auto-security/install
	$(INSTALL_DIR) $(1)/opt/auto-security
	$(INSTALL_DIR) $(1)/opt/auto-security/logs
	$(INSTALL_DIR) $(1)/opt/auto-security/config
	$(INSTALL_DIR) $(1)/opt/auto-security/backup
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/config
	
	# Core scripts
	$(INSTALL_BIN) ./auto_ban.sh $(1)/opt/auto-security/auto_ban.sh
	$(INSTALL_BIN) ./monitor.sh $(1)/opt/auto-security/monitor.sh
	
	# Configuration
	$(INSTALL_CONF) ./auto-security.conf $(1)/opt/auto-security/auto-security.conf
	$(INSTALL_CONF) ./luci/root/etc/config/auto_security $(1)/etc/config/auto_security
	
	# Management command
	$(INSTALL_BIN) ./files/usr/bin/auto-security $(1)/usr/bin/auto-security
	
	# Init script
	$(INSTALL_BIN) ./files/etc/init.d/auto-security $(1)/etc/init.d/auto-security
	
	# Default whitelist
	$(INSTALL_CONF) ./files/opt/auto-security/config/whitelist.txt $(1)/opt/auto-security/config/whitelist.txt
endef

define Package/auto-security/postinst
#!/bin/sh
# Enable and start service
/etc/init.d/auto-security enable
/etc/init.d/auto-security start

# Add firewall logging rules if not present
if ! nft list chain inet fw4 input_wan 2>/dev/null | grep -q "Log-Blocked-WAN"; then
    echo "WARNING: Firewall logging rules not configured."
    echo "Please add logging rules to /etc/config/firewall and restart firewall."
fi

exit 0
endef

define Package/auto-security/prerm
#!/bin/sh
# Stop and disable service
/etc/init.d/auto-security stop
/etc/init.d/auto-security disable

# Remove cron jobs
crontab -l 2>/dev/null | grep -v "auto_ban.sh" | grep -v "monitor.sh" | crontab -

exit 0
endef

$(eval $(call BuildPackage,auto-security))