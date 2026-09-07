# Auto-Security LUCI Module Makefile

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-auto-security
PKG_VERSION:=2.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Igor Castro <igor@castro.com>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-auto-security
	SECTION:=luci
	CATEGORY:=LuCI
	SUBMENU:=3. Applications
	TITLE:=Auto-Security - Automated Intrusion Detection and Blocking
	DEPENDS:=+luci-base +luci-compat +nftables +logread +coreutils-timeout +curl
	PKGARCH:=all
endef

define Package/luci-app-auto-security/description
	LuCI web interface for OpenWRT Auto-Security system.
	Provides web-based management for automated intrusion detection,
	IP banning, whitelist management, and service correlation.
endef

define Build/Compile
	# Nothing to compile - pure Lua/HTML
endef

define Package/luci-app-auto-security/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./luci/controller/auto_security.lua $(1)/usr/lib/lua/luci/controller/auto_security.lua
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/auto_security
	$(INSTALL_DATA) ./luci/view/auto_security/*.htm $(1)/usr/lib/lua/luci/view/auto_security/
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi/auto_security
	$(INSTALL_DATA) ./luci/model/cbi/auto_security/settings.lua $(1)/usr/lib/lua/luci/model/cbi/auto_security/settings.lua
	
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./luci/root/etc/config/auto_security $(1)/etc/config/auto_security
endef

$(eval $(call BuildPackage,luci-app-auto-security))