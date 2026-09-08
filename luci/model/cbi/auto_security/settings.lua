m = Map("auto_security", translate("Auto-Security Settings"),
    translate("Configure automated intrusion detection and blocking for OpenWRT."))

-- Core Detection Settings
s = m:section(NamedSection, "core", "auto_security", translate("Core Detection Settings"))

o = s:option(Value, "attack_threshold", translate("Attack Threshold"),
    translate("Number of attacks from same IP before auto-ban"))
o.datatype = "uinteger"
o.default = 3

o = s:option(Value, "scan_interval", translate("Scan Interval (minutes)"),
    translate("How often to run auto-ban detection"))
o.datatype = "uinteger"
o.default = 10

o = s:option(Value, "ban_duration", translate("Ban Duration (seconds)"),
    translate("0 = permanent, 3600 = 1 hour, 86400 = 24 hours"))
o.datatype = "uinteger"
o.default = 0

o = s:option(Value, "log_retention", translate("Log Retention (days)"))
o.datatype = "uinteger"
o.default = 30

-- IPv6
s = m:section(NamedSection, "ipv6", "auto_security", translate("IPv6 Support"))

o = s:option(Flag, "enable_ipv6", translate("Enable IPv6 Detection"),
    translate("Detect and block IPv6 attackers"))
o.default = 1

-- CIDR Banning
s = m:section(NamedSection, "cidr", "auto_security", translate("CIDR-Based Banning"))

o = s:option(Flag, "enable_cidr_ban", translate("Enable CIDR Banning"),
    translate("Automatically ban entire /24 ranges when multiple IPs attack"))
o.default = 1

o = s:option(Value, "cidr_threshold", translate("CIDR Threshold"),
    translate("Attacks from same /24 before banning entire range"))
o.datatype = "uinteger"
o.default = 8

o = s:option(Value, "cidr_prefix", translate("CIDR Prefix Length"),
    translate("Prefix length for CIDR bans (24 = /24)"))
o.datatype = "uinteger"
o.default = 24

-- Feature Flags
s = m:section(NamedSection, "features", "auto_security", translate("Feature Flags"))

o = s:option(Flag, "enable_auto_ban", translate("Enable Auto-Ban"))
o.default = 1

o = s:option(Flag, "enable_monitoring", translate("Enable Monitoring"))
o.default = 1

o = s:option(Flag, "enable_alerts", translate("Enable Alerts"))
o.default = 1

o = s:option(Flag, "enable_correlation", translate("Enable Service Correlation"),
    translate("Correlate attacks with mwan3, AdGuard, netdata"))
o.default = 1

-- Alert Settings
s = m:section(NamedSection, "alerts", "auto_security", translate("Alert Settings"))

o = s:option(ListValue, "alert_methods", translate("Alert Methods"),
    translate("Comma-separated list"))
o:value("log", "Log only")
o:value("log,webhook", "Log + Webhook")
o:value("log,email", "Log + Email")
o:value("log,webhook,email", "All methods")
o.default = "log"

o = s:option(Value, "alert_webhook_url", translate("Webhook URL"),
    translate("Slack, Discord, or custom webhook"))
o.placeholder = "https://hooks.slack.com/..."

o = s:option(Value, "alert_email", translate("Alert Email"))
o.placeholder = "admin@example.com"

o = s:option(Value, "smtp_server", translate("SMTP Server"))
o.placeholder = "smtp.gmail.com"

o = s:option(Value, "smtp_port", translate("SMTP Port"))
o.datatype = "port"
o.default = "587"

o = s:option(Value, "smtp_user", translate("SMTP Username"))
o = s:option(Value, "smtp_pass", translate("SMTP Password"))
o.password = true

o = s:option(Flag, "alert_on_new_ban", translate("Alert on New Ban"))
o.default = 1

o = s:option(Flag, "alert_on_cidr_ban", translate("Alert on CIDR Ban"))
o.default = 1

o = s:option(Value, "alert_high_volume", translate("High Volume Alert Threshold"),
    translate("Attacks per hour to trigger alert"))
o.datatype = "uinteger"
o.default = 50

-- Service Correlation
s = m:section(NamedSection, "correlation", "auto_security", translate("Service Correlation"))

o = s:option(Flag, "enable_mwan3", translate("Enable mwan3 Correlation"))
o.default = 1

o = s:option(Value, "mwan3_interfaces", translate("mwan3 Interfaces"),
    translate("Space-separated interface names"))
o.placeholder = "wan wanb"

o = s:option(Flag, "enable_adguard", translate("Enable AdGuard Correlation"))
o.default = 1

o = s:option(Value, "adguard_api_url", translate("AdGuard API URL"))
o.placeholder = "http://127.0.0.1:3000"
o.default = "http://127.0.0.1:3000"

o = s:option(Value, "adguard_api_user", translate("AdGuard API User"))
o.default = "admin"

o = s:option(DummyValue, "ag_pass_status", translate("API Password Status"))
function o.cfgvalue(self, section)
	local f = io.open("/root/adguard-admin.txt", "r")
	if f then
		f:close()
		return translate("Password is set")
	end
	return translate("No password set - stats unavailable until set below")
end

agpw1 = s:option(Value, "ag_password_new", translate("AdGuard Admin Password"))
agpw1.password = true
agpw1.rmempty = true
agpw1.description = translate("Saved to /root/adguard-admin.txt (root-only, mode 600). Leave empty to keep the current password.")

function agpw1.write(self, section, value)
	if not value or value == "" then
		return
	end
	local user = self.map:get(section, "adguard_api_user") or "admin"
	if not user or user == "" then
		user = "admin"
	end
	local cmd = string.format(
		"printf '%%s %%s' %s %s > /root/adguard-admin.txt && chmod 600 /root/adguard-admin.txt",
		luci.util.shellquote(user), luci.util.shellquote(value))
	luci.util.exec(cmd)
end

function agpw1.remove(self, section) end

o = s:option(Flag, "enable_netdata", translate("Enable Netdata Correlation"))
o.default = 1

o = s:option(Value, "netdata_api_url", translate("Netdata API URL"))
o.placeholder = "http://127.0.0.1:19999"
o.default = "http://127.0.0.1:19999"

-- Per-Service Thresholds
s = m:section(NamedSection, "thresholds", "auto_security", translate("Per-Service Thresholds"),
    translate("Override global threshold for specific services"))

o = s:option(Value, "ssh_threshold", translate("SSH (port 22)"), translate("Default: 3"))
o.datatype = "uinteger"
o.placeholder = "3"

o = s:option(Value, "http_threshold", translate("HTTP (port 80)"), translate("Default: 15"))
o.datatype = "uinteger"
o.placeholder = "15"

o = s:option(Value, "https_threshold", translate("HTTPS (port 443)"), translate("Default: 10"))
o.datatype = "uinteger"
o.placeholder = "10"

o = s:option(Value, "rdp_threshold", translate("RDP (port 3389)"), translate("Default: 2"))
o.datatype = "uinteger"
o.placeholder = "2"

o = s:option(Value, "dns_threshold", translate("DNS (port 53)"), translate("Default: 30"))
o.datatype = "uinteger"
o.placeholder = "30"

o = s:option(Value, "smtp_threshold", translate("SMTP (port 25/587)"), translate("Default: 5"))
o.datatype = "uinteger"
o.placeholder = "5"

-- Advanced
s = m:section(NamedSection, "advanced", "auto_security", translate("Advanced Settings"))

o = s:option(Value, "nft_chain", translate("nftables Chain"))
o.default = "input_wan"

o = s:option(Value, "nft_table", translate("nftables Table"))
o.default = "inet fw4"

o = s:option(Value, "log_prefix", translate("Log Prefix to Match"))
o.default = "Log-Blocked-WAN-Access"

o = s:option(Value, "max_log_entries", translate("Max Log Entries Per Scan"))
o.datatype = "uinteger"
o.default = 5000

o = s:option(Value, "live_timeout", translate("Live Monitoring Timeout (seconds)"))
o.datatype = "uinteger"
o.default = 300

o = s:option(Flag, "auto_save", translate("Auto-save Bans on Shutdown"))
o.default = 1

o = s:option(Flag, "auto_restore", translate("Auto-restore Bans on Startup"))
o.default = 1


-- API / Admin Password (like AdGuard Home admin password)
-- Required for changes via web (unban, whitelist, scan, reset).
-- Stored as SHA256 hash in /opt/auto-security/config/admin.passhash.
-- Leave both password fields empty to keep the current password.
s = m:section(NamedSection, "api_auth", "auto_security", translate("API / Admin Password"),
	translate("Password required for changes via web (unban, whitelist, scan, reset). Leave both fields empty to keep the current password."))

o = s:option(Value, "api_user", translate("Admin Username"))
o.default = "admin"
o.rmempty = false

pass_status = s:option(DummyValue, "pass_status", translate("Password Status"))
function pass_status.cfgvalue(self, section)
	local f = io.open("/opt/auto-security/config/admin.passhash", "r")
	if f then
		f:close()
		return translate("Password is set - changes require it")
	end
	return translate("No password set - changes allowed from LAN without password")
end

pw1 = s:option(Value, "api_password_new", translate("New Password"))
pw1.password = true
pw1.rmempty = true

pw2 = s:option(Value, "api_password_confirm", translate("Confirm New Password"))
pw2.password = true
pw2.rmempty = true

function pw2.validate(self, value, section)
	local v1 = pw1:formvalue(section) or ""
	value = value or ""
	if v1 == "" and value == "" then
		return value
	end
	if v1 ~= value then
		return nil, translate("Passwords do not match")
	end
	if #value < 8 then
		return nil, translate("Password must have at least 8 characters")
	end
	return value
end

function pw1.write(self, section, value)
	if not value or value == "" then
		return
	end
	local user = self.map:get(section, "api_user") or "admin"
	if not user or user == "" then
		user = "admin"
	end
	local cmd = string.format(
		"mkdir -p /opt/auto-security/config && printf '%%s' %s | sha256sum | cut -d' ' -f1 | { read h; printf '%%s:%%s\\n' %s \"$h\" > /opt/auto-security/config/admin.passhash; chmod 600 /opt/auto-security/config/admin.passhash; }",
		luci.util.shellquote(value), luci.util.shellquote(user))
	luci.util.exec(cmd)
end

function pw2.write(self, section, value)
	-- handled together with api_password_new; never stored
end

function pw1.remove(self, section) end
function pw2.remove(self, section) end

return m
