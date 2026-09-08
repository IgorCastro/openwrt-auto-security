m = Map("auto_security", translate("Auto-Security Settings"),
	translate("Automated intrusion detection and blocking. Changes apply on Save."))

-- Core Detection Settings (all consumed by auto_ban.sh)
s = m:section(NamedSection, "core", "auto_security", translate("Detection"))
s.addremove = false

o = s:option(Value, "attack_threshold", translate("Attack Threshold"),
	translate("Attacks from the same IP before auto-ban"))
o.datatype = "uinteger"
o.default = 3

o = s:option(Value, "scan_interval", translate("Scan Interval (minutes)"),
	translate("How often the detector runs (cron). Re-run install or edit crontab to apply."))
o.datatype = "uinteger"
o.default = 10

o = s:option(Value, "ban_duration", translate("Ban Duration (seconds)"),
	translate("0 = permanent, 3600 = 1 hour, 86400 = 24 hours"))
o.datatype = "uinteger"
o.default = 0

o = s:option(Value, "log_retention", translate("Log Retention (days)"))
o.datatype = "uinteger"
o.default = 30

-- IPv6 (consumed by auto_ban.sh)
s = m:section(NamedSection, "ipv6", "auto_security", translate("IPv6"))
s.addremove = false

o = s:option(Flag, "enable_ipv6", translate("Detect and block IPv6 attackers"))
o.default = 1
o.rmempty = false

-- CIDR-Based Banning (consumed by auto_ban.sh)
s = m:section(NamedSection, "cidr", "auto_security", translate("CIDR Auto-Ban"))
s.addremove = false

o = s:option(Flag, "enable_cidr_ban", translate("Ban whole ranges when a botnet attacks"),
	translate("Bans the entire prefix when many IPs from the same range attack"))
o.default = 1
o.rmempty = false

o = s:option(Value, "cidr_threshold", translate("CIDR Threshold"),
	translate("Attacks from the same range before banning it"))
o.datatype = "uinteger"
o.default = 8

o = s:option(Value, "cidr_prefix", translate("CIDR Prefix Length"),
	translate("24 = /24, 16 = /16"))
o.datatype = "uinteger"
o.default = 24

-- Correlation (only fields consumed by monitor.sh)
s = m:section(NamedSection, "correlation", "auto_security", translate("AdGuard Correlation"))
s.addremove = false

o = s:option(Value, "adguard_api_url", translate("AdGuard API URL"))
o.default = "http://127.0.0.1:3000"

o = s:option(Value, "adguard_api_user", translate("AdGuard Admin User"))
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

-- API / Admin Password (protects web changes: unban, whitelist, scan, reset)
s = m:section(NamedSection, "api_auth", "auto_security", translate("API / Admin Password"))
s.addremove = false
s.description = translate("Password required for changes via web. Stored as SHA256 hash in /opt/auto-security/config/admin.passhash. Leave both fields empty to keep the current password.")

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
