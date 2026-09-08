module("luci.controller.auto_security", package.seeall)

function index()
	entry({"admin", "services", "auto_security"}, firstchild(), _("Auto-Security"), 60).dependent = true
	entry({"admin", "services", "auto_security", "overview"}, template("auto_security/overview"), _("Overview"), 10)
	entry({"admin", "services", "auto_security", "banned"}, template("auto_security/banned"), _("Banned IPs"), 20)
	entry({"admin", "services", "auto_security", "whitelist"}, template("auto_security/whitelist"), _("Whitelist"), 30)
	entry({"admin", "services", "auto_security", "settings"}, cbi("auto_security/settings"), _("Settings"), 40)
	entry({"admin", "services", "auto_security", "logs"}, template("auto_security/logs"), _("Logs"), 50)
	entry({"admin", "services", "auto_security", "correlation"}, template("auto_security/correlation"), _("Correlation"), 60)
end
