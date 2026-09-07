module("luci.controller.auto_security", package.seeall)

function index()
    local page

    page = entry({"admin", "services", "auto_security"}, alias("admin", "services", "auto_security", "overview"), _("Auto-Security"), 60)
    page.dependent = true
    page.acl_depends = { "luci-app-auto-security" }

    entry({"admin", "services", "auto_security", "overview"}, template("auto_security/overview"), _("Overview"), 10)
    entry({"admin", "services", "auto_security", "banned"}, template("auto_security/banned"), _("Banned IPs"), 20)
    entry({"admin", "services", "auto_security", "whitelist"}, template("auto_security/whitelist"), _("Whitelist"), 30)
    entry({"admin", "services", "auto_security", "settings"}, cbi("auto_security/settings"), _("Settings"), 40)
    entry({"admin", "services", "auto_security", "logs"}, template("auto_security/logs"), _("Logs"), 50)
    entry({"admin", "services", "auto_security", "correlation"}, template("auto_security/correlation"), _("Correlation"), 60)

    -- API endpoints for AJAX
    entry({"admin", "services", "auto_security", "api", "status"}, call("api_status"))
    entry({"admin", "services", "auto_security", "api", "banned"}, call("api_banned"))
    entry({"admin", "services", "auto_security", "api", "whitelist"}, call("api_whitelist"))
    entry({"admin", "services", "auto_security", "api", "whitelist_add"}, call("api_whitelist_add"))
    entry({"admin", "services", "auto_security", "api", "whitelist_remove"}, call("api_whitelist_remove"))
    entry({"admin", "services", "auto_security", "api", "unban"}, call("api_unban"))
    entry({"admin", "services", "auto_security", "api", "reset"}, call("api_reset"))
    entry({"admin", "services", "auto_security", "api", "scan"}, call("api_scan"))
    entry({"admin", "services", "auto_security", "api", "save"}, call("api_save"))
    entry({"admin", "services", "auto_security", "api", "restore"}, call("api_restore"))
    entry({"admin", "services", "auto_security", "api", "live"}, call("api_live"))
    entry({"admin", "services", "auto_security", "api", "correlation"}, call("api_correlation"))
end

local function exec_cmd(cmd)
    local util = require "luci.util"
    local result = util.exec(cmd)
    return result
end

local function json_response(data)
    local json = require "luci.jsonc"
    luci.http.prepare_content("application/json")
    luci.http.write(json.stringify(data))
end

function api_status()
    local result = exec_cmd("/opt/auto-security/monitor.sh report 2>&1")
    json_response({output = result})
end

function api_banned()
    local result = exec_cmd("/opt/auto-security/monitor.sh banned 2>&1")
    json_response({output = result})
end

function api_whitelist()
    local result = exec_cmd("/opt/auto-security/monitor.sh whitelist 2>&1")
    json_response({output = result})
end

function api_whitelist_add()
    local ip = luci.http.formvalue("ip")
    if not ip or ip == "" then
        json_response({success = false, error = "IP required"})
        return
    end
    local result = exec_cmd("/opt/auto-security/monitor.sh whitelist-add " .. luci.util.shellquote(ip) .. " 2>&1")
    json_response({success = true, output = result})
end

function api_whitelist_remove()
    local ip = luci.http.formvalue("ip")
    if not ip or ip == "" then
        json_response({success = false, error = "IP required"})
        return
    end
    local result = exec_cmd("/opt/auto-security/monitor.sh whitelist-remove " .. luci.util.shellquote(ip) .. " 2>&1")
    json_response({success = true, output = result})
end

function api_unban()
    local ip = luci.http.formvalue("ip")
    if not ip or ip == "" then
        json_response({success = false, error = "IP required"})
        return
    end
    local result = exec_cmd("/opt/auto-security/monitor.sh unban " .. luci.util.shellquote(ip) .. " 2>&1")
    json_response({success = true, output = result})
end

function api_reset()
    local result = exec_cmd("/opt/auto-security/monitor.sh reset 2>&1")
    json_response({success = true, output = result})
end

function api_scan()
    local result = exec_cmd("/opt/auto-security/auto_ban.sh 2>&1")
    json_response({success = true, output = result})
end

function api_save()
    local result = exec_cmd("/opt/auto-security/monitor.sh save 2>&1")
    json_response({success = true, output = result})
end

function api_restore()
    local result = exec_cmd("/opt/auto-security/monitor.sh restore 2>&1")
    json_response({success = true, output = result})
end

function api_live()
    -- Return last 50 attack log entries for live view
    local result = exec_cmd("logread | grep 'Log-Blocked-WAN-Access' | tail -50 2>&1")
    json_response({output = result})
end

function api_correlation()
    local result = exec_cmd("/opt/auto-security/monitor.sh correlation 2>&1")
    json_response({output = result})
end