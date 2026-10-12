package detect

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/logs/access"
	"github.com/ciruzz00/astro/internal/logs/syslog"
)

// eventRule flags single events.
type eventRule struct {
	Rule
	match   func(e *logs.Event) bool
	group   func(e *logs.Event) string // default: host and user
	example func(e *logs.Event) string // default: the event message
}

// Provider families of Windows events.
func provider(e *logs.Event, part string) bool {
	return strings.Contains(strings.ToLower(e.Provider), part)
}

func security(e *logs.Event, ids ...int) bool {
	return provider(e, "security-auditing") && hasID(e, ids)
}

func hasID(e *logs.Event, ids []int) bool {
	for _, id := range ids {
		if e.EventID == id {
			return true
		}
	}
	return false
}

func field(e *logs.Event, k string) string { return strings.TrimSpace(e.Fields[k]) }

// Privileged Windows groups, by name and by well-known RID.
var (
	adminGroups = regexp.MustCompile(`(?i)^(administrators|domain admins|enterprise admins|schema admins|backup operators|remote desktop users|account operators|server operators|dnsadmins|group policy creator owners)$`)
	adminRIDs   = regexp.MustCompile(`-(544|512|518|519|551|555|548|549)$`)
	linuxAdmins = regexp.MustCompile(`^(sudo|wheel|admin|root|docker|lxd|disk|shadow)$`)

	suspiciousService = regexp.MustCompile(`(?i)(cmd(\.exe)?"?\s*/[ck]|%comspec%|powershell|pwsh|\\temp\\|\\users\\|\\programdata\\|\\appdata\\|\\windows\\tasks\\|\.(bat|cmd|ps1|vbs|js|hta)\b|rundll32|regsvr32|mshta|psexesvc|\\\\127\.0\.0\.1\\|\badmin\$)`)
	suspiciousTask    = regexp.MustCompile(`(?i)(powershell|pwsh|cmd(\.exe)?\s*/c|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|\\temp\\|\\appdata\\|\\users\\public\\|https?://)`)
	shellCommand      = regexp.MustCompile(`(?i)^(\S*/)?((ba|z|da|k|c|tc)?sh|su)(\s+-[il]*\s*|\s*$)|\s-i\s*$|^(\S*/)?(vi|vim|less|more|find|awk|python[23]?|perl|ruby|nmap|env)\b.*(-c|-e|-exec|!/bin/sh|os\.system|pty\.spawn)`)
	lsassAccess       = regexp.MustCompile(`(?i)^0x(1010|1410|1438|143a|1fffff|1f3fff|1f1fff|1f0fff|1418|1438)$`)
	// Processes that open LSASS as part of Windows itself or of the antivirus.
	lsassReaders       = regexp.MustCompile(`(?i)\\windows\\system32\\(wbem\\wmiprvse|svchost|csrss|wininit|lsm|services|smss|lsass|taskmgr|vmtoolsd)\.exe$|\\windows defender\\(platform\\[^\\]+\\)?msmpeng\.exe$|\\program files\\windows defender\\`)
	trustedServicePath = regexp.MustCompile(`(?i)\\(microsoft\\)?windows defender\\`)
	systemDriver       = regexp.MustCompile(`(?i)^\\?(systemroot|\??\\c:\\windows|c:\\windows)\\system32\\drivers\\[^\\]+\.sys$|^system32\\drivers\\[^\\]+\.sys$`)
	replicationRights  = regexp.MustCompile(`(?i)(1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c)`)

	// Web requests.
	scannerUA  = regexp.MustCompile(`(?i)(nmap|nikto|sqlmap|gobuster|dirbuster|dirb/|feroxbuster|ffuf|wfuzz|nuclei|masscan|zgrab|wpscan|hydra|acunetix|nessus|openvas|qualys|burp|zap/|arachni|whatweb|httpx|commix|xsstrike|jaeles|metasploit)`)
	scriptedUA = regexp.MustCompile(`(?i)^(python-requests|python-urllib|curl/|wget/|go-http-client|libwww-perl|okhttp|aiohttp|httpie|java/|ruby|powershell|axios/|node-fetch)`)
	webAttack  = regexp.MustCompile(`(?i)(\.\./|\.\.%2f|%2e%2e(/|%2f)|/etc/(passwd|shadow|hosts)\b|c:\\windows\\win\.ini|\bunion(\s|\+|%20)+(all(\s|\+|%20)+)?select\b|'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d|\bsleep\(\d+\)|benchmark\(|<script|%3cscript|javascript:|onerror\s*=|\$\{jndi:|\$%7bjndi|;\s*(wget|curl|nc|bash|sh|id|whoami)\b|\|\s*(id|whoami|uname)\b|` + "`" + `(id|whoami)` + "`" + `|/bin/(ba)?sh|cmd\.exe|powershell|/\.git/|/\.env\b|/wp-config\.php|/cgi-bin/.*\.(sh|cgi)|%00|php://|file://|expect://|data://text|\bexec\(|eval\(|base64_decode\()`)
)

func webGroup(e *logs.Event) string { return e.SrcIP + "|" + field(e, "client") }
func webExample(e *logs.Event) string {
	return field(e, "method") + " " + field(e, "path") + " → " + field(e, "status")
}

var eventRules = []eventRule{
	// Windows: logs, accounts, persistence, credentials.
	{Rule: Rule{"win-log-cleared", "Event log cleared", logs.Critical, "T1070.001"},
		match: func(e *logs.Event) bool { return provider(e, "eventlog") && hasID(e, []int{1102, 104}) }},
	{Rule: Rule{"win-user-created", "User account created", logs.Medium, "T1136.001"},
		match: func(e *logs.Event) bool { return security(e, 4720) && !bySystem(e) }},
	{Rule: Rule{"win-user-created-by-system", "User account created by the system (setup, domain join or SYSTEM context)", logs.Low, "T1136.001"},
		match: func(e *logs.Event) bool { return security(e, 4720) && bySystem(e) }},
	{Rule: Rule{"win-admin-group", "Account added to a privileged group", logs.High, "T1098"},
		match: func(e *logs.Event) bool { return privilegedGroup(e) && !bySystem(e) }},
	{Rule: Rule{"win-admin-group-by-system", "Account added to a privileged group by the system (setup, domain join or SYSTEM context)", logs.Low, "T1098"},
		match: func(e *logs.Event) bool { return privilegedGroup(e) && bySystem(e) }},
	{Rule: Rule{"win-service-installed", "Service installed", logs.Medium, "T1543.003"},
		match: func(e *logs.Event) bool {
			return serviceInstall(e) && !systemDriver.MatchString(strings.Trim(e.CommandLine, `" `))
		},
		group: func(e *logs.Event) string { return strings.ToLower(e.Host) },
		example: func(e *logs.Event) string {
			return field(e, "ServiceName") + ": " + e.CommandLine
		}},
	{Rule: Rule{"win-service-suspicious", "Service runs a script, shell or file from a user folder", logs.High, "T1543.003"},
		match: func(e *logs.Event) bool {
			return serviceInstall(e) && suspiciousService.MatchString(e.CommandLine) && !trustedServicePath.MatchString(e.CommandLine)
		},
		example: func(e *logs.Event) string { return field(e, "ServiceName") + ": " + e.CommandLine }},
	{Rule: Rule{"win-task-created", "Scheduled task created", logs.Medium, "T1053.005"},
		match: func(e *logs.Event) bool {
			return security(e, 4698) || (provider(e, "taskscheduler") && e.EventID == 106)
		},
		group: func(e *logs.Event) string { return e.Host + "|" + field(e, "TaskName") }},
	{Rule: Rule{"win-task-suspicious", "Scheduled task runs a script, shell or download", logs.High, "T1053.005"},
		match: func(e *logs.Event) bool {
			return security(e, 4698) && suspiciousTask.MatchString(field(e, "TaskContent"))
		}},
	{Rule: Rule{"win-dcsync", "Directory replication requested by an account (DCSync)", logs.Critical, "T1003.006"},
		match: func(e *logs.Event) bool {
			return security(e, 4662) && replicationRights.MatchString(field(e, "Properties")) && !strings.HasSuffix(field(e, "SubjectUserName"), "$")
		}},
	{Rule: Rule{"win-asrep-roast", "Kerberos ticket without pre-authentication (AS-REP roasting)", logs.High, "T1558.004"},
		match: func(e *logs.Event) bool { return security(e, 4768) && field(e, "PreAuthType") == "0" }},
	{Rule: Rule{"win-lsass-access", "LSASS memory opened by another process", logs.Critical, "T1003.001"},
		match: func(e *logs.Event) bool {
			return provider(e, "sysmon") && e.EventID == 10 && strings.HasSuffix(strings.ToLower(field(e, "TargetImage")), `\lsass.exe`) &&
				lsassAccess.MatchString(field(e, "GrantedAccess")) && !lsassReaders.MatchString(field(e, "SourceImage"))
		},
		example: func(e *logs.Event) string {
			return field(e, "SourceImage") + " → lsass.exe (" + field(e, "GrantedAccess") + ")"
		}},
	{Rule: Rule{"win-defender-detection", "Malware detected by Microsoft Defender", logs.High, ""},
		match:   func(e *logs.Event) bool { return provider(e, "windows defender") && hasID(e, []int{1116, 1117}) },
		example: func(e *logs.Event) string { return field(e, "Threat Name") + " " + field(e, "Path") }},
	{Rule: Rule{"win-defender-disabled", "Microsoft Defender protection disabled", logs.High, "T1562.001"},
		match: func(e *logs.Event) bool { return provider(e, "windows defender") && hasID(e, []int{5001, 5010, 5012}) }},
	{Rule: Rule{"win-audit-policy", "Audit policy changed", logs.Medium, "T1562.002"},
		match: func(e *logs.Event) bool { return security(e, 4719) }},
	{Rule: Rule{"win-pass-the-hash", "Logon with injected credentials (pass the hash)", logs.High, "T1550.002"},
		match: func(e *logs.Event) bool {
			return security(e, 4624) && field(e, "LogonType") == "9" && strings.EqualFold(field(e, "LogonProcessName"), "seclogo")
		}},
	{Rule: Rule{"win-rdp-logon", "Remote Desktop logon", logs.Low, "T1021.001"},
		match: func(e *logs.Event) bool {
			return (security(e, 4624) && field(e, "LogonType") == "10") || (provider(e, "remoteconnectionmanager") && e.EventID == 1149)
		},
		group: func(e *logs.Event) string { return e.Host + "|" + e.SrcIP + "|" + strings.ToLower(e.User) }},

	// Linux: accounts, privilege use, log tampering.
	{Rule: Rule{"linux-user-created", "User account created", logs.Medium, "T1136.001"},
		match: func(e *logs.Event) bool {
			return e.Kind == syslog.KindUserCreated && !systemAccount(e) && field(e, "uid") != "0"
		}},
	{Rule: Rule{"linux-uid0-user", "Account created with UID 0 (a second root)", logs.Critical, "T1136.001"},
		match: func(e *logs.Event) bool { return e.Kind == syslog.KindUserCreated && field(e, "uid") == "0" }},
	{Rule: Rule{"linux-admin-group", "Account added to a privileged group", logs.High, "T1098"},
		match: func(e *logs.Event) bool {
			return e.Kind == syslog.KindGroupMember && linuxAdmins.MatchString(field(e, "group"))
		},
		group: func(e *logs.Event) string { return e.Host + "|" + e.User + "|" + field(e, "group") }},
	{Rule: Rule{"linux-sudo-denied", "Privilege escalation refused", logs.Medium, "T1548.003"},
		match: func(e *logs.Event) bool { return e.Kind == syslog.KindSudoDenied || e.Kind == syslog.KindPkexecDenied }},
	{Rule: Rule{"linux-root-shell", "Root shell through sudo or pkexec", logs.Medium, "T1548.003"},
		match: func(e *logs.Event) bool {
			return (e.Kind == syslog.KindSudo || e.Kind == syslog.KindPkexec) && shellCommand.MatchString(strings.TrimSpace(e.CommandLine))
		}},
	{Rule: Rule{"linux-root-ssh", "Direct SSH login as root", logs.Medium, "T1078.003"},
		match: func(e *logs.Event) bool { return e.Kind == syslog.KindSSHAccepted && e.User == "root" },
		group: func(e *logs.Event) string { return e.Host + "|" + e.SrcIP }},
	{Rule: Rule{"log-truncated", "Log truncated while being written or abrupt stop", logs.High, "T1070.002"},
		match: func(e *logs.Event) bool { return e.Kind == logs.KindNULPadding },
		group: func(e *logs.Event) string { return e.Host + "|" + e.Source + "|" + e.Ref.Record }},

	// Web requests (access logs and containers).
	{Rule: Rule{"web-attack", "Exploitation attempt in a web request", logs.High, "T1190"},
		match: func(e *logs.Event) bool {
			return e.Kind == access.KindRequest && webAttack.MatchString(field(e, "path")+" "+field(e, "user_agent")+" "+field(e, "referer"))
		},
		group: webGroup, example: webExample},
	{Rule: Rule{"web-scanner", "Web scanner or attack tool", logs.Medium, "T1595.002"},
		match: func(e *logs.Event) bool {
			return e.Kind == access.KindRequest && scannerUA.MatchString(field(e, "user_agent"))
		},
		group: webGroup, example: func(e *logs.Event) string { return field(e, "user_agent") }},
	{Rule: Rule{"web-scripted-client", "Scripted HTTP client", logs.Low, ""},
		match: func(e *logs.Event) bool {
			return e.Kind == access.KindRequest && scriptedUA.MatchString(field(e, "user_agent")) && !scannerUA.MatchString(field(e, "user_agent")) &&
				!loopback(e.SrcIP) // local health checks
		},
		group: webGroup, example: func(e *logs.Event) string { return field(e, "user_agent") }},
}

// bySystem reports changes made by a computer account (names ending in $):
// Windows setup, domain joins, or code running as SYSTEM.
func bySystem(e *logs.Event) bool { return strings.HasSuffix(field(e, "SubjectUserName"), "$") }

func privilegedGroup(e *logs.Event) bool {
	return security(e, 4728, 4732, 4756) && (adminGroups.MatchString(field(e, "TargetUserName")) || adminRIDs.MatchString(field(e, "TargetSid")))
}

func serviceInstall(e *logs.Event) bool {
	return (provider(e, "service control manager") && e.EventID == 7045) || security(e, 4697)
}

// systemAccount reports service accounts made by package installs: a low
// UID and no login shell.
func systemAccount(e *logs.Event) bool {
	uid, err := strconv.Atoi(field(e, "uid"))
	shell := field(e, "shell")
	return err == nil && uid > 0 && uid < 1000 && (strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false"))
}

func loopback(ip string) bool { return ip == "127.0.0.1" || ip == "::1" }

// number reads a numeric field, 0 when absent.
func number(e *logs.Event, k string) int {
	n, _ := strconv.Atoi(field(e, k))
	return n
}
