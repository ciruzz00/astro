package detect

import (
	"regexp"

	"github.com/ciruzz00/astro/internal/logs"
)

// commandRule flags a command line, wherever it was logged: shell history,
// sudo, cron, pkexec, Windows process creation, PowerShell script blocks,
// service image paths.
type commandRule struct {
	Rule
	re *regexp.Regexp
}

func cmd(id, title string, sev logs.Severity, technique, pattern string) commandRule {
	return commandRule{Rule{ID: id, Title: title, Severity: sev, Technique: technique}, regexp.MustCompile(pattern)}
}

// commandRules are matched case-insensitively against command lines. They
// look for the techniques attackers use on hosts, not for every admin task:
// a match is a lead to verify, with the command shown in the finding.
var commandRules = []commandRule{
	// Execution and command and control.
	cmd("cmd-reverse-shell", "Reverse shell", logs.Critical, "T1059.004",
		`(?i)(/dev/(tcp|udp)/[^/\s]+/\d+|\b(nc|ncat|netcat)\b[^|;]*\s-[a-z]*[ec]\s|\bsh\s+-i\s*[>&]|bash\s+-i\s*>&|mkfifo\s+\S+.*\b(nc|ncat|sh)\b|socat\b[^|;]*exec:|python[23]?\s+-c\s+['"].*socket.*(subprocess|pty)|php\s+-r\s+['"].*fsockopen|perl\s+-e\s+['"].*socket)`),
	cmd("cmd-download-exec", "Download piped to a shell", logs.High, "T1105",
		`(?i)\b(curl|wget|fetch)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`),
	cmd("cmd-download-tmp", "Download to a temporary directory", logs.Medium, "T1105",
		`(?i)\b(curl|wget)\b[^|;]*(\s-o\s*|\s-O\s+|--output[= ]|\s>\s*)(/tmp/|/dev/shm/|/var/tmp/)`),
	cmd("cmd-exec-tmp", "Executable made in a temporary directory", logs.Medium, "T1059.004",
		`(?i)chmod\s+(\+x|[0-7]*[1357][0-7]{0,2})\s+\S*(/tmp/|/dev/shm/|/var/tmp/)`),
	cmd("cmd-base64-exec", "Decoded payload piped to a shell", logs.High, "T1140",
		`(?i)base64\s+(-d|--decode)[^|;]*\|\s*(ba|z|da)?sh\b`),
	cmd("ps-encoded", "Encoded PowerShell command", logs.High, "T1059.001",
		`(?i)\bpowershell(\.exe)?\b.*\s-(e|ec|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}`),
	cmd("ps-download-cradle", "PowerShell download cradle", logs.High, "T1059.001",
		`(?i)(IEX|Invoke-Expression)\b.*(DownloadString|DownloadData|Invoke-WebRequest|iwr\s|Net\.WebClient)|(DownloadString|DownloadFile)\s*\(\s*['"]https?://`),
	cmd("ps-decode", "PowerShell decodes a Base64 payload", logs.Medium, "T1140",
		`(?i)FromBase64String\s*\(`),
	cmd("ps-hidden", "Hidden, policy-bypassing PowerShell", logs.Medium, "T1059.001",
		`(?i)\bpowershell(\.exe)?\b.*(-w(indowstyle)?\s+h(idden)?\b.*-(nop|noprofile|ep|exec|executionpolicy)\s|-(nop|noprofile)\b.*-w(indowstyle)?\s+h(idden)?\b)`),
	cmd("lolbin-certutil", "certutil used to download or decode", logs.High, "T1105",
		`(?i)\bcertutil(\.exe)?\b.*\s[-/](urlcache|decode|decodehex|verifyctl)\b`),
	cmd("lolbin-bitsadmin", "bitsadmin transfer", logs.High, "T1197",
		`(?i)\bbitsadmin(\.exe)?\b.*\s/(transfer|addfile|setnotifycmdline)\b`),
	cmd("lolbin-proxy-exec", "Signed binary used to run remote or script code", logs.High, "T1218",
		`(?i)\b(mshta(\.exe)?\s+(https?:|javascript:|vbscript:)|regsvr32(\.exe)?\b.*/i:\s*https?:|rundll32(\.exe)?\b.*(javascript:|url\.dll.*(OpenURL|FileProtocolHandler)))`),

	// Credential access.
	cmd("cred-sam-dump", "Registry hives with credentials saved", logs.Critical, "T1003.002",
		`(?i)\breg(\.exe)?\s+(save|export)\s+"?(HKLM|HKEY_LOCAL_MACHINE)\\(SAM|SYSTEM|SECURITY)\b`),
	cmd("cred-lsass-dump", "LSASS memory dump", logs.Critical, "T1003.001",
		`(?i)(comsvcs(\.dll)?[, ]+#?(MiniDump|24)\b|procdump(64)?(\.exe)?\b.*\blsass|sekurlsa::|\bmimikatz\b|lsadump::)`),
	cmd("cred-ntds", "Active Directory database copied", logs.Critical, "T1003.003",
		`(?i)(ntdsutil(\.exe)?\b.*\b(ifm|ac\s+i\s+ntds)|\\ntds\.dit\b|vssadmin(\.exe)?\s+create\s+shadow)`),
	cmd("cred-linux-shadow", "Password hashes read", logs.Medium, "T1003.008",
		`(?i)\b(cat|cp|less|more|head|tail|tar|scp|base64|xxd)\b[^|;]*\s/etc/(shadow|gshadow)\b|\bunshadow\b`),

	// Privilege escalation.
	cmd("privesc-potato", "Potato or print spooler privilege escalation tool", logs.High, "T1134",
		`(?i)\b(juicy|rotten|sweet|god|rogue|local|hot|lovely|sharpefs|efs)potato|printspoofer`),
	cmd("privesc-suid", "SUID bit set", logs.Medium, "T1548.001",
		`(?i)chmod\s+(u\+s|[2467][0-7]{3})\s`),

	// Persistence.
	cmd("persist-ssh-key", "SSH key planted", logs.High, "T1098.004",
		`(?i)(>>?\s*\S*authorized_keys|authorized_keys\S*\s*<|ssh-copy-id\b)`),
	cmd("persist-cron", "Cron job written from the shell", logs.High, "T1053.003",
		`(?i)(crontab\s+(-u\s+\S+\s+)?(-e\b|[^-\s]\S*)|>>?\s*/etc/cron|>>?\s*/var/spool/cron|\|\s*crontab\s+-)`),
	cmd("persist-systemd", "systemd service created or enabled", logs.Medium, "T1543.002",
		`(?i)(>>?\s*/(etc|lib|usr/lib)/systemd/system/\S+\.service|systemctl\s+(--now\s+)?enable\s)`),
	cmd("persist-shell-rc", "Shell startup file modified", logs.Medium, "T1546.004",
		`(?i)>>?\s*\S*(\.bashrc|\.bash_profile|\.profile|\.zshrc|/etc/profile|/etc/bash\.bashrc)\b`),
	cmd("persist-schtasks", "Scheduled task created from the command line", logs.Medium, "T1053.005",
		`(?i)\bschtasks(\.exe)?\s+/create\b`),
	cmd("persist-sc-create", "Service created from the command line", logs.Medium, "T1543.003",
		`(?i)\bsc(\.exe)?\s+(\\\\\S+\s+)?create\s`),
	cmd("persist-run-key", "Run key written", logs.Medium, "T1547.001",
		`(?i)\breg(\.exe)?\s+add\s+"?\S*\\(Run|RunOnce)\b`),
	cmd("account-add", "Local account created from the command line", logs.Medium, "T1136.001",
		`(?i)(\bnet1?(\.exe)?\s+user\s+\S+\s+\S*\s*/add\b|\buseradd\b|\badduser\b)`),
	cmd("account-admin", "Account added to an administrators group", logs.High, "T1098",
		`(?i)(\bnet1?(\.exe)?\s+(localgroup|group)\s+"?(administrators|domain admins|enterprise admins|remote desktop users)"?\s+\S+.*/add\b|\busermod\b.*\s-[a-zA-Z]*G\s*\S*\b(sudo|wheel|admin|root|docker|lxd)\b|\bgpasswd\s+-a\s+\S+\s+(sudo|wheel|admin|root|docker|lxd)\b)`),

	// Defense evasion.
	cmd("evasion-clear-history", "Shell history cleared or disabled", logs.High, "T1070.003",
		`(?i)(history\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|(rm|shred|truncate)\b[^|;]*\.(bash|zsh|sh)_history|ln\s+-sf?\s+/dev/null\s+\S*_history)`),
	cmd("evasion-clear-logs", "Logs deleted or truncated", logs.High, "T1070.002",
		`(?i)((rm|shred|truncate)\b[^|;]*\s/var/log/|>\s*/var/log/\S+|journalctl\s+--(vacuum|rotate)|\bwevtutil(\.exe)?\s+(cl|clear-log)\b|Clear-EventLog\b|Remove-EventLog\b)`),
	cmd("evasion-defender", "Antivirus protection disabled", logs.High, "T1562.001",
		`(?i)(Set-MpPreference\b.*-Disable\w+\s+\$?true|Add-MpPreference\b.*-ExclusionPath|DisableRealtimeMonitoring|sc(\.exe)?\s+(stop|config)\s+WinDefend)`),
	cmd("evasion-firewall", "Firewall disabled", logs.Medium, "T1562.004",
		`(?i)(netsh(\.exe)?\s+(adv)?firewall\s+set\s+\S+\s+state\s+off|ufw\s+disable|iptables\s+-F\b|systemctl\s+(stop|disable)\s+(firewalld|ufw))`),

	// Impact.
	cmd("impact-shadow-delete", "Backups or shadow copies deleted", logs.Critical, "T1490",
		`(?i)(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)|bcdedit(\.exe)?\s+/set\s+\S+\s+recoveryenabled\s+no)`),

	// Lateral movement and discovery.
	cmd("lateral-psexec", "PsExec or remote service execution", logs.Medium, "T1569.002",
		`(?i)\b(psexec(64)?(\.exe)?|psexesvc|paexec)\b`),
	cmd("discovery-domain", "Domain discovery commands", logs.Low, "T1087.002",
		`(?i)(\bnet1?(\.exe)?\s+(user|group)\s+.*/domain\b|\bnltest(\.exe)?\s+/(dclist|domain_trusts)|\bdsquery\b|Get-AD(User|Group|Computer)\b|\bAdFind\b|\bbloodhound\b|\bsharphound\b)`),
	cmd("discovery-privileges", "Privileges enumerated", logs.Low, "T1033",
		`(?i)\bwhoami(\.exe)?\s+/(priv|all|groups)\b|\bsudo\s+-l\b`),
	cmd("discovery-tools", "Enumeration or scanning tool run", logs.Medium, "T1046",
		`(?i)\b(linpeas|winpeas|linenum|pspy|nmap|masscan|rustscan|chisel|ligolo|seatbelt|powerup|privesc)\b`),
}
