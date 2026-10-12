package evtx

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// KindEvent is the kind of every Windows event; rules match on EventID,
// Channel and Provider.
const KindEvent = "windows-event"

// toEvent maps a decoded record to an event.
func toEvent(root *node, recordID uint64, written time.Time, opts logs.Options) *logs.Event {
	ev := find(root, "Event")
	if ev == nil {
		ev = root
	}
	sys := child(ev, "System")
	provider := attrOf(child(sys, "Provider"), "Name")
	if provider == "" {
		provider = attrOf(child(sys, "Provider"), "EventSourceName")
	}
	id, _ := strconv.Atoi(textOf(child(sys, "EventID")))
	e := &logs.Event{
		Time: written, Source: opts.Source, Kind: KindEvent, EventID: id, Provider: provider,
		Channel: textOf(child(sys, "Channel")), Host: textOf(child(sys, "Computer")),
		Fields: map[string]string{},
	}
	if t, ok := parseTime(attrOf(child(sys, "TimeCreated"), "SystemTime")); ok {
		e.Time = t
	}
	set := func(k, v string) {
		if v != "" {
			e.Fields[k] = v
		}
	}
	set("record_id", firstNonEmpty(textOf(child(sys, "EventRecordID")), strconv.FormatUint(recordID, 10)))
	set("level", textOf(child(sys, "Level")))
	set("task", textOf(child(sys, "Task")))
	set("keywords", textOf(child(sys, "Keywords")))
	set("process_id", attrOf(child(sys, "Execution"), "ProcessID"))
	set("user_sid", attrOf(child(sys, "Security"), "UserID"))

	data := eventData(ev)
	for k, v := range data {
		if _, taken := e.Fields[k]; !taken {
			e.Fields[k] = v
		}
	}
	key := sourceKey(provider) + ":" + strconv.Itoa(id)
	if groupEvents[key] {
		// TargetUserName is the group: the user is who changed it.
		e.User = pick(data, "SubjectUserName")
	} else {
		e.User = pick(data, "TargetUserName", "SubjectUserName", "User", "UserName", "AccountName", "Param1")
	}
	if ip, ok := address(pick(data, "IpAddress", "SourceAddress", "SourceIp", "ClientAddress", "ClientIP", "Address")); ok {
		e.SrcIP = ip
	}
	if ip, ok := address(pick(data, "DestAddress", "DestinationIp")); ok {
		e.DstIP = ip
	}
	e.Process = pick(data, "NewProcessName", "Image", "ProcessName", "Application")
	e.Parent = pick(data, "ParentProcessName", "ParentImage")
	e.CommandLine = pick(data, "CommandLine", "ScriptBlockText", "ImagePath", "ServiceFileName", "Payload")

	if msg := textOf(child(child(ev, "RenderingInfo"), "Message")); msg != "" {
		e.Message = msg // forwarded events carry the rendered text
	} else {
		e.Message = message(e, data)
	}
	e.Severity = baseline[key]
	e.Raw = renderXML(ev)
	return e
}

// eventData flattens EventData (Data elements, named or numbered) and
// UserData (the leaf elements of the provider's own element).
func eventData(ev *node) map[string]string {
	out := map[string]string{}
	add := func(k, v string) {
		if v = strings.TrimSpace(v); v == "" {
			return
		}
		key := k
		for i := 2; ; i++ {
			if _, dup := out[key]; !dup {
				break
			}
			key = k + strconv.Itoa(i)
		}
		out[key] = v
	}
	if ed := child(ev, "EventData"); ed != nil {
		n := 0
		for _, c := range ed.children {
			n++
			name := attrOf(c, "Name")
			if name == "" {
				name = c.name
				if c.name == "Data" {
					name = "Data" + strconv.Itoa(n)
				}
			}
			add(name, c.text.String())
		}
	}
	if ud := child(ev, "UserData"); ud != nil {
		var walk func(n *node, depth int)
		walk = func(n *node, depth int) {
			if depth > maxDepth {
				return
			}
			if len(n.children) == 0 {
				add(n.name, n.text.String())
				return
			}
			for _, c := range n.children {
				walk(c, depth+1)
			}
		}
		for _, c := range ud.children {
			walk(c, 0)
		}
	}
	return out
}

// pick returns the first meaningful value among keys ("-" means none).
func pick(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" && v != "-" {
			return v
		}
	}
	return ""
}

// address normalizes an IP from event data ("::ffff:192.0.2.1", "-").
func address(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

// sourceKey groups providers under the short keys of the tables below.
func sourceKey(provider string) string {
	p := strings.ToLower(provider)
	switch {
	case strings.Contains(p, "security-auditing"):
		return "sec"
	case strings.Contains(p, "eventlog"):
		return "eventlog"
	case strings.Contains(p, "sysmon"):
		return "sysmon"
	case strings.Contains(p, "powershell"):
		return "powershell"
	case p == "service control manager":
		return "scm"
	case strings.Contains(p, "windows defender"):
		return "defender"
	case strings.Contains(p, "terminalservices-localsessionmanager"):
		return "rdp-session"
	case strings.Contains(p, "terminalservices-remoteconnectionmanager"):
		return "rdp-auth"
	case strings.Contains(p, "taskscheduler"):
		return "tasks"
	case strings.Contains(p, "bits-client"):
		return "bits"
	case strings.Contains(p, "winrm"):
		return "winrm"
	}
	return p
}

// descriptions of the events most often met in investigations.
var descriptions = map[string]string{
	"sec:4624": "Logon", "sec:4625": "Failed logon", "sec:4634": "Logoff", "sec:4647": "User initiated logoff",
	"sec:4648": "Logon with explicit credentials", "sec:4672": "Special privileges assigned to a new logon",
	"sec:4688": "Process created", "sec:4689": "Process exited", "sec:4697": "Service installed",
	"sec:4698": "Scheduled task created", "sec:4699": "Scheduled task deleted", "sec:4700": "Scheduled task enabled",
	"sec:4702": "Scheduled task updated", "sec:4719": "Audit policy changed", "sec:4720": "User account created",
	"sec:4722": "User account enabled", "sec:4723": "Password change attempt", "sec:4724": "Password reset attempt",
	"sec:4725": "User account disabled", "sec:4726": "User account deleted", "sec:4728": "Member added to a global security group",
	"sec:4729": "Member removed from a global security group", "sec:4733": "Member removed from a local security group",
	"sec:4757": "Member removed from a universal security group", "sec:4767": "User account unlocked",
	"sec:4732": "Member added to a local security group", "sec:4738": "User account changed",
	"sec:4740": "User account locked out", "sec:4756": "Member added to a universal security group",
	"sec:4662": "Operation performed on a directory object", "sec:4768": "Kerberos TGT requested",
	"sec:4769": "Kerberos service ticket requested", "sec:4771": "Kerberos pre-authentication failed",
	"sec:4776": "NTLM credential validation", "sec:4778": "Session reconnected", "sec:4779": "Session disconnected",
	"sec:4798": "Local group membership of a user enumerated", "sec:4799": "Local group membership enumerated",
	"sec:5140": "Network share accessed", "sec:5145": "Network share object checked", "sec:5156": "Network connection allowed",
	"eventlog:1102": "Security audit log cleared", "eventlog:104": "Event log cleared",
	"sysmon:1": "Process created", "sysmon:3": "Network connection", "sysmon:7": "Image loaded",
	"sysmon:8": "Remote thread created", "sysmon:10": "Process accessed", "sysmon:11": "File created",
	"sysmon:12": "Registry object created or deleted", "sysmon:13": "Registry value set", "sysmon:22": "DNS query",
	"sysmon:23": "File deleted", "powershell:4103": "PowerShell pipeline executed", "powershell:4104": "PowerShell script block",
	"powershell:400": "PowerShell engine started", "powershell:600": "PowerShell provider started",
	"scm:7045": "Service installed", "scm:7036": "Service state changed", "scm:7040": "Service start type changed",
	"defender:1116": "Malware detected", "defender:1117": "Malware action taken", "defender:5001": "Real-time protection disabled",
	"rdp-session:21": "RDP logon", "rdp-session:22": "RDP shell started", "rdp-session:24": "RDP session disconnected",
	"rdp-session:25": "RDP session reconnected", "rdp-auth:1149": "RDP authentication succeeded",
	"tasks:106": "Scheduled task registered", "tasks:200": "Scheduled task action started", "tasks:201": "Scheduled task action completed",
	"bits:59": "BITS transfer started", "winrm:91": "WinRM session created",
}

// baseline severities before the detection rules weigh the context.
var baseline = map[string]logs.Severity{
	"eventlog:1102": logs.High, "eventlog:104": logs.High,
	"sec:4625": logs.Low, "sec:4771": logs.Low, "sec:4740": logs.Low,
	"sec:4720": logs.Medium, "sec:4726": logs.Medium, "sec:4728": logs.Medium, "sec:4732": logs.Medium,
	"sec:4756": logs.Medium, "sec:4724": logs.Medium, "sec:4719": logs.Medium,
	"sec:4697": logs.Medium, "scm:7045": logs.Medium, "sec:4698": logs.Medium, "tasks:106": logs.Medium,
	"defender:1116": logs.High, "defender:1117": logs.High, "defender:5001": logs.High,
}

// Security events about groups and accounts, where TargetUserName is the
// object changed and SubjectUserName who changed it.
var (
	groupEvents = map[string]bool{
		"sec:4727": true, "sec:4728": true, "sec:4729": true, "sec:4731": true, "sec:4732": true, "sec:4733": true,
		"sec:4754": true, "sec:4756": true, "sec:4757": true, "sec:4799": true,
	}
	accountEvents = map[string]bool{
		"sec:4720": true, "sec:4722": true, "sec:4723": true, "sec:4724": true, "sec:4725": true, "sec:4726": true,
		"sec:4738": true, "sec:4740": true, "sec:4767": true, "sec:4781": true, "sec:4798": true,
	}
)

// message builds a readable line from the description and the key fields.
func message(e *logs.Event, data map[string]string) string {
	key := sourceKey(e.Provider) + ":" + strconv.Itoa(e.EventID)
	desc := descriptions[key]
	if desc == "" {
		desc = "Event " + strconv.Itoa(e.EventID)
		if e.Provider != "" {
			desc += " from " + e.Provider
		}
	}
	var parts []string
	add := func(label, v string) {
		if v != "" {
			parts = append(parts, label+" "+v)
		}
	}
	switch {
	case groupEvents[key]:
		add("group", pick(data, "TargetUserName", "GroupName"))
		add("member", pick(data, "MemberName", "MemberSid"))
		add("by", pick(data, "SubjectUserName"))
		return join(desc, parts)
	case accountEvents[key]:
		add("account", pick(data, "TargetUserName"))
		add("by", pick(data, "SubjectUserName"))
		add("from", pick(data, "TargetDomainName", "CallerComputerName"))
		return join(desc, parts)
	}
	add("user", e.User)
	add("from", firstNonEmpty(e.SrcIP, pick(data, "WorkstationName", "Workstation")))
	add("to", e.DstIP)
	add("logon type", pick(data, "LogonType"))
	add("service", pick(data, "ServiceName"))
	add("task", pick(data, "TaskName"))
	add("process", e.Process)
	if e.CommandLine != "" {
		add("command", logs.Truncate(e.CommandLine, 300))
	}
	return join(desc, parts)
}

func join(desc string, parts []string) string {
	if len(parts) == 0 {
		return desc
	}
	return fmt.Sprintf("%s: %s", desc, strings.Join(parts, ", "))
}

// Tree helpers.

func child(n *node, name string) *node {
	if n == nil {
		return nil
	}
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

// find looks for the first element with this name, breadth first.
func find(n *node, name string) *node {
	queue := []*node{n}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.name == name {
			return cur
		}
		queue = append(queue, cur.children...)
	}
	return nil
}

func attrOf(n *node, name string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.attrs {
		if a.name == name {
			return a.value
		}
	}
	return ""
}

func textOf(n *node) string {
	if n == nil {
		return ""
	}
	return strings.TrimSpace(n.text.String())
}

var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

// renderXML writes the event back as compact XML for the raw view.
func renderXML(n *node) string {
	var b strings.Builder
	var walk func(n *node, depth int)
	walk = func(n *node, depth int) {
		if depth > maxDepth || b.Len() > logs.MaxRaw {
			return
		}
		b.WriteString("<" + n.name)
		for _, a := range n.attrs {
			b.WriteString(" " + a.name + `="` + xmlEscaper.Replace(a.value) + `"`)
		}
		if len(n.children) == 0 && n.text.Len() == 0 {
			b.WriteString("/>")
			return
		}
		b.WriteString(">")
		b.WriteString(xmlEscaper.Replace(n.text.String()))
		for _, c := range n.children {
			walk(c, depth+1)
		}
		b.WriteString("</" + n.name + ">")
	}
	walk(n, 0)
	return logs.Truncate(strings.ToValidUTF8(b.String(), "\uFFFD"), logs.MaxRaw)
}
