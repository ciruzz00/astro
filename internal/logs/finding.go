package logs

import "time"

// Finding is what a detection rule concluded from one or more events.
type Finding struct {
	ID       int64    `json:"id,omitempty"`
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	// Technique is a MITRE ATT&CK technique ID (T1110, T1059.004...).
	Technique string    `json:"technique,omitempty"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Host      string    `json:"host,omitempty"`
	User      string    `json:"user,omitempty"`
	SrcIP     string    `json:"src_ip,omitempty"`
	// Summary explains the finding in one or two sentences.
	Summary string `json:"summary"`
	// Count is how many events matched; EventIDs keeps the first of them
	// as references to the evidence.
	Count    int     `json:"count"`
	EventIDs []int64 `json:"event_ids,omitempty"`
}

// MaxFindingEvents bounds the event references kept by a finding.
const MaxFindingEvents = 200
