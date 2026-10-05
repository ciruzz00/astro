// Package ioc detects, validates and normalizes indicators of compromise
// and other threat intelligence identifiers (CVE, MITRE ATT&CK IDs, MAC addresses).
package ioc

import (
	"bufio"
	_ "embed"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// Type is the kind of an indicator.
type Type string

const (
	MD5              Type = "md5"
	SHA1             Type = "sha1"
	SHA256           Type = "sha256"
	SHA512           Type = "sha512"
	IPv4             Type = "ipv4"
	IPv6             Type = "ipv6"
	Domain           Type = "domain"
	URL              Type = "url"
	Email            Type = "email"
	CVE              Type = "cve"
	AttackTechnique  Type = "attack-technique"
	AttackTactic     Type = "attack-tactic"
	AttackGroup      Type = "attack-group"
	AttackSoftware   Type = "attack-software"
	AttackMitigation Type = "attack-mitigation"
	AttackCampaign   Type = "attack-campaign"
	MAC              Type = "mac"
	// Keyword is free text that matches no other type (e.g. a threat actor name).
	Keyword Type = "keyword"
)

// Types lists every indicator type, in display order.
var Types = []Type{
	MD5, SHA1, SHA256, SHA512, IPv4, IPv6, Domain, URL, Email, CVE,
	AttackTechnique, AttackTactic, AttackGroup, AttackSoftware, AttackMitigation, AttackCampaign,
	MAC, Keyword,
}

// IsHash reports whether t is a file hash type.
func (t Type) IsHash() bool {
	return t == MD5 || t == SHA1 || t == SHA256 || t == SHA512
}

// IsIP reports whether t is an IP address type.
func (t Type) IsIP() bool { return t == IPv4 || t == IPv6 }

// IsAttack reports whether t is a MITRE ATT&CK identifier type.
func (t Type) IsAttack() bool {
	switch t {
	case AttackTechnique, AttackTactic, AttackGroup, AttackSoftware, AttackMitigation, AttackCampaign:
		return true
	}
	return false
}

// Indicator is a validated, normalized indicator.
type Indicator struct {
	Type  Type   `json:"type"`
	Value string `json:"value"`
}

func (i Indicator) String() string { return string(i.Type) + ":" + i.Value }

// Limits on accepted input, to keep lookups and storage bounded.
const (
	MaxLen        = 2048
	minKeywordLen = 2
	maxKeywordLen = 200
)

var (
	ErrEmpty   = errors.New("empty indicator")
	ErrTooLong = errors.New("indicator too long")
	ErrInvalid = errors.New("invalid indicator")
)

var (
	reHex    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reCVE    = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,7}$`)
	reAttack = regexp.MustCompile(`(?i)^(TA|T|G|S|M|C)(\d{4})(\.\d{3})?$`)
	reLabel  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reEmail  = regexp.MustCompile(`^[A-Za-z0-9._%+\-]{1,64}@([^@\s]+)$`)
)

//go:embed tlds.txt
var tldList string

var tlds = func() map[string]struct{} {
	m := make(map[string]struct{}, 1500)
	sc := bufio.NewScanner(strings.NewReader(tldList))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[strings.ToLower(line)] = struct{}{}
	}
	return m
}()

// Parse refangs, detects and normalizes a single indicator.
// Text that matches no known type is returned as a Keyword.
func Parse(s string) (Indicator, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Indicator{}, ErrEmpty
	}
	if len(s) > MaxLen {
		return Indicator{}, ErrTooLong
	}
	if i, ok := detect(Refang(s)); ok {
		return i, nil
	}
	if strings.ContainsFunc(s, isControl) || len(s) < minKeywordLen || len(s) > maxKeywordLen {
		return Indicator{}, ErrInvalid
	}
	return Indicator{Type: Keyword, Value: s}, nil
}

// detect returns the indicator if s matches a strict (non keyword) type.
func detect(s string) (Indicator, bool) {
	if strings.ContainsFunc(s, isControl) {
		return Indicator{}, false
	}
	if t, ok := hashType(s); ok {
		return Indicator{Type: t, Value: strings.ToLower(s)}, true
	}
	if reCVE.MatchString(s) {
		return Indicator{Type: CVE, Value: strings.ToUpper(s)}, true
	}
	if m := reAttack.FindStringSubmatch(s); m != nil {
		if t, ok := attackType(strings.ToUpper(m[1]), m[3] != ""); ok {
			return Indicator{Type: t, Value: strings.ToUpper(s)}, true
		}
	}
	if v, ok := parseMAC(s); ok {
		return Indicator{Type: MAC, Value: v}, true
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		a = a.Unmap()
		if a.Is4() {
			return Indicator{Type: IPv4, Value: a.String()}, true
		}
		return Indicator{Type: IPv6, Value: a.String()}, true
	}
	if v, ok := parseURL(s); ok {
		return Indicator{Type: URL, Value: v}, true
	}
	if m := reEmail.FindStringSubmatch(s); m != nil {
		if d, ok := normalizeDomain(m[1]); ok {
			local := s[:len(s)-len(m[1])-1]
			return Indicator{Type: Email, Value: local + "@" + d}, true
		}
	}
	if d, ok := normalizeDomain(s); ok {
		return Indicator{Type: Domain, Value: d}, true
	}
	return Indicator{}, false
}

func hashType(s string) (Type, bool) {
	if !reHex.MatchString(s) {
		return "", false
	}
	switch len(s) {
	case 32:
		return MD5, true
	case 40:
		return SHA1, true
	case 64:
		return SHA256, true
	case 128:
		return SHA512, true
	}
	return "", false
}

func attackType(prefix string, sub bool) (Type, bool) {
	if sub && prefix != "T" {
		return "", false
	}
	switch prefix {
	case "T":
		return AttackTechnique, true
	case "TA":
		return AttackTactic, true
	case "G":
		return AttackGroup, true
	case "S":
		return AttackSoftware, true
	case "M":
		return AttackMitigation, true
	case "C":
		return AttackCampaign, true
	}
	return "", false
}

// parseMAC accepts 48-bit MAC addresses in colon, dash, Cisco dot or bare
// hex notation and returns them as upper-case colon separated octets.
func parseMAC(s string) (string, bool) {
	if len(s) == 12 && reHex.MatchString(s) {
		s = s[0:2] + ":" + s[2:4] + ":" + s[4:6] + ":" + s[6:8] + ":" + s[8:10] + ":" + s[10:12]
	}
	if len(s) != 17 && len(s) != 14 {
		return "", false
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return "", false
	}
	return strings.ToUpper(hw.String()), true
}

func parseURL(s string) (string, bool) {
	i := strings.Index(s, "://")
	if i <= 0 {
		return "", false
	}
	switch strings.ToLower(s[:i]) {
	case "http", "https", "ftp", "ftps", "sftp", "ws", "wss":
	default:
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", false
	}
	host := u.Hostname()
	if _, err := netip.ParseAddr(host); err != nil {
		d, ok := normalizeDomain(host)
		if !ok {
			return "", false
		}
		if p := u.Port(); p != "" {
			u.Host = d + ":" + p
		} else {
			u.Host = d
		}
	}
	u.Scheme = strings.ToLower(u.Scheme)
	return u.String(), true
}

// normalizeDomain validates a hostname with a known public TLD and returns it
// lower-cased without a trailing dot.
func normalizeDomain(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if len(s) > 253 || !strings.Contains(s, ".") {
		return "", false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !reLabel.MatchString(l) {
			return "", false
		}
	}
	if _, ok := tlds[labels[len(labels)-1]]; !ok {
		return "", false
	}
	return s, true
}

func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0)
}
