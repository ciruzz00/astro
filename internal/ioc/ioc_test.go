package ioc

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in    string
		typ   Type
		value string
	}{
		{"D41D8CD98F00B204E9800998ECF8427E", MD5, "d41d8cd98f00b204e9800998ecf8427e"},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{strings.Repeat("ab", 64), SHA512, strings.Repeat("ab", 64)},
		{"  8.8.8.8 ", IPv4, "8.8.8.8"},
		{"8[.]8[.]8[.]8", IPv4, "8.8.8.8"},
		{"::ffff:1.2.3.4", IPv4, "1.2.3.4"},
		{"2001:DB8::1", IPv6, "2001:db8::1"},
		{"Example.COM.", Domain, "example.com"},
		{"evil[.]example[.]org", Domain, "evil.example.org"},
		{"xn--80ak6aa92e.com", Domain, "xn--80ak6aa92e.com"},
		{"hxxps://evil[.]example[.]com/path?q=1", URL, "https://evil.example.com/path?q=1"},
		{"HTTP://Example.com:8080/a", URL, "http://example.com:8080/a"},
		{"hxxp[://]1.2.3.4/x", URL, "http://1.2.3.4/x"},
		{"user@Example.com", Email, "user@example.com"},
		{"admin[@]example[.]com", Email, "admin@example.com"},
		{"cve-2021-44228", CVE, "CVE-2021-44228"},
		{"t1059.001", AttackTechnique, "T1059.001"},
		{"T1059", AttackTechnique, "T1059"},
		{"TA0002", AttackTactic, "TA0002"},
		{"G0032", AttackGroup, "G0032"},
		{"S0154", AttackSoftware, "S0154"},
		{"M1036", AttackMitigation, "M1036"},
		{"C0022", AttackCampaign, "C0022"},
		{"00:50:56:aa:bb:cc", MAC, "00:50:56:AA:BB:CC"},
		{"00-50-56-AA-BB-CC", MAC, "00:50:56:AA:BB:CC"},
		{"0050.56aa.bbcc", MAC, "00:50:56:AA:BB:CC"},
		{"005056aabbcc", MAC, "00:50:56:AA:BB:CC"},
		{"Lazarus Group", Keyword, "Lazarus Group"},
		{"invoice.exe", Keyword, "invoice.exe"},
		{"G0032.001", Keyword, "G0032.001"},
	}
	for _, tt := range tests {
		got, err := Parse(tt.in)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", tt.in, err)
			continue
		}
		if got.Type != tt.typ || got.Value != tt.value {
			t.Errorf("Parse(%q) = %v, want %s:%s", tt.in, got, tt.typ, tt.value)
		}
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		in  string
		err error
	}{
		{"", ErrEmpty},
		{"   ", ErrEmpty},
		{"x", ErrInvalid},
		{"a\x1b[31mb", ErrInvalid},
		{strings.Repeat("a", MaxLen+1), ErrTooLong},
		{strings.Repeat("a", 300), ErrInvalid},
	}
	for _, tt := range tests {
		if _, err := Parse(tt.in); !errors.Is(err, tt.err) {
			t.Errorf("Parse(%q) error = %v, want %v", tt.in, err, tt.err)
		}
	}
}

func TestRefang(t *testing.T) {
	tests := map[string]string{
		"hxxp://a[.]b":    "http://a.b",
		"HXXPS://a(.)b":   "https://a.b",
		"hxxps[://]a[.]b": "https://a.b",
		"h**p://a[dot]b":  "http://a.b",
		"fxp://a[.]b":     "ftp://a.b",
		"x[@]y[.]z":       "x@y.z",
		"https://already": "https://already",
	}
	for in, want := range tests {
		if got := Refang(in); got != want {
			t.Errorf("Refang(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDefang(t *testing.T) {
	tests := []struct {
		in   Indicator
		want string
	}{
		{Indicator{URL, "https://evil.com/a"}, "hxxps[://]evil[.]com/a"},
		{Indicator{Domain, "evil.com"}, "evil[.]com"},
		{Indicator{IPv4, "1.2.3.4"}, "1[.]2[.]3[.]4"},
		{Indicator{Email, "a@b.com"}, "a[@]b[.]com"},
		{Indicator{MD5, "d41d8cd98f00b204e9800998ecf8427e"}, "d41d8cd98f00b204e9800998ecf8427e"},
	}
	for _, tt := range tests {
		if got := Defang(tt.in); got != tt.want {
			t.Errorf("Defang(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExtract(t *testing.T) {
	text := `2024-01-01 alert src=10.0.0.5 dst:8[.]8[.]8[.]8 user=bob
The dropper (sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) contacted
hxxps://evil[.]example[.]com/gate.php, see also CVE-2021-44228 and T1059.001.
Repeated: 8.8.8.8, report.pdf, mac 00:50:56:aa:bb:cc [contact: soc@example.org]`

	got := Extract(text)
	want := []Indicator{
		{IPv4, "10.0.0.5"},
		{IPv4, "8.8.8.8"},
		{SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{URL, "https://evil.example.com/gate.php"},
		{CVE, "CVE-2021-44228"},
		{AttackTechnique, "T1059.001"},
		{MAC, "00:50:56:AA:BB:CC"},
		{Email, "soc@example.org"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Extract() =\n%v\nwant\n%v", got, want)
	}
}

func TestExtractCap(t *testing.T) {
	var b strings.Builder
	for i := range MaxExtract + 10 {
		b.WriteString("10.")
		b.WriteString(strconv.Itoa(i / 65536 % 256))
		b.WriteString(".")
		b.WriteString(strconv.Itoa(i / 256 % 256))
		b.WriteString(".")
		b.WriteString(strconv.Itoa(i % 256))
		b.WriteString(" ")
	}
	if n := len(Extract(b.String())); n != MaxExtract {
		t.Errorf("Extract returned %d indicators, want cap %d", n, MaxExtract)
	}
}
