package ioc

import (
	"net/netip"
	"testing"
)

func TestIsInternalAddr(t *testing.T) {
	internal := []string{
		"10.0.0.5", "172.16.3.4", "172.31.255.255", "192.168.1.1", "127.0.0.1", "0.0.0.0",
		"169.254.10.1", "100.64.0.1", "100.127.255.254", "192.0.2.1", "198.51.100.7", "203.0.113.9",
		"198.18.0.1", "192.0.0.8", "224.0.0.251", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "2001:db8::1", "3fff::1",
		"::ffff:10.0.0.1", "64:ff9b:1::1", "100::1",
	}
	for _, s := range internal {
		if !IsInternalAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s: want internal", s)
		}
	}
	public := []string{
		"8.8.8.8", "1.1.1.1", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1",
		"192.0.3.1", "198.20.0.1", "2606:4700:4700::1111", "2001:4860:4860::8888", "64:ff9b::808:808",
	}
	for _, s := range public {
		if IsInternalAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s: want public", s)
		}
	}
	if IsInternalAddr(netip.Addr{}) {
		t.Error("zero Addr reported as internal")
	}
}

func TestIndicatorIsInternal(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"10.0.0.5", true},
		{"10[.]0[.]0[.]5", true},
		{"8.8.8.8", false},
		{"fd00::1", true},
		{"http://192.168.1.10:8080/admin", true},
		{"hxxp://[::1]/x", true},
		{"https://example.com/x", false},
		{"https://203.0.113.5/a", true},
		{"nas.home.arpa", true},
		{"example.com", false},
		{"user@example.com", false},
		{"CVE-2021-44228", false},
		{"Lazarus", false},
	}
	for _, tt := range tests {
		ind, err := Parse(tt.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.in, err)
		}
		if got := ind.IsInternal(); got != tt.want {
			t.Errorf("%q (%s): IsInternal = %v, want %v", tt.in, ind, got, tt.want)
		}
	}
}
