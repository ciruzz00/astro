package ioc

import (
	"net/netip"
	"net/url"
	"strings"
)

// internalPrefixes are special-purpose ranges (IANA registries, RFC 6890) that
// netip does not classify on its own and that never identify a public host.
var internalPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // "this network"
		"100.64.0.0/10",   // carrier-grade NAT (RFC 6598)
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation (TEST-NET-1)
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation (TEST-NET-2)
		"203.0.113.0/24",  // documentation (TEST-NET-3)
		"240.0.0.0/4",     // reserved, includes the limited broadcast address
		"64:ff9b:1::/48",  // local-use NAT64 (RFC 8215)
		"100::/64",        // discard-only (RFC 6666)
		"2001:db8::/32",   // documentation
		"3fff::/20",       // documentation (RFC 9637)
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// IsInternalAddr reports whether a is a private, loopback, link-local,
// multicast, shared (CGNAT), documentation or otherwise reserved address:
// one that only makes sense inside a network and must not be sent to online
// sources, where it would leak the layout of the network under analysis.
func IsInternalAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range internalPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsInternal reports whether the indicator names an internal host: an
// internal IP address, a URL or email whose host is one, or a name under
// home.arpa (RFC 8375). Such indicators are never sent to online sources.
func (i Indicator) IsInternal() bool {
	switch i.Type {
	case IPv4, IPv6:
		a, err := netip.ParseAddr(i.Value)
		return err == nil && IsInternalAddr(a)
	case URL:
		u, err := url.Parse(i.Value)
		return err == nil && internalHost(u.Hostname())
	case Email:
		_, d, _ := strings.Cut(i.Value, "@")
		return internalHost(d)
	case Domain:
		return internalHost(i.Value)
	}
	return false
}

func internalHost(h string) bool {
	if a, err := netip.ParseAddr(h); err == nil {
		return IsInternalAddr(a)
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	return h == "home.arpa" || strings.HasSuffix(h, ".home.arpa")
}
