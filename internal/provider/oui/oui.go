// Package oui resolves MAC addresses to their vendor using the offline IEEE registry.
package oui

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

const name = "ieee-oui"

// virtualHints flags prefixes commonly seen on virtual machines and sandboxes.
var virtualHints = map[string]string{
	"000569": "VMware virtual NIC",
	"000C29": "VMware virtual NIC",
	"001C14": "VMware virtual NIC",
	"005056": "VMware virtual NIC",
	"080027": "VirtualBox virtual NIC",
	"0A0027": "VirtualBox host-only adapter",
	"00155D": "Microsoft Hyper-V virtual NIC",
	"00163E": "Xen virtual NIC",
	"525400": "QEMU/KVM virtual NIC",
	"001C42": "Parallels virtual NIC",
	"0242AC": "Docker container (default bridge)",
}

// Provider queries the OUI table of the store.
type Provider struct {
	store *store.Store
}

// New returns an OUI provider.
func New(s *store.Store) *Provider { return &Provider{store: s} }

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool { return t == ioc.MAC }

// Details is the structured payload of a MAC lookup.
type Details struct {
	Vendor              *store.OUI `json:"vendor,omitempty"`
	Broadcast           bool       `json:"broadcast"`
	Multicast           bool       `json:"multicast"`
	LocallyAdministered bool       `json:"locally_administered"`
	Hint                string     `json:"hint,omitempty"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	hex := strings.ReplaceAll(i.Value, ":", "")
	first, err := strconv.ParseUint(hex[:2], 16, 8)
	if err != nil {
		return nil, err
	}
	d := Details{
		Broadcast:           hex == "FFFFFFFFFFFF",
		Multicast:           first&0x01 != 0,
		LocallyAdministered: first&0x02 != 0,
		Hint:                virtualHints[hex[:6]],
	}
	r := &provider.Result{Provider: name, Verdict: provider.VerdictInfo, Details: &d}

	switch {
	case d.Broadcast:
		r.Found, r.Summary = true, "broadcast address"
	case d.LocallyAdministered:
		r.Found = true
		r.Summary = "locally administered address: randomized (privacy MAC) or assigned by software, no vendor"
	default:
		v, err := p.store.OUILookup(ctx, hex)
		switch {
		case errors.Is(err, store.ErrNotFound):
			synced, err := p.store.HasDataset(ctx, "oui")
			if err != nil {
				return nil, err
			}
			if !synced {
				return nil, errors.New("OUI dataset not synced: run 'astro sync oui'")
			}
			r.Summary = "vendor not found in the IEEE registry"
		case err != nil:
			return nil, err
		default:
			d.Vendor = v
			r.Found = true
			r.Summary = v.Org
			r.Add("Vendor", v.Org)
			r.Add("Address", v.Address)
			r.Addf("Block", "%s (%s)", v.Prefix, v.Registry)
		}
	}
	r.Add("Hint", d.Hint)
	r.Add("Type", addrType(d))
	return r, nil
}

func addrType(d Details) string {
	scope := "unicast"
	if d.Multicast {
		scope = "multicast"
	}
	admin := "globally unique (OUI)"
	if d.LocallyAdministered {
		admin = "locally administered"
	}
	return scope + ", " + admin
}
