package config

import (
	"fmt"
	"net"
	"net/netip"
)

// Point-to-point IP tunnels, like RouterOS /interface gre, ipip, eoip,
// 6to4, eoipv6 and gre6. None of them encrypts.
const (
	IfGRE    = "gre"    // IPv4 GRE, layer 3
	IfIPIP   = "ipip"   // IPv4 in IPv4
	IfEoIP   = "eoip"   // MikroTik EoIP: Ethernet in GRE over IPv4
	If6to4   = "6to4"   // IPv6 in IPv4 (SIT)
	IfEoIPv6 = "eoipv6" // MikroTik EoIPv6: Ethernet in IPv6 (protocol 97)
	IfGRE6   = "gre6"   // GRE over IPv6, layer 3
)

// IsIPTunnel reports the tunnel types in this file.
func IsIPTunnel(t string) bool {
	switch t {
	case IfGRE, IfIPIP, IfEoIP, If6to4, IfEoIPv6, IfGRE6:
		return true
	}
	return false
}

// IsEoIP reports the MikroTik Ethernet tunnels (run by mahan-eoip).
func IsEoIP(t string) bool { return t == IfEoIP || t == IfEoIPv6 }

// TunnelIPv6 reports whether a tunnel type runs over IPv6.
func TunnelIPv6(t string) bool { return t == IfEoIPv6 || t == IfGRE6 }

// Tunnel is the transport of a GRE / IPIP / EoIP / 6to4 / EoIPv6 / GRE6
// interface. The addresses on the interface itself are set as usual.
type Tunnel struct {
	// Local is this router's address the tunnel runs from (empty: any;
	// required for GRE6).
	Local string `yaml:"local,omitempty" json:"local,omitempty"`
	// Remote is the other end. Only 6to4 may leave it empty, for a
	// 2002::/16 relay tunnel.
	Remote string `yaml:"remote,omitempty" json:"remote,omitempty"`
	// TunnelID (EoIP 0-65535, EoIPv6 0-4095) must match the other end.
	TunnelID int `yaml:"tunnel_id,omitempty" json:"tunnel_id,omitempty"`
	// Key (GRE, GRE6) is the optional GRE key; 0 means none.
	Key uint32 `yaml:"key,omitempty" json:"key,omitempty"`
	// TTL (hop limit on IPv6); 0 means inherit from the inner packet.
	TTL int `yaml:"ttl,omitempty" json:"ttl,omitempty"`
	// Keepalive (EoIP, EoIPv6) is the keepalive interval in seconds, 0
	// turns it off. Default 10, like RouterOS: the link goes down after
	// 10 intervals without a packet from the other end.
	Keepalive *int `yaml:"keepalive,omitempty" json:"keepalive,omitempty"`
	// MAC (EoIP, EoIPv6) is the tunnel's Ethernet address; empty means one
	// derived from the interface name, so it stays the same.
	MAC string `yaml:"mac,omitempty" json:"mac,omitempty"`
}

// DefaultKeepalive is RouterOS's EoIP keepalive interval.
const DefaultKeepalive = 10

// KeepaliveSec returns the keepalive interval, 0 when off.
func (t *Tunnel) KeepaliveSec() int {
	if t.Keepalive == nil {
		return DefaultKeepalive
	}
	return *t.Keepalive
}

func (v *validator) ipTunnel(p string, ifc *Interface) {
	t := ifc.Tunnel
	if t == nil {
		v.add("%s: tunnel section missing", p)
		return
	}
	v6 := TunnelIPv6(ifc.Type)
	fam := "IPv4"
	if v6 {
		fam = "IPv6"
	}
	check := func(field, s string) {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			v.add("%s: tunnel.%s must be an %s address", p, field, fam)
			return
		}
		if a.Is4() == v6 || a.Is4In6() {
			v.add("%s: tunnel.%s must be an %s address for %s", p, field, fam, ifc.Type)
		}
		if a.IsUnspecified() || a.IsMulticast() {
			v.add("%s: tunnel.%s cannot be %s", p, field, s)
		}
	}
	if t.Remote != "" {
		check("remote", t.Remote)
	} else if ifc.Type != If6to4 {
		v.add("%s: tunnel.remote is required", p)
	}
	if t.Local != "" {
		check("local", t.Local)
	} else if ifc.Type == IfGRE6 {
		// The kernel does not send ip6gre packets without a source.
		v.add("%s: tunnel.local is required for gre6", p)
	}
	switch ifc.Type {
	case IfEoIP:
		if t.TunnelID < 0 || t.TunnelID > 65535 {
			v.add("%s: tunnel.tunnel_id must be 0-65535", p)
		}
	case IfEoIPv6:
		if t.TunnelID < 0 || t.TunnelID > 4095 {
			v.add("%s: tunnel.tunnel_id must be 0-4095 for eoipv6", p)
		}
	default:
		if t.TunnelID != 0 {
			v.add("%s: tunnel.tunnel_id is only for eoip and eoipv6", p)
		}
	}
	if t.Key != 0 && ifc.Type != IfGRE && ifc.Type != IfGRE6 {
		v.add("%s: tunnel.key is only for gre and gre6", p)
	}
	if t.TTL < 0 || t.TTL > 255 {
		v.add("%s: tunnel.ttl must be 0-255", p)
	}
	if IsEoIP(ifc.Type) {
		if k := t.KeepaliveSec(); k < 0 || k > 3600 {
			v.add("%s: tunnel.keepalive must be 0-3600 seconds", p)
		}
		if t.MAC != "" {
			if hw, err := net.ParseMAC(t.MAC); err != nil || len(hw) != 6 || hw[0]&1 == 1 {
				v.add("%s: tunnel.mac %q is not a unicast MAC address", p, t.MAC)
			}
		}
	} else {
		if t.Keepalive != nil {
			v.add("%s: tunnel.keepalive is only for eoip and eoipv6", p)
		}
		if t.MAC != "" {
			v.add("%s: tunnel.mac is only for eoip and eoipv6", p)
		}
	}
	if ifc.Addressing == AddrDHCP && !IsEoIP(ifc.Type) {
		v.add("%s: dhcp on %s is not possible", p, ifc.Type)
	}
}

// tunnelChecks runs after the interfaces: two tunnels with the same
// endpoints (and key / tunnel ID) would receive each other's packets.
func (v *validator) tunnelChecks() {
	seen := map[string]string{}
	for _, ifc := range v.c.Interfaces {
		if !IsIPTunnel(ifc.Type) || ifc.Tunnel == nil || ifc.Disabled {
			continue
		}
		t := ifc.Tunnel
		// GRE and EoIP share IP protocol 47 but differ in the header, so
		// they do not clash; the kernel tells GRE tunnels apart by key.
		var key string
		switch ifc.Type {
		case IfGRE, IfGRE6:
			key = fmt.Sprintf("%s|%s|%s|key%d", ifc.Type, t.Local, t.Remote, t.Key)
		case IfEoIP, IfEoIPv6:
			key = fmt.Sprintf("%s|%s|id%d", ifc.Type, t.Remote, t.TunnelID)
		default:
			key = fmt.Sprintf("%s|%s|%s", ifc.Type, t.Local, t.Remote)
		}
		if prev, dup := seen[key]; dup {
			v.add("interfaces[%s]: same %s endpoints as %s; change the remote, key or tunnel ID", ifc.Name, ifc.Type, prev)
		}
		seen[key] = ifc.Name
	}
}
