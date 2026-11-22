package config

import (
	"net/netip"
	"regexp"
	"strings"
)

// IPsec holds the site-to-site tunnels (strongSwan). L2TP/IPsec is not
// here: it belongs to the L2TP client and server.
type IPsec struct {
	Tunnels []IPsecTunnel `yaml:"tunnels,omitempty" json:"tunnels,omitempty"`
}

// IPsecTunnel joins local subnets to the subnets of another site, like a
// RouterOS peer + identity + policies. It is policy based: there is no
// interface; packets between the subnets are encrypted on their way out.
type IPsecTunnel struct {
	Name     string `yaml:"name" json:"name"`
	Comment  string `yaml:"comment,omitempty" json:"comment,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	// Remote is the other router's address or DNS name. Empty means the
	// other side has no fixed address: this router only answers.
	Remote string `yaml:"remote,omitempty" json:"remote,omitempty"`
	// Local is the address to use on this router (empty: chosen by route).
	Local string `yaml:"local,omitempty" json:"local,omitempty"`
	// IKEVersion is 2 (default) or 1.
	IKEVersion int `yaml:"ike_version,omitempty" json:"ike_version,omitempty"`
	// Aggressive (IKEv1) uses aggressive mode instead of main mode.
	Aggressive bool   `yaml:"aggressive,omitempty" json:"aggressive,omitempty"`
	PSK        string `yaml:"psk" json:"psk"`
	// LocalID and RemoteID are the IKE identities (address, FQDN or
	// user@fqdn). Empty means the address. RemoteID is required when
	// Remote is not an IP address.
	LocalID  string `yaml:"local_id,omitempty" json:"local_id,omitempty"`
	RemoteID string `yaml:"remote_id,omitempty" json:"remote_id,omitempty"`
	// LocalSubnets and RemoteSubnets are the networks on each side. Every
	// pair gets its own SA, as RouterOS and most firewalls expect.
	LocalSubnets  []string `yaml:"local_subnets" json:"local_subnets"`
	RemoteSubnets []string `yaml:"remote_subnets" json:"remote_subnets"`
	// PFS is the DH group for rekeying the tunnel keys ("" accepts both,
	// "none", or a group such as modp1024, modp2048, ecp256).
	PFS string `yaml:"pfs,omitempty" json:"pfs,omitempty"`
	// IKEProposals and ESPProposals replace the built-in wide lists, in
	// strongSwan syntax (aes256-sha256-modp2048,...).
	IKEProposals string `yaml:"ike_proposals,omitempty" json:"ike_proposals,omitempty"`
	ESPProposals string `yaml:"esp_proposals,omitempty" json:"esp_proposals,omitempty"`
	// Passive: do not start the tunnel, only answer. Always so without
	// a Remote.
	Passive bool `yaml:"passive,omitempty" json:"passive,omitempty"`
	// AllowRouter lets the remote subnets reach the router itself (panel,
	// DNS, ping). Traffic to the local subnets is always let through.
	AllowRouter bool `yaml:"allow_router,omitempty" json:"allow_router,omitempty"`
}

// IPsecMaxSubnetPairs bounds local × remote subnets of one tunnel.
const IPsecMaxSubnetPairs = 64

// Version returns the IKE version, 2 by default.
func (t *IPsecTunnel) Version() int {
	if t.IKEVersion == 1 {
		return 1
	}
	return 2
}

// Initiates reports whether this router starts the tunnel.
func (t *IPsecTunnel) Initiates() bool { return t.Remote != "" && !t.Passive }

// RemoteIsAddr reports whether Remote is an IP address (not a name).
func (t *IPsecTunnel) RemoteIsAddr() bool {
	_, err := netip.ParseAddr(t.Remote)
	return err == nil
}

// PeerID is the identity the other side must show: RemoteID, or its address.
func (t *IPsecTunnel) PeerID() string {
	if t.RemoteID != "" {
		return t.RemoteID
	}
	if t.RemoteIsAddr() {
		return t.Remote
	}
	return ""
}

// SubnetPairs lists every local/remote subnet pair of one address family.
func (t *IPsecTunnel) SubnetPairs() [][2]string {
	var out [][2]string
	for _, l := range t.LocalSubnets {
		for _, r := range t.RemoteSubnets {
			lp, e1 := netip.ParsePrefix(l)
			rp, e2 := netip.ParsePrefix(r)
			if e1 == nil && e2 == nil && lp.Addr().Is4() == rp.Addr().Is4() {
				out = append(out, [2]string{l, r})
			}
		}
	}
	return out
}

func (c *Config) hasL2TPSecret() bool {
	if c.PPPServer.L2TPOn() && c.PPPServer.L2TP.IPsecSecret != "" {
		return true
	}
	for _, ifc := range c.Interfaces {
		if ifc.Type == IfL2TP && ifc.PPP != nil && ifc.PPP.IPsecSecret != "" && !ifc.Disabled {
			return true
		}
	}
	return false
}

// IPsecTunnels returns the enabled site-to-site tunnels.
func (c *Config) IPsecTunnels() []*IPsecTunnel {
	if c.IPsec == nil {
		return nil
	}
	var out []*IPsecTunnel
	for i := range c.IPsec.Tunnels {
		if !c.IPsec.Tunnels[i].Disabled {
			out = append(out, &c.IPsec.Tunnels[i])
		}
	}
	return out
}

var (
	ipsecNameRe     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,23}$`)
	ipsecIDRe       = regexp.MustCompile(`^[A-Za-z0-9@._:-]{1,128}$`)
	ipsecProposalRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*(,[a-z0-9]+(-[a-z0-9]+)*)*$`)
	ipsecGroupRe    = regexp.MustCompile(`^(modp(768|1024|1536|2048|3072|4096|6144|8192)|ecp(256|384|521)|curve25519|x25519)$`)
)

func (v *validator) ipsec() {
	if v.c.IPsec == nil {
		return
	}
	names := map[string]bool{}
	peers := map[string]string{}
	anyRemote := map[int]string{}
	for i := range v.c.IPsec.Tunnels {
		t := &v.c.IPsec.Tunnels[i]
		p := "ipsec.tunnels[" + t.Name + "]"
		if !ipsecNameRe.MatchString(t.Name) {
			v.add("%s: name must be lower-case letters, digits and - (max 24, starting with a letter)", p)
		} else if names[t.Name] {
			v.add("%s: duplicate name", p)
		}
		names[t.Name] = true
		if t.IKEVersion != 0 && t.IKEVersion != 1 && t.IKEVersion != 2 {
			v.add("%s: ike_version must be 1 or 2", p)
		}
		if t.Aggressive && t.Version() != 1 {
			v.add("%s: aggressive mode is only for IKEv1", p)
		}
		if !pppSafe(t.PSK) {
			v.add("%s: psk is required and may not contain quotes, backslashes or control characters", p)
		} else if len(t.PSK) < 8 {
			v.add("%s: psk must be at least 8 characters", p)
		}
		if t.Remote != "" && !t.RemoteIsAddr() && !domainRe.MatchString(t.Remote) {
			v.add("%s: remote must be an IP address or a DNS name", p)
		}
		if t.Remote != "" && !t.RemoteIsAddr() && t.RemoteID == "" {
			v.add("%s: remote_id is required when remote is a DNS name", p)
		}
		if t.Local != "" {
			if _, err := netip.ParseAddr(t.Local); err != nil {
				v.add("%s: local must be an IP address", p)
			}
		}
		for what, id := range map[string]string{"local_id": t.LocalID, "remote_id": t.RemoteID} {
			if id != "" && !ipsecIDRe.MatchString(id) {
				v.add("%s: %s may hold letters, digits and @ . _ : - only", p, what)
			}
		}
		if t.PFS != "" && t.PFS != "none" && !ipsecGroupRe.MatchString(t.PFS) {
			v.add("%s: pfs must be none or a DH group such as modp1024, modp2048 or ecp256", p)
		}
		for what, pr := range map[string]string{"ike_proposals": t.IKEProposals, "esp_proposals": t.ESPProposals} {
			if pr != "" && (len(pr) > 512 || !ipsecProposalRe.MatchString(pr)) {
				v.add("%s: %s must look like aes256-sha256-modp2048,aes128-sha1-modp1024", p, what)
			}
		}
		v.ipsecSubnets(p, "local_subnets", t.LocalSubnets)
		v.ipsecSubnets(p, "remote_subnets", t.RemoteSubnets)
		if len(t.LocalSubnets)*len(t.RemoteSubnets) > IPsecMaxSubnetPairs {
			v.add("%s: too many subnet pairs (max %d)", p, IPsecMaxSubnetPairs)
		}
		for _, l := range t.LocalSubnets {
			for _, r := range t.RemoteSubnets {
				lp, e1 := netip.ParsePrefix(l)
				rp, e2 := netip.ParsePrefix(r)
				if e1 == nil && e2 == nil && lp.Addr().Is4() == rp.Addr().Is4() && lp.Overlaps(rp) {
					v.add("%s: local subnet %s and remote subnet %s overlap", p, l, r)
				}
			}
		}
		pairs := 0
		for _, pr := range t.SubnetPairs() {
			_ = pr
			pairs++
		}
		if pairs == 0 && len(t.LocalSubnets) > 0 && len(t.RemoteSubnets) > 0 {
			v.add("%s: local and remote subnets must share an address family (IPv4 with IPv4, IPv6 with IPv6)", p)
		}
		if t.Disabled {
			continue
		}
		if t.PeerID() == "" && v.c.hasL2TPSecret() {
			v.add("%s: with an L2TP/IPsec secret in use, a tunnel without a remote address needs a remote_id", p)
		}
		// Two tunnels to the same peer, or two without a fixed peer and
		// without an ID to tell them apart, cannot be matched to a key.
		if t.Remote != "" {
			k := strings.ToLower(t.Remote)
			if other, dup := peers[k]; dup {
				v.add("%s: tunnel %s already goes to %s; put all subnets in one tunnel", p, other, t.Remote)
			}
			peers[k] = t.Name
		} else if t.RemoteID == "" {
			if other, dup := anyRemote[t.Version()]; dup {
				v.add("%s: tunnel %s also has no remote; give each a remote_id", p, other)
			}
			anyRemote[t.Version()] = t.Name
		}
	}
}

func (v *validator) ipsecSubnets(p, what string, list []string) {
	if len(list) == 0 {
		v.add("%s: %s needs at least one subnet", p, what)
	}
	seen := map[string]bool{}
	for _, s := range list {
		pfx, err := netip.ParsePrefix(s)
		if err != nil || pfx != pfx.Masked() {
			v.add("%s: %s: %q is not a network address such as 192.168.10.0/24", p, what, s)
			continue
		}
		if pfx.Bits() == 0 {
			v.add("%s: %s: %s would send everything into the tunnel; use real subnets", p, what, s)
		}
		if seen[s] {
			v.add("%s: %s: %s is listed twice", p, what, s)
		}
		seen[s] = true
	}
}
