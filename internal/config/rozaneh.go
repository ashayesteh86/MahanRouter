package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"net/netip"
	"regexp"
	"strings"
)

// RozanehLinkPrefix starts a Rozaneh client link. mahanvpn:// is the old name.
const RozanehLinkPrefix = "rozaneh://config/"

// DecodeRozanehLink returns the client JSON inside a link as a map, so that
// fields added by newer servers pass through untouched.
func DecodeRozanehLink(link string) (map[string]any, error) {
	link = strings.TrimSpace(link)
	i := strings.Index(link, "://config/")
	if i < 0 || (link[:i] != "rozaneh" && link[:i] != "mahanvpn") {
		return nil, errors.New("not a rozaneh://config/ link")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(link[i+len("://config/"):], "="))
	if err != nil {
		return nil, fmt.Errorf("link is damaged: %w", err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("link is damaged: %w", err)
	}
	for _, k := range []string{"server", "sni", "path", "private_key", "server_public_key"} {
		if s, _ := m[k].(string); s == "" {
			return nil, fmt.Errorf("link has no %s", k)
		}
	}
	for _, k := range []string{"private_key", "server_public_key"} {
		if !wgKey(m[k].(string)) {
			return nil, fmt.Errorf("link %s is not a 32-byte key", k)
		}
	}
	return m, nil
}

var domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

func (v *validator) rozaneh(p string, ifc *Interface) {
	switch ifc.Type {
	case IfRozaneh:
		if ifc.Rozaneh == nil {
			v.add("%s: rozaneh section missing", p)
			return
		}
		if _, err := DecodeRozanehLink(ifc.Rozaneh.Link); err != nil {
			v.add("%s: rozaneh.link: %v", p, err)
		}
		switch ifc.Rozaneh.Method {
		case "", "auto", "tunnel", "dns":
		default:
			v.add("%s: rozaneh.method must be auto, tunnel or dns", p)
		}
		if len(ifc.Addresses) > 0 || ifc.Addressing == AddrDHCP || ifc.Addressing == AddrStatic {
			v.add("%s: the rozaneh server assigns the address, leave addressing empty", p)
		}
	case IfRozanehServer:
		s := ifc.RozanehServer
		if s == nil {
			v.add("%s: rozaneh_server section missing", p)
			return
		}
		if len(ifc.Addresses) != 1 {
			v.add("%s: rozaneh_server needs exactly one address, the tunnel gateway like 10.77.0.1/24", p)
		}
		var subnet netip.Prefix
		if len(ifc.Addresses) == 1 {
			pfx, err := netip.ParsePrefix(ifc.Addresses[0])
			if err == nil && (!pfx.Addr().Is4() || pfx.Bits() > 30) {
				v.add("%s: tunnel address must be IPv4 with room for clients", p)
			}
			subnet = pfx
		}
		if !domainRe.MatchString(s.Domain) {
			v.add("%s: rozaneh_server.domain %q must be a DNS name pointing at this router", p, s.Domain)
		}
		if !strings.HasPrefix(s.Path, "/") || len(s.Path) < 8 || strings.ContainsAny(s.Path, " ?#") {
			v.add("%s: rozaneh_server.path must start with / and be at least 8 characters", p)
		}
		if !wgKey(s.PrivateKey) {
			v.add("%s: rozaneh_server.private_key is not a base64 32-byte key", p)
		}
		if (s.CertPEM == "") != (s.KeyPEM == "") {
			v.add("%s: cert_pem and key_pem go together", p)
		}
		pub, listen := s.Ports()
		if pub < 1 || pub > 65535 || listen < 1 || listen > 65535 {
			v.add("%s: ports out of range", p)
		}
		switch listen {
		case 22, 53, 80, 443:
			v.add("%s: listen_port %d is used by the router itself", p, listen)
		}
		if s.CertPEM == "" && pub != 443 {
			v.add("%s: Let's Encrypt needs public_port 443; give cert_pem/key_pem to use another port", p)
		}
		if s.CoverURL != "" {
			if !strings.HasPrefix(s.CoverURL, "http://") && !strings.HasPrefix(s.CoverURL, "https://") {
				v.add("%s: cover_url must be an http(s) URL", p)
			}
		}
		for _, d := range s.ClientDNS {
			if _, err := netip.ParseAddr(d); err != nil {
				v.add("%s: client_dns %q is not an IP address", p, d)
			}
		}
		keys, ips, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for j, peer := range s.Peers {
			pp := fmt.Sprintf("%s.rozaneh_server.peers[%d]", p, j)
			if peer.Name == "" || len(peer.Name) > 64 || names[peer.Name] {
				v.add("%s: name must be 1-64 characters and unique", pp)
			}
			names[peer.Name] = true
			if !wgKey(peer.PublicKey) {
				v.add("%s: public_key is not a base64 32-byte key", pp)
			} else if keys[peer.PublicKey] {
				v.add("%s: public_key used twice", pp)
			}
			keys[peer.PublicKey] = true
			ip, err := netip.ParseAddr(peer.IP)
			switch {
			case err != nil:
				v.add("%s: ip %q is not an address", pp, peer.IP)
			case subnet.IsValid() && (!subnet.Masked().Contains(ip) || ip == subnet.Addr() || ip == subnet.Masked().Addr()):
				v.add("%s: ip %s is not a client address in %s", pp, ip, subnet.Masked())
			case ips[peer.IP]:
				v.add("%s: ip %s used twice", pp, ip)
			}
			ips[peer.IP] = true
		}
	}
}

func (v *validator) policyRoutes(names map[string]*Interface) {
	used := map[string]bool{}
	for i, r := range v.c.PolicyRoutes {
		p := fmt.Sprintf("policy_routes[%d]", i)
		ifc, ok := names[r.Interface]
		switch {
		case !ok:
			v.add("%s: interface %q does not exist", p, r.Interface)
		case ifc.Type == IfBridge || ifc.Type == IfLoopback || ifc.Type == IfRozanehServer:
			v.add("%s: %s interface %q cannot carry policy routes", p, ifc.Type, r.Interface)
		}
		if used[r.Interface] {
			v.add("%s: interface %q already has a policy route", p, r.Interface)
		}
		used[r.Interface] = true
		switch r.From {
		case PolicyFromLAN:
		case PolicyFromDevices:
			if len(r.Devices) == 0 {
				v.add("%s: choose at least one device", p)
			}
		default:
			v.add("%s: from must be lan or devices", p)
		}
		for _, d := range r.Devices {
			if a, err := netip.ParseAddr(d); err == nil && a.Is4() {
				continue
			}
			if pf, err := netip.ParsePrefix(d); err == nil && pf.Addr().Is4() {
				continue
			}
			v.add("%s: device %q must be an IPv4 address or prefix", p, d)
		}
	}
	if len(v.c.PolicyRoutes) > 50 {
		v.add("policy_routes: at most 50")
	}
}

// RozanehServerFor reports the rozaneh_server interface, if any.
func (c *Config) RozanehServerFor() *Interface {
	for i := range c.Interfaces {
		if c.Interfaces[i].Type == IfRozanehServer && !c.Interfaces[i].Disabled {
			return &c.Interfaces[i]
		}
	}
	return nil
}
