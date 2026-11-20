package render

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path"
	"strings"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// OpenVPN paths and units. Clients and the server share one unit template,
// instance = interface name (the server is config.OpenVPNServerIf).
const (
	OpenVPNDir = "/etc/mahan-router/openvpn"
	// OpenVPNRunDir is the units' RuntimeDirectory (status file and
	// management socket of the server).
	OpenVPNRunDir   = "/run/mahan-openvpn"
	OpenVPNStatus   = OpenVPNRunDir + "/" + config.OpenVPNServerIf + ".status"
	OpenVPNMgmt     = OpenVPNRunDir + "/" + config.OpenVPNServerIf + ".sock"
	OpenVPNUsers    = OpenVPNDir + "/" + config.OpenVPNServerIf + ".users"
	openVPNAuthCmd  = "/usr/sbin/mrctl ovpn-auth " + OpenVPNUsers
	openVPNCiphers  = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
	openVPNCBCs     = "AES-256-CBC:AES-192-CBC:AES-128-CBC"
	defaultOVPNFall = config.OpenVPNCipher
)

// OpenVPNConfPath is the openvpn config of a client or the server.
func OpenVPNConfPath(n string) string { return path.Join(OpenVPNDir, n+".conf") }

// OpenVPNAuthPath holds a client's user name and password.
func OpenVPNAuthPath(n string) string { return path.Join(OpenVPNDir, n+".auth") }

// OpenVPNUnit runs openvpn for a client interface or the server.
func OpenVPNUnit(n string) string { return "mahan-openvpn@" + n + ".service" }

// ffdhe2048 (RFC 7919) for clients that only do DHE key exchange.
const ffdhe2048 = `-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----`

func inline(w *strings.Builder, tag, pem string) {
	fmt.Fprintf(w, "<%s>\n%s\n</%s>\n", tag, strings.TrimSpace(pem), tag)
}

// The router decides routing (policy routes), not the server: pushed
// default and other routes are ignored, like the PPP clients' nodefaultroute.
const openVPNClientTail = `dev-type tun
script-security 1
route-noexec
pull-filter ignore "redirect-gateway"
pull-filter ignore "route-ipv6"
pull-filter ignore "ifconfig-ipv6"
persist-tun
persist-key
auth-nocache
auth-retry nointeract
resolv-retry infinite
connect-retry 5 30
keepalive 10 60
suppress-timestamps
verb 3
`

func renderOpenVPN(c *config.Config, b Bundle) error {
	for i := range c.Interfaces {
		ifc := &c.Interfaces[i]
		if ifc.Type != config.IfOpenVPN || ifc.OpenVPN == nil {
			continue
		}
		o := ifc.OpenVPN
		var w strings.Builder
		fmt.Fprintf(&w, "# %s\nclient\n", Header)
		if o.Config != "" {
			f, err := config.ParseOVPN(o.Config)
			if err != nil {
				return fmt.Errorf("%s: %w", ifc.Name, err)
			}
			w.WriteString("# --- imported .ovpn ---\n")
			for _, l := range f.Lines {
				w.WriteString(l + "\n")
			}
			w.WriteString("# --- router settings ---\n")
		} else {
			proto := "tcp-client"
			if o.ProtoOr() == "udp" {
				proto = "udp"
			}
			fmt.Fprintf(&w, "remote %s %d\nproto %s\n", o.Server, o.PortOr(), proto)
			if proto == "udp" {
				w.WriteString("nobind\nexplicit-exit-notify 1\n")
			}
			// RouterOS 6 and other servers without cipher negotiation use
			// the fallback; newer ones negotiate one of data-ciphers.
			fall := o.Cipher
			if fall == "" {
				fall = defaultOVPNFall
			}
			fmt.Fprintf(&w, "data-ciphers %s\ndata-ciphers-fallback %s\n", cipherList(fall), fall)
			auth := o.Auth
			if auth == "" {
				auth = config.OpenVPNAuth
			}
			fmt.Fprintf(&w, "auth %s\n", auth)
			if o.CAPEM != "" {
				inline(&w, "ca", o.CAPEM)
			} else {
				fmt.Fprintf(&w, "peer-fingerprint %s\n", config.NormFingerprint(o.Fingerprint))
			}
			if o.CertPEM != "" {
				inline(&w, "cert", o.CertPEM)
				inline(&w, "key", o.KeyPEM)
			}
		}
		fmt.Fprintf(&w, "dev %s\n", ifc.Name)
		w.WriteString(openVPNClientTail)
		if ifc.MTU != 0 {
			fmt.Fprintf(&w, "tun-mtu %d\n", ifc.MTU)
		}
		if o.Username != "" {
			fmt.Fprintf(&w, "auth-user-pass %s\n", OpenVPNAuthPath(ifc.Name))
			b.add(OpenVPNAuthPath(ifc.Name), CompVPN, 0o600, o.Username+"\n"+o.Password+"\n")
		}
		if ifc.Disabled {
			// Also makes enabling it again change the file, which restarts the unit.
			w.WriteString("# interface disabled: unit is stopped\n")
		}
		b.add(OpenVPNConfPath(ifc.Name), CompVPN, 0o600, w.String())
	}
	renderOpenVPNServer(c, b)
	return nil
}

// cipherList puts the pinned cipher first and keeps the others for
// negotiation.
func cipherList(first string) string {
	out := []string{first}
	for _, x := range strings.Split(openVPNCiphers+":"+openVPNCBCs, ":") {
		if x != first {
			out = append(out, x)
		}
	}
	return strings.Join(out, ":")
}

func renderOpenVPNServer(c *config.Config, b Bundle) {
	s := c.PPPServer
	if s == nil || s.OpenVPN == nil {
		return
	}
	o := s.OpenVPN
	port, proto, addr, cipher, auth := o.Defaults()
	gw, err := netip.ParsePrefix(addr)
	if err != nil {
		return
	}
	mask := net.IP(net.CIDRMask(gw.Bits(), 32)).String()
	first, last := openVPNPool(gw)
	var w strings.Builder
	fmt.Fprintf(&w, "# %s\nmode server\ntls-server\n", Header)
	fmt.Fprintf(&w, "dev %s\ndev-type tun\ntopology subnet\n", config.OpenVPNServerIf)
	if proto == "udp" {
		fmt.Fprintf(&w, "proto udp\nport %d\n", port)
	} else {
		fmt.Fprintf(&w, "proto tcp-server\nport %d\n", port)
	}
	fmt.Fprintf(&w, "ifconfig %s %s\nifconfig-pool %s %s %s\n", gw.Addr(), mask, first, last, mask)
	fmt.Fprintf(&w, "push \"topology subnet\"\npush \"route-gateway %s\"\n", gw.Addr())
	if o.SplitTunnel {
		if s.AllowLAN {
			for _, p := range lanSubnets(c) {
				fmt.Fprintf(&w, "push \"route %s %s\"\n", p.Addr(), net.IP(net.CIDRMask(p.Bits(), 32)))
			}
		}
	} else {
		w.WriteString("push \"redirect-gateway def1 bypass-dhcp\"\n")
	}
	dns := s.ClientDNS
	if len(dns) == 0 {
		dns = strings.Split(defaultClientNS, ",")
	}
	for _, d := range dns {
		if a, err := netip.ParseAddr(d); err == nil && a.Is4() {
			fmt.Fprintf(&w, "push \"dhcp-option DNS %s\"\n", d)
		}
	}
	w.WriteString("keepalive 10 60\n")
	fmt.Fprintf(&w, "data-ciphers %s:%s\ndata-ciphers-fallback %s\nauth %s\n", openVPNCiphers, openVPNCBCs, cipher, auth)
	inline(&w, "ca", o.CertPEM)
	inline(&w, "cert", o.CertPEM)
	inline(&w, "key", o.KeyPEM)
	inline(&w, "dh", ffdhe2048)
	// Users log in with the PPP server's user names and passwords.
	w.WriteString("verify-client-cert none\nusername-as-common-name\nscript-security 2\n")
	fmt.Fprintf(&w, "auth-user-pass-verify %q via-file\n", openVPNAuthCmd)
	fmt.Fprintf(&w, "status %s 5\nstatus-version 2\nmanagement %s unix\n", OpenVPNStatus, OpenVPNMgmt)
	w.WriteString("persist-key\npersist-tun\nsuppress-timestamps\nverb 3\n")
	if s.Disabled || !o.Enabled {
		w.WriteString("# server disabled: unit is stopped\n")
	}
	b.add(OpenVPNConfPath(config.OpenVPNServerIf), CompVPN, 0o600, w.String())

	users := map[string]string{}
	for _, u := range s.Users {
		if !u.Disabled {
			users[u.Name] = u.Password
		}
	}
	j, _ := json.MarshalIndent(users, "", "  ")
	b.add(OpenVPNUsers, CompVPN, 0o600, string(j)+"\n")
}

// openVPNPool is the longest run of client addresses in the subnet: all
// hosts except the router's own address.
func openVPNPool(gw netip.Prefix) (netip.Addr, netip.Addr) {
	pfx := gw.Masked()
	first := pfx.Addr().Next()
	last := first
	for a := first; pfx.Contains(a.Next()); a = a.Next() {
		last = a // ends one before the broadcast address
	}
	r := gw.Addr()
	switch {
	case r == first:
		return r.Next(), last
	case r == last:
		return first, r.Prev()
	}
	// The router sits in the middle: take the larger side.
	below := r.Prev()
	above := r.Next()
	if dist(first, below) >= dist(above, last) {
		return first, below
	}
	return above, last
}

func dist(a, b netip.Addr) uint32 {
	x, y := a.As4(), b.As4()
	return (uint32(y[0])<<24 | uint32(y[1])<<16 | uint32(y[2])<<8 | uint32(y[3])) -
		(uint32(x[0])<<24 | uint32(x[1])<<16 | uint32(x[2])<<8 | uint32(x[3]))
}

// lanSubnets are the IPv4 subnets of the LAN interface list.
func lanSubnets(c *config.Config) []netip.Prefix {
	var out []netip.Prefix
	for _, n := range c.InterfaceLists["LAN"] {
		ifc := c.Interface(n)
		if ifc == nil {
			continue
		}
		for _, a := range ifc.Addresses {
			if p, err := netip.ParsePrefix(a); err == nil && p.Addr().Is4() {
				out = append(out, p.Masked())
			}
		}
	}
	return out
}
