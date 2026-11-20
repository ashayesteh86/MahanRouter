package config

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// PPP-family VPNs (MikroTik's /interface pptp-client, l2tp-client,
// sstp-client and the matching servers) and static L2TPv3 tunnels.
const (
	IfPPTP   = "pptp"
	IfL2TP   = "l2tp"
	IfSSTP   = "sstp"
	IfL2TPv3 = "l2tpv3"
)

// PPPServerIf is the interface name prefix of PPP server sessions
// (pppsN). It can be used like an interface name in interface lists and
// firewall rules, where it matches every session.
const PPPServerIf = "ppps"

// IsPPPClient reports the interface types dialled by pppd.
func IsPPPClient(t string) bool { return t == IfPPTP || t == IfL2TP || t == IfSSTP }

// PPPClient is a PPTP, L2TP or SSTP client connection.
type PPPClient struct {
	// Server is the host name or IP address; SSTP may add :port (443).
	Server   string `yaml:"server" json:"server"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
	// IPsecSecret (L2TP only) is the IPsec pre-shared key. Empty means
	// plain L2TP without IPsec, which few servers accept.
	IPsecSecret string `yaml:"ipsec_secret,omitempty" json:"ipsec_secret,omitempty"`
	// VerifyCert (SSTP only) refuses servers whose certificate is not
	// trusted. Off by default, because most SSTP servers (MikroTik,
	// Windows RRAS) use self-signed certificates.
	VerifyCert bool `yaml:"verify_cert,omitempty" json:"verify_cert,omitempty"`
}

// L2TPv3 is a static (unmanaged) L2TPv3 Ethernet pseudowire to another
// router. Both ends must use mirrored tunnel and session IDs.
type L2TPv3 struct {
	// Local is this router's address the tunnel runs from (empty: auto).
	Local  string `yaml:"local,omitempty" json:"local,omitempty"`
	Remote string `yaml:"remote" json:"remote"`
	// Encapsulation: udp (default) or ip (IP protocol 115).
	Encapsulation string `yaml:"encapsulation,omitempty" json:"encapsulation,omitempty"`
	// Port is the UDP port on both ends (default 1701).
	Port          int    `yaml:"port,omitempty" json:"port,omitempty"`
	TunnelID      uint32 `yaml:"tunnel_id" json:"tunnel_id"`
	PeerTunnelID  uint32 `yaml:"peer_tunnel_id" json:"peer_tunnel_id"`
	SessionID     uint32 `yaml:"session_id" json:"session_id"`
	PeerSessionID uint32 `yaml:"peer_session_id" json:"peer_session_id"`
}

// L2TPv3 defaults.
const L2TPPort = 1701

// UDPPort returns the UDP port, or 0 for IP encapsulation.
func (l *L2TPv3) UDPPort() int {
	if l.Encapsulation == "ip" {
		return 0
	}
	if l.Port == 0 {
		return L2TPPort
	}
	return l.Port
}

// PPPServer runs PPTP, L2TP(/IPsec) and SSTP servers (accel-ppp) for
// phones, laptops and other routers. All three share the users and the
// address pool; sessions appear as interfaces ppps0, ppps1, ...
type PPPServer struct {
	Disabled bool `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	// Address is the router's side of the tunnels and the client subnet,
	// e.g. 10.80.0.1/24. Clients get the other addresses of the subnet.
	Address string `yaml:"address" json:"address"`
	// ClientDNS is given to clients (default 1.1.1.1 and 8.8.8.8).
	ClientDNS []string `yaml:"client_dns,omitempty" json:"client_dns,omitempty"`
	MTU       int      `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	// AllowLAN lets clients reach the LAN and the router; otherwise they
	// only get the internet.
	AllowLAN bool           `yaml:"allow_lan,omitempty" json:"allow_lan,omitempty"`
	PPTP     *PPPServerPPTP `yaml:"pptp,omitempty" json:"pptp,omitempty"`
	L2TP     *PPPServerL2TP `yaml:"l2tp,omitempty" json:"l2tp,omitempty"`
	SSTP     *PPPServerSSTP `yaml:"sstp,omitempty" json:"sstp,omitempty"`
	// OpenVPN server for the same users, on its own subnet.
	OpenVPN *PPPServerOpenVPN `yaml:"openvpn,omitempty" json:"openvpn,omitempty"`
	Users   []PPPUser         `yaml:"users,omitempty" json:"users,omitempty"`
}

// PPPServerPPTP enables the PPTP server (TCP 1723 + GRE). PPTP's
// encryption (MPPE/MS-CHAPv2) is broken; it is here for old devices.
type PPPServerPPTP struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// PPPServerL2TP enables the L2TP server (UDP 1701), with IPsec (UDP
// 500/4500 + ESP) when IPsecSecret is set.
type PPPServerL2TP struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	IPsecSecret string `yaml:"ipsec_secret,omitempty" json:"ipsec_secret,omitempty"`
}

// PPPServerSSTP enables the SSTP server (PPP over TLS).
type PPPServerSSTP struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// PublicPort is what clients dial (443); the router redirects it from
	// WAN to ListenPort, because the web panel holds 443.
	PublicPort int `yaml:"public_port,omitempty" json:"public_port,omitempty"`
	ListenPort int `yaml:"listen_port,omitempty" json:"listen_port,omitempty"`
	// Domain is the name clients dial; it must match the certificate.
	Domain  string `yaml:"domain,omitempty" json:"domain,omitempty"`
	CertPEM string `yaml:"cert_pem" json:"cert_pem"`
	KeyPEM  string `yaml:"key_pem" json:"key_pem"`
}

// SSTP port defaults.
const (
	SSTPPublicPort = 443
	SSTPListenPort = 8445
)

// Ports returns the SSTP public and listen ports with defaults applied.
func (s *PPPServerSSTP) Ports() (public, listen int) {
	public, listen = s.PublicPort, s.ListenPort
	if public == 0 {
		public = SSTPPublicPort
	}
	if listen == 0 {
		listen = SSTPListenPort
	}
	return
}

// PPPUser is one PPP server account (MikroTik's /ppp secret).
type PPPUser struct {
	Name     string `yaml:"name" json:"name"`
	Password string `yaml:"password" json:"password"`
	// IP pins the user to an address in the server subnet.
	IP       string `yaml:"ip,omitempty" json:"ip,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// PPTPOn, L2TPOn and SSTPOn report which server protocols run.
func (s *PPPServer) PPTPOn() bool { return s != nil && !s.Disabled && s.PPTP != nil && s.PPTP.Enabled }
func (s *PPPServer) L2TPOn() bool { return s != nil && !s.Disabled && s.L2TP != nil && s.L2TP.Enabled }
func (s *PPPServer) SSTPOn() bool { return s != nil && !s.Disabled && s.SSTP != nil && s.SSTP.Enabled }

// Running reports whether the server has anything to run.
func (s *PPPServer) Running() bool { return s.PPTPOn() || s.L2TPOn() || s.SSTPOn() }

// L2TPClientPort is the local UDP port xl2tpd uses: 1701, or 1702 when the
// L2TP server holds 1701.
func (c *Config) L2TPClientPort() int {
	if c.PPPServer.L2TPOn() {
		return L2TPPort + 1
	}
	return L2TPPort
}

// pppSafe rejects characters that would break pppd, accel-ppp, xl2tpd or
// swanctl files, where these values are written inside double quotes.
func pppSafe(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

func hostOK(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return domainRe.MatchString(h)
}

func (v *validator) pppClient(p string, ifc *Interface) {
	pc := ifc.PPP
	if pc == nil {
		v.add("%s: ppp section missing", p)
		return
	}
	host := pc.Server
	if ifc.Type == IfSSTP {
		if h, port, err := net.SplitHostPort(pc.Server); err == nil {
			n, _ := strconv.Atoi(port)
			if n < 1 || n > 65535 {
				v.add("%s: ppp.server port out of range", p)
			}
			host = h
		}
	}
	if !hostOK(host) {
		v.add("%s: ppp.server %q must be a host name or IP address", p, pc.Server)
	}
	if !pppSafe(pc.Username) {
		v.add("%s: ppp.username is required and may not contain quotes, backslashes or control characters", p)
	}
	if !pppSafe(pc.Password) {
		v.add("%s: ppp.password is required and may not contain quotes, backslashes or control characters", p)
	}
	if pc.IPsecSecret != "" && (ifc.Type != IfL2TP || !pppSafe(pc.IPsecSecret)) {
		v.add("%s: ppp.ipsec_secret is only for l2tp and may not contain quotes, backslashes or control characters", p)
	}
	if pc.VerifyCert && ifc.Type != IfSSTP {
		v.add("%s: ppp.verify_cert is only for sstp", p)
	}
	if len(ifc.Addresses) > 0 || ifc.Addressing == AddrStatic || ifc.Addressing == AddrDHCP {
		v.add("%s: the server assigns the address, leave addressing empty", p)
	}
}

func (v *validator) l2tpv3(p string, ifc *Interface) {
	l := ifc.L2TPv3
	if l == nil {
		v.add("%s: l2tpv3 section missing", p)
		return
	}
	rem, err := netip.ParseAddr(l.Remote)
	if err != nil {
		v.add("%s: l2tpv3.remote must be an IP address", p)
	}
	if l.Local != "" {
		loc, err := netip.ParseAddr(l.Local)
		if err != nil {
			v.add("%s: l2tpv3.local must be an IP address or empty", p)
		} else if rem.IsValid() && loc.Is4() != rem.Is4() {
			v.add("%s: l2tpv3.local and remote must be the same IP version", p)
		}
	}
	switch l.Encapsulation {
	case "", "udp", "ip":
	default:
		v.add("%s: l2tpv3.encapsulation must be udp or ip", p)
	}
	if l.Port < 0 || l.Port > 65535 {
		v.add("%s: l2tpv3.port out of range", p)
	}
	if l.TunnelID == 0 || l.PeerTunnelID == 0 || l.SessionID == 0 || l.PeerSessionID == 0 {
		v.add("%s: l2tpv3 tunnel and session IDs must be 1-4294967295", p)
	}
}

// pppChecks runs after the interfaces: things that span several of them.
func (v *validator) pppChecks() {
	c := v.c
	tunnels := map[uint32]string{}
	ports := map[string]string{}
	l2tpClients := false
	for _, ifc := range c.Interfaces {
		if ifc.Type == IfL2TP {
			l2tpClients = true
		}
		if ifc.Type != IfL2TPv3 || ifc.L2TPv3 == nil {
			continue
		}
		l := ifc.L2TPv3
		p := fmt.Sprintf("interfaces[%s]", ifc.Name)
		if prev, dup := tunnels[l.TunnelID]; dup {
			v.add("%s: l2tpv3 tunnel_id %d is already used by %s", p, l.TunnelID, prev)
		}
		tunnels[l.TunnelID] = ifc.Name
		if port := l.UDPPort(); port != 0 {
			key := l.Local + "/" + strconv.Itoa(port)
			if prev, dup := ports[key]; dup {
				v.add("%s: l2tpv3 UDP port %d is already used by %s; give each tunnel its own port", p, port, prev)
			}
			ports[key] = ifc.Name
			if port == L2TPPort && c.PPPServer.L2TPOn() {
				v.add("%s: UDP port 1701 is used by the L2TP server; use another l2tpv3 port", p)
			}
			if port == c.L2TPClientPort() && l2tpClients {
				v.add("%s: UDP port %d is used by the L2TP client; use another l2tpv3 port", p, port)
			}
		}
	}
	for _, ifc := range c.Interfaces {
		if strings.HasPrefix(ifc.Name, PPPServerIf) {
			v.add("interfaces[%s]: names starting with %q are kept for PPP server sessions", ifc.Name, PPPServerIf)
		}
	}
	v.pppServer()
}

func (v *validator) pppServer() {
	s := v.c.PPPServer
	if s == nil {
		return
	}
	gw, err := netip.ParsePrefix(s.Address)
	if err != nil || !gw.Addr().Is4() || gw.Bits() < 16 || gw.Bits() > 29 {
		v.add("ppp_server.address must be an IPv4 address with a /16 to /29 subnet, like 10.80.0.1/24")
	} else if gw.Addr() == gw.Masked().Addr() {
		v.add("ppp_server.address must be a host address, like 10.80.0.1/24")
	}
	for _, d := range s.ClientDNS {
		if _, err := netip.ParseAddr(d); err != nil {
			v.add("ppp_server.client_dns: %q is not an IP address", d)
		}
	}
	if s.MTU != 0 && (s.MTU < 576 || s.MTU > 1500) {
		v.add("ppp_server.mtu out of range 576-1500")
	}
	if s.PPTP == nil && s.L2TP == nil && s.SSTP == nil && s.OpenVPN == nil {
		v.add("ppp_server: enable at least one of pptp, l2tp, sstp or openvpn")
	}
	if s.OpenVPN != nil {
		v.openvpnServer(gw)
	}
	if s.L2TP != nil && s.L2TP.IPsecSecret != "" && !pppSafe(s.L2TP.IPsecSecret) {
		v.add("ppp_server.l2tp.ipsec_secret may not contain quotes, backslashes or control characters")
	}
	if st := s.SSTP; st != nil {
		pub, listen := st.Ports()
		if pub < 1 || pub > 65535 || listen < 1 || listen > 65535 {
			v.add("ppp_server.sstp: ports out of range")
		}
		switch listen {
		case 22, 53, 80, 443, 1701, 1723, RozanehListenPort:
			v.add("ppp_server.sstp.listen_port %d is used by the router itself", listen)
		}
		if rz := v.c.RozanehServerFor(); rz != nil {
			if rp, rl := rz.RozanehServer.Ports(); rp == pub || rl == listen {
				v.add("ppp_server.sstp: port %d is already used by the Rozaneh server", pub)
			}
		}
		if vs := v.c.V2RayServer; vs != nil {
			if _, vp, vl, _ := vs.Defaults(); vp == pub || vl == listen {
				v.add("ppp_server.sstp: port %d is already used by the V2Ray server", pub)
			}
		}
		if st.Domain != "" && !hostOK(st.Domain) {
			v.add("ppp_server.sstp.domain %q is not a host name", st.Domain)
		}
		if _, err := tls.X509KeyPair([]byte(st.CertPEM), []byte(st.KeyPEM)); err != nil {
			v.add("ppp_server.sstp: cert_pem/key_pem are not a valid certificate and key: %v", err)
		}
	}
	names := map[string]bool{}
	ips := map[string]bool{}
	for i, u := range s.Users {
		pp := fmt.Sprintf("ppp_server.users[%d]", i)
		if !pppSafe(u.Name) || strings.ContainsAny(u.Name, " \t") || names[u.Name] {
			v.add("%s: name must be unique, without spaces, quotes or backslashes", pp)
		}
		names[u.Name] = true
		if !pppSafe(u.Password) {
			v.add("%s: password is required and may not contain quotes, backslashes or control characters", pp)
		}
		if u.IP != "" {
			a, err := netip.ParseAddr(u.IP)
			switch {
			case err != nil:
				v.add("%s: ip %q is not an IP address", pp, u.IP)
			case gw.IsValid() && (!gw.Contains(a) || a == gw.Addr()):
				v.add("%s: ip %s must be inside %s and not the router's address", pp, u.IP, gw.Masked())
			case ips[u.IP]:
				v.add("%s: ip %s is given to two users", pp, u.IP)
			}
			ips[u.IP] = true
		}
	}
}
