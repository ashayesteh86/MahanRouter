package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/netip"
)

// IKEv2 server for phones and laptops ("road warriors"): the VPN type
// built into Windows, iOS, macOS and Android. Like RouterOS's IKEv2 with
// EAP, it lives next to the PPP server and uses its users.

// IKEv2ServerIf is the server's XFRM interface: every client's traffic
// arrives on it. It starts with the PPP server prefix, so what covers PPP
// sessions (the "ppps" pseudo interface in lists and firewall rules, the
// internet-only rules) covers IKEv2 clients too.
const IKEv2ServerIf = PPPServerIf + "-ike"

// IKEv2 defaults.
const (
	IKEv2Subnet = "10.82.0.1/24"
	// IKEv2IfID is the XFRM interface ID that ties the clients' SAs to
	// IKEv2ServerIf.
	IKEv2IfID = 82
	// IKEv2MTU leaves room for ESP in UDP on a 1500-byte path.
	IKEv2MTU = 1400
)

// PPPServerIKEv2 is the IKEv2 server. Clients check the router's
// certificate and log in with a PPP server user name and password
// (EAP-MSCHAPv2).
type PPPServerIKEv2 struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Address is the router's address and the client subnet
	// (default 10.82.0.1/24); it must not overlap the other VPN subnets.
	Address string `yaml:"address,omitempty" json:"address,omitempty"`
	// Domain is the name (or IP address) clients dial. It is the server's
	// IKE identity and must be in the certificate.
	Domain  string `yaml:"domain" json:"domain"`
	CertPEM string `yaml:"cert_pem" json:"cert_pem"`
	KeyPEM  string `yaml:"key_pem" json:"key_pem"`
	// CAPEM is the authority that signed CertPEM. Clients install it once;
	// it is empty when the certificate comes from a public authority.
	CAPEM string `yaml:"ca_pem,omitempty" json:"ca_pem,omitempty"`
	// SplitTunnel offers clients only this router's networks instead of
	// everything. Windows and iOS decide themselves what they send.
	SplitTunnel bool `yaml:"split_tunnel,omitempty" json:"split_tunnel,omitempty"`
}

// Subnet returns the router address and client subnet, with the default.
func (o *PPPServerIKEv2) Subnet() string {
	if o.Address == "" {
		return IKEv2Subnet
	}
	return o.Address
}

// IKEv2On reports whether the IKEv2 server runs.
func (s *PPPServer) IKEv2On() bool {
	return s != nil && !s.Disabled && s.IKEv2 != nil && s.IKEv2.Enabled
}

func (v *validator) ikev2Server(gw netip.Prefix) {
	s := v.c.PPPServer
	o := s.IKEv2
	ik, err := netip.ParsePrefix(o.Subnet())
	switch {
	case err != nil || !ik.Addr().Is4() || ik.Bits() < 16 || ik.Bits() > 29:
		v.add("ppp_server.ikev2.address must be an IPv4 address with a /16 to /29 subnet, like %s", IKEv2Subnet)
	case ik.Addr() == ik.Masked().Addr():
		v.add("ppp_server.ikev2.address must be a host address, like %s", IKEv2Subnet)
	case gw.IsValid() && ik.Overlaps(gw):
		v.add("ppp_server.ikev2.address %s overlaps the PPP subnet %s; give IKEv2 its own subnet", o.Subnet(), gw.Masked())
	default:
		if s.OpenVPN != nil {
			_, _, addr, _, _ := s.OpenVPN.Defaults()
			if ov, err := netip.ParsePrefix(addr); err == nil && ik.Overlaps(ov) {
				v.add("ppp_server.ikev2.address %s overlaps the OpenVPN subnet %s", o.Subnet(), ov.Masked())
			}
		}
	}
	if o.Domain == "" || !hostOK(o.Domain) {
		v.add("ppp_server.ikev2.domain must be the host name or IP address clients dial")
	}
	pair, err := tls.X509KeyPair([]byte(o.CertPEM), []byte(o.KeyPEM))
	if err != nil {
		v.add("ppp_server.ikev2: cert_pem/key_pem are not a valid certificate and key: %v", err)
	} else if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil && o.Domain != "" && hostOK(o.Domain) {
		// Clients refuse a server whose certificate does not name it.
		if err := leaf.VerifyHostname(o.Domain); err != nil {
			v.add("ppp_server.ikev2: the certificate is not for %q (it must list that name)", o.Domain)
		}
	}
	if o.CAPEM != "" {
		blk, _ := pem.Decode([]byte(o.CAPEM))
		if blk == nil || blk.Type != "CERTIFICATE" {
			v.add("ppp_server.ikev2.ca_pem is not a PEM certificate")
		} else if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			v.add("ppp_server.ikev2.ca_pem: %v", err)
		}
	}
	if !o.Enabled || s.Disabled {
		return
	}
	for _, u := range s.Users {
		if !u.Disabled && !pppSafe(u.Password) {
			v.add("ppp_server.users[%s]: the password may not contain quotes or backslashes when IKEv2 is on", u.Name)
		}
	}
}
