package render

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// IKEv2 server for phones and laptops (strongSwan, EAP-MSCHAPv2 with the
// PPP server's users). The clients' SAs are tied to one XFRM interface,
// config.IKEv2ServerIf, so their traffic passes the firewall like that of
// PPP and OpenVPN clients.
const (
	IKEv2Conn = "mr-ikev2"
	IKEv2Cert = "/etc/swanctl/x509/" + IKEv2Conn + ".pem"
	IKEv2Key  = "/etc/swanctl/private/" + IKEv2Conn + ".pem"
	// StrongswanConf turns off the plugins that come with the EAP
	// packages and that the router does not use.
	StrongswanConf = "/etc/strongswan.d/zz-mahan-router.conf"

	// Windows offers AES-256/SHA-1/MODP-1024 unless it is tuned; iOS,
	// macOS and Android offer the stronger ones first.
	ikev2IKE = "aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-ecp256,aes256-sha384-ecp384,aes256-sha256-ecp256," +
		"aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes256-sha384-modp1024,aes256-sha256-modp1024," +
		"aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024"
	ikev2ESP = "aes256gcm16,aes128gcm16,aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1,3des-sha1"
)

// unusedCharonPlugins come with libcharon-extra-plugins (needed for
// eap-identity) and load by default. None is used; some would change how
// addresses are handed out or how IKEv1 behaves.
var unusedCharonPlugins = []string{"addrblock", "certexpire", "dhcp", "eap-aka", "eap-gtc", "eap-md5", "eap-radius", "eap-tls",
	"eap-tnc", "eap-ttls", "error-notify", "farp", "forecast", "ha", "kernel-libipsec", "led", "lookip", "tnc-tnccs",
	"unity", "xauth-eap", "xauth-generic", "xauth-pam"}

func renderStrongswanConf(b Bundle) {
	var w strings.Builder
	fmt.Fprintf(&w, "# %s\ncharon {\n\tplugins {\n", Header)
	for _, p := range unusedCharonPlugins {
		fmt.Fprintf(&w, "\t\t%s {\n\t\t\tload = no\n\t\t}\n", p)
	}
	w.WriteString("\t}\n}\n")
	b.add(StrongswanConf, CompIPsec, 0o644, w.String())
}

// renderIKEv2Net makes the XFRM interface the clients arrive on. It holds
// the router's address in the client subnet, which also gives the route.
func renderIKEv2Net(c *config.Config, b Bundle) {
	s := c.PPPServer
	if !s.IKEv2On() {
		return
	}
	var nd ini
	nd.section("NetDev")
	nd.kv("Name", config.IKEv2ServerIf)
	nd.kv("Kind", "xfrm")
	nd.section("Xfrm")
	nd.kv("InterfaceId", config.IKEv2IfID)
	nd.kv("Independent", "yes")
	b.add(netdevPath(config.IKEv2ServerIf), CompNetwork, 0o644, nd.String())

	var nw ini
	nw.section("Match")
	nw.kv("Name", config.IKEv2ServerIf)
	nw.section("Link")
	nw.kv("RequiredForOnline", "no")
	nw.kv("MTUBytes", config.IKEv2MTU)
	nw.section("Network")
	nw.kv("Address", s.IKEv2.Subnet())
	nw.kv("LinkLocalAddressing", "no")
	nw.kv("IPv6AcceptRA", "no")
	b.add(networkPath(config.IKEv2ServerIf), CompNetwork, 0o644, nw.String())
}

// ikev2Server adds the server's connection, pool, user secrets and
// certificate files. It returns 1 when the server runs.
func ikev2Server(c *config.Config, conns, pools, secrets *strings.Builder, b Bundle) int {
	s := c.PPPServer
	if !s.IKEv2On() {
		return 0
	}
	o := s.IKEv2
	gw, err := netip.ParsePrefix(o.Subnet())
	if err != nil {
		return 0
	}
	first, last := openVPNPool(gw)
	ts := []string{"0.0.0.0/0"}
	if o.SplitTunnel {
		ts = []string{gw.Masked().String()}
		if s.AllowLAN {
			for _, p := range lanSubnets(c) {
				ts = append(ts, p.String())
			}
		}
	}
	fmt.Fprintf(conns, `	%[1]s {
		version = 2
		proposals = %[2]s
		send_cert = always
		send_certreq = no
		pools = %[1]s
		fragmentation = yes
		unique = never
		dpd_delay = 60s
		rekey_time = 0s
		local {
			auth = pubkey
			certs = %[1]s.pem
			id = %[3]s
		}
		remote {
			auth = eap-mschapv2
			eap_id = %%any
		}
		children {
			%[1]s {
				local_ts = %[4]s
				esp_proposals = %[5]s
				dpd_action = clear
				rekey_time = 0s
				if_id_in = %[6]d
				if_id_out = %[6]d
			}
		}
	}
`, IKEv2Conn, ikev2IKE, o.Domain, strings.Join(ts, ","), ikev2ESP, config.IKEv2IfID)

	dns := s.ClientDNS
	if len(dns) == 0 {
		dns = strings.Split(defaultClientNS, ",")
	}
	var v4 []string
	for _, d := range dns {
		if a, err := netip.ParseAddr(d); err == nil && a.Is4() {
			v4 = append(v4, d)
		}
	}
	fmt.Fprintf(pools, "\t%s {\n\t\taddrs = %s-%s\n", IKEv2Conn, first, last)
	if len(v4) > 0 {
		fmt.Fprintf(pools, "\t\tdns = %s\n", strings.Join(v4, ","))
	}
	pools.WriteString("\t}\n")

	for i, u := range s.Users {
		if !u.Disabled {
			fmt.Fprintf(secrets, "\teap-mr-user%d {\n\t\tid = %s\n\t\tsecret = %s\n\t}\n", i, quote(u.Name), quote(u.Password))
		}
	}
	b.add(IKEv2Cert, CompIPsec, 0o644, strings.TrimSpace(o.CertPEM)+"\n")
	b.add(IKEv2Key, CompIPsec, 0o600, strings.TrimSpace(o.KeyPEM)+"\n")
	return 1
}

// ikev2Rules: IKE and ESP in from anywhere, and a TCP MSS that fits the
// tunnel in both directions (clients sit behind every kind of network).
func ikev2Rules(c *config.Config, chain string) []string {
	if !c.PPPServer.IKEv2On() {
		return nil
	}
	tag := quote("ikev2 server")
	switch chain {
	case "input":
		return []string{
			"udp dport { 500, 4500 } counter accept comment " + tag,
			"meta l4proto 50 counter accept comment " + tag,
		}
	case "forward":
		mss := config.IKEv2MTU - 40
		ifn := quote(config.IKEv2ServerIf)
		return []string{
			fmt.Sprintf("iifname %s tcp flags syn tcp option maxseg size set %d comment %s", ifn, mss, quote("ikev2 server: MSS")),
			fmt.Sprintf("oifname %s tcp flags syn tcp option maxseg size set %d comment %s", ifn, mss, quote("ikev2 server: MSS")),
		}
	}
	return nil
}
