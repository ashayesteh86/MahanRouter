package render

import (
	"fmt"
	"net"
	"net/netip"
	"path"
	"strings"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// Files and units of the PPP-family VPNs.
const (
	XL2TPDConf      = "/etc/xl2tpd/xl2tpd.conf"
	XL2TPDUnit      = "xl2tpd.service"
	SwanctlConf     = "/etc/swanctl/conf.d/mahan.conf"
	IPsecUnit       = "strongswan.service"
	AccelDir        = "/etc/accel-ppp"
	AccelConf       = AccelDir + "/accel-ppp.conf"
	AccelSecrets    = AccelDir + "/chap-secrets"
	AccelCert       = AccelDir + "/sstp.pem"
	AccelKey        = AccelDir + "/sstp.key"
	PPPServerUnit   = "mahan-ppp-server.service"
	AccelCLI        = "127.0.0.1:2001"
	pppClientMTU    = 1400
	defaultClientNS = "1.1.1.1,8.8.8.8"
)

// PPPClientUnit runs pppd for a PPTP or SSTP client (L2TP runs under xl2tpd).
func PPPClientUnit(name string) string { return "mahan-ppp@" + name + ".service" }

// PPPPeerFile is the pppd options file of a PPP interface.
func PPPPeerFile(name string) string { return path.Join(PPPPeersDir, "mr-"+name) }

// L2TPOptionsFile is the pppd options file xl2tpd uses for an L2TP client.
func L2TPOptionsFile(name string) string { return "/etc/ppp/mr-" + name + ".l2tp" }

// pppRemote is the remotename that ties a connection to its secret line.
func pppRemote(name string) string { return "mr-" + name }

const pppCommon = "noauth\nhide-password\nnoipdefault\nnodefaultroute\nlcp-echo-interval 20\nlcp-echo-failure 3\nnoaccomp\ndefault-asyncmap\nnopcomp\nrefuse-eap\n"

func renderPPP(c *config.Config, b Bundle) {
	var secrets strings.Builder
	secrets.WriteString("# " + Header + "\n# client\tserver\tsecret\tIP addresses\n")
	any := false
	var lacs []string
	for _, ifc := range c.Interfaces {
		switch {
		case ifc.Type == config.IfPPPoE && ifc.PPPoE != nil:
			any = true
			renderPPPoE(&ifc, b)
			p := ifc.PPPoE
			fmt.Fprintf(&secrets, "%s\t*\t%s\t*\n", quote(p.Username), quote(p.Password))
		case config.IsPPPClient(ifc.Type) && ifc.PPP != nil:
			any = true
			p := ifc.PPP
			fmt.Fprintf(&secrets, "%s\t%s\t%s\t*\n", quote(p.Username), pppRemote(ifc.Name), quote(p.Password))
			opts := pppClientOptions(&ifc)
			if ifc.Type == config.IfL2TP {
				b.add(L2TPOptionsFile(ifc.Name), CompPPP, 0o640, opts)
				if !ifc.Disabled {
					lacs = append(lacs, ifc.Name)
				}
			} else {
				b.add(PPPPeerFile(ifc.Name), CompPPP, 0o640, opts)
			}
		}
	}
	if any {
		b.add("/etc/ppp/chap-secrets", CompPPP, 0o600, secrets.String())
		b.add("/etc/ppp/pap-secrets", CompPPP, 0o600, secrets.String())
	}
	if len(lacs) > 0 {
		var w strings.Builder
		fmt.Fprintf(&w, "; %s\n[global]\nport = %d\naccess control = no\n", Header, c.L2TPClientPort())
		for _, n := range lacs {
			ifc := c.Interface(n)
			fmt.Fprintf(&w, "\n[lac %s]\nlns = %s\npppoptfile = %s\nname = %s\nautodial = yes\nredial = yes\nredial timeout = 10\nlength bit = yes\n",
				n, ifc.PPP.Server, L2TPOptionsFile(n), ifc.PPP.Username)
		}
		b.add(XL2TPDConf, CompPPP, 0o640, w.String())
	}
}

func renderPPPoE(ifc *config.Interface, b Bundle) {
	p := ifc.PPPoE
	var w strings.Builder
	fmt.Fprintf(&w, "# %s\nplugin pppoe.so\nnic-%s\nifname %s\nuser %s\n", Header, ifc.Parent, ifc.Name, quote(p.Username))
	if p.ServiceName != "" {
		fmt.Fprintf(&w, "rp_pppoe_service %s\n", quote(p.ServiceName))
	}
	w.WriteString("noauth\nhide-password\nnoipdefault\npersist\nmaxfail 0\nholdoff 5\nlcp-echo-interval 20\nlcp-echo-failure 3\nnoaccomp\ndefault-asyncmap\n")
	if p.AddDefaultRoute {
		w.WriteString("defaultroute\nreplacedefaultroute\n")
	}
	if p.UsePeerDNS {
		w.WriteString("usepeerdns\n")
	}
	mtu := ifc.MTU
	if mtu == 0 {
		mtu = 1492
	}
	fmt.Fprintf(&w, "mtu %d\nmru %d\n", mtu, mtu)
	if ifc.Disabled {
		w.WriteString("# interface disabled: unit is stopped\n")
	}
	b.add(PPPPeerFile(ifc.Name), CompPPP, 0o640, w.String())
}

// pppClientOptions renders the pppd options of a PPTP, L2TP or SSTP client.
// Routing is left to policy routes: the tunnel never takes the router's
// own default route, so the connection to the server keeps working.
func pppClientOptions(ifc *config.Interface) string {
	p := ifc.PPP
	var w strings.Builder
	fmt.Fprintf(&w, "# %s\n", Header)
	switch ifc.Type {
	case config.IfPPTP:
		fmt.Fprintf(&w, "pty \"pptp %s --nolaunchpppd --loglevel 0\"\n", p.Server)
		// PPTP carries MPPE over MS-CHAPv2 only.
		w.WriteString("require-mppe-128\nrefuse-pap\nrefuse-chap\nrefuse-mschap\nnobsdcomp\nnodeflate\n")
	case config.IfSSTP:
		flags := "--ipparam " + pppRemote(ifc.Name) + " --nolaunchpppd --save-server-route"
		host := p.Server
		if h, _, err := net.SplitHostPort(p.Server); err == nil {
			host = h
		}
		if _, err := netip.ParseAddr(host); err != nil {
			flags += " --tls-ext"
		}
		if !p.VerifyCert {
			flags += " --cert-warn"
		}
		fmt.Fprintf(&w, "pty \"sstpc %s %s\"\nplugin sstp-pppd-plugin.so\nsstp-sock /var/run/sstpc/sstpc-%s\n", flags, p.Server, pppRemote(ifc.Name))
	case config.IfL2TP:
		// xl2tpd starts pppd; it redials by itself.
	}
	if ifc.Type != config.IfPPTP {
		// No compression or encryption inside IPsec/TLS (CCP is only for MPPE).
		w.WriteString("noccp\n")
	}
	fmt.Fprintf(&w, "name %s\nremotename %s\nifname %s\n", quote(p.Username), pppRemote(ifc.Name), ifc.Name)
	w.WriteString(pppCommon)
	if ifc.Type != config.IfL2TP {
		w.WriteString("persist\nmaxfail 0\nholdoff 10\n")
	}
	mtu := ifc.MTU
	if mtu == 0 {
		mtu = pppClientMTU
	}
	fmt.Fprintf(&w, "mtu %d\nmru %d\n", mtu, mtu)
	if ifc.Disabled {
		// Also makes enabling it again change the file, which restarts the unit.
		w.WriteString("# interface disabled: unit is stopped\n")
	}
	return w.String()
}

// renderIPsec writes the strongSwan (swanctl) connections: one per L2TP
// client with a secret, the L2TP server's when it has one, and the
// site-to-site tunnels (ipsec.go).
func renderIPsec(c *config.Config, b Bundle) {
	var conns, secrets strings.Builder
	const ike = "aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024"
	const esp = "aes256-sha1,aes128-sha1,aes256-sha256,aes128-sha256,3des-sha1"
	clientPSKs := map[string]bool{}
	for _, ifc := range c.Interfaces {
		if ifc.Type == config.IfL2TP && ifc.PPP != nil && ifc.PPP.IPsecSecret != "" && !ifc.Disabled {
			clientPSKs[ifc.PPP.IPsecSecret] = true
		}
	}
	srv := c.PPPServer
	serverPSK := ""
	if srv.L2TPOn() {
		serverPSK = srv.L2TP.IPsecSecret
	}
	n := 0
	for _, ifc := range c.Interfaces {
		if ifc.Type != config.IfL2TP || ifc.PPP == nil || ifc.PPP.IPsecSecret == "" || ifc.Disabled {
			continue
		}
		n++
		name := pppRemote(ifc.Name)
		// One shared secret is the usual case and works with any peer ID.
		// Several different ones are told apart by the server's address,
		// which then must also be the connection's remote ID: otherwise
		// the lookup falls back to the server's "any peer" secret.
		shared := len(clientPSKs) == 1 && serverPSK == ""
		remoteID := ""
		if _, err := netip.ParseAddr(ifc.PPP.Server); err == nil && !shared {
			remoteID = "\n\t\t\tid = " + ifc.PPP.Server
		}
		fmt.Fprintf(&conns, `	%s {
		version = 1
		remote_addrs = %s
		proposals = %s
		dpd_delay = 30s
		local {
			auth = psk
		}
		remote {
			auth = psk%s
		}
		children {
			%s {
				mode = transport
				local_ts = dynamic[17/%d]
				remote_ts = dynamic[17/1701]
				esp_proposals = %s
				start_action = trap
				dpd_action = restart
				close_action = restart
			}
		}
	}
`, name, ifc.PPP.Server, ike, remoteID, name, c.L2TPClientPort(), esp)
		if shared {
			if n == 1 {
				fmt.Fprintf(&secrets, "\tike-%s {\n\t\tsecret = %s\n\t}\n", name, quote(ifc.PPP.IPsecSecret))
			}
		} else {
			fmt.Fprintf(&secrets, "\tike-%s {\n\t\tid = %s\n\t\tsecret = %s\n\t}\n", name, ifc.PPP.Server, quote(ifc.PPP.IPsecSecret))
		}
	}
	if serverPSK != "" {
		n++
		fmt.Fprintf(&conns, `	mr-l2tp-server {
		version = 1
		proposals = %s,default
		encap = no
		dpd_delay = 30s
		local {
			auth = psk
		}
		remote {
			auth = psk
		}
		children {
			mr-l2tp-server {
				mode = transport
				local_ts = dynamic[17/1701]
				remote_ts = dynamic[17]
				esp_proposals = %s,default
			}
		}
	}
`, ike, esp)
		fmt.Fprintf(&secrets, "\tike-mr-l2tp-server {\n\t\tsecret = %s\n\t}\n", quote(serverPSK))
	}
	n += ipsecSiteToSite(c, &conns, &secrets)
	var pools strings.Builder
	n += ikev2Server(c, &conns, &pools, &secrets, b)
	if n == 0 {
		return
	}
	renderStrongswanConf(b)
	body := "# " + Header + "\nconnections {\n" + conns.String() + "}\n\n"
	if pools.Len() > 0 {
		body += "pools {\n" + pools.String() + "}\n\n"
	}
	b.add(SwanctlConf, CompIPsec, 0o600, body+"secrets {\n"+secrets.String()+"}\n")
}

// renderPPPServer writes the accel-ppp config for the PPTP/L2TP/SSTP server.
func renderPPPServer(c *config.Config, b Bundle) {
	s := c.PPPServer
	if s == nil {
		return
	}
	gw, err := netip.ParsePrefix(s.Address)
	if err != nil {
		return
	}
	mtu := s.MTU
	if mtu == 0 {
		mtu = pppClientMTU
	}
	var w strings.Builder
	fmt.Fprintf(&w, "# %s\n[modules]\nlog_syslog\n", Header)
	if s.PPTPOn() {
		w.WriteString("pptp\n")
	}
	if s.L2TPOn() {
		w.WriteString("l2tp\n")
	}
	if s.SSTPOn() {
		w.WriteString("sstp\n")
	}
	w.WriteString("auth_mschap_v2\nauth_mschap_v1\nauth_chap_md5\nchap-secrets\nippool\n")
	w.WriteString("\n[core]\nthread-count=2\n\n[common]\nsingle-session=replace\n")
	fmt.Fprintf(&w, "\n[ppp]\nverbose=1\nmin-mtu=1280\nmtu=%d\nmru=%d\nipv4=require\nipv6=deny\nmppe=prefer\nlcp-echo-interval=20\nlcp-echo-failure=3\nunit-cache=1\n", mtu, mtu)
	w.WriteString("\n[auth]\nany-login=0\nnoauth=0\n")
	// Clients dial from anywhere on the internet.
	w.WriteString("\n[client-ip-range]\ndisable\n")
	ifname := config.PPPServerIf + "%d"
	if s.PPTPOn() {
		fmt.Fprintf(&w, "\n[pptp]\nverbose=1\nifname=%s\nmppe=require\n", ifname)
	}
	if s.L2TPOn() {
		fmt.Fprintf(&w, "\n[l2tp]\nverbose=1\nifname=%s\nhost-name=%s\nppp-max-mtu=%d\n", ifname, c.System.Hostname, mtu)
	}
	if s.SSTPOn() {
		_, listen := s.SSTP.Ports()
		fmt.Fprintf(&w, "\n[sstp]\nverbose=1\nifname=%s\nport=%d\naccept=ssl\nssl-pemfile=%s\nssl-keyfile=%s\nssl-protocol=tls1.2,tls1.3\n", ifname, listen, AccelCert, AccelKey)
		if s.SSTP.Domain != "" {
			fmt.Fprintf(&w, "host-name=%s\n", s.SSTP.Domain)
		}
		b.add(AccelCert, CompPPPServer, 0o644, strings.TrimSpace(s.SSTP.CertPEM)+"\n")
		b.add(AccelKey, CompPPPServer, 0o600, strings.TrimSpace(s.SSTP.KeyPEM)+"\n")
	}
	dns := s.ClientDNS
	if len(dns) == 0 {
		dns = strings.Split(defaultClientNS, ",")
	}
	w.WriteString("\n[dns]\n")
	for i, d := range dns {
		if i < 2 {
			fmt.Fprintf(&w, "dns%d=%s\n", i+1, d)
		}
	}
	fmt.Fprintf(&w, "\n[ip-pool]\ngw-ip-address=%s\n", gw.Addr())
	reserved := map[netip.Addr]bool{gw.Addr(): true}
	for _, u := range s.Users {
		if a, err := netip.ParseAddr(u.IP); err == nil {
			reserved[a] = true
		}
	}
	for _, r := range poolRanges(gw, reserved) {
		w.WriteString(r + "\n")
	}
	fmt.Fprintf(&w, "\n[chap-secrets]\ngw-ip-address=%s\nchap-secrets=%s\n", gw.Addr(), AccelSecrets)
	w.WriteString("\n[log]\nsyslog=accel-pppd,daemon\nlevel=3\n")
	fmt.Fprintf(&w, "\n[cli]\ntcp=%s\n", AccelCLI)
	b.add(AccelConf, CompPPPServer, 0o600, w.String())

	var sec strings.Builder
	sec.WriteString("# " + Header + "\n# client\tserver\tsecret\tIP\n")
	for _, u := range s.Users {
		if u.Disabled {
			continue
		}
		ip := "*"
		if u.IP != "" {
			ip = u.IP
		}
		fmt.Fprintf(&sec, "%s\t*\t%s\t%s\n", quote(u.Name), quote(u.Password), ip)
	}
	b.add(AccelSecrets, CompPPPServer, 0o600, sec.String())
}

// poolRanges lists the client addresses of the subnet as accel-ppp
// ranges (a.b.c.x-y), leaving out the network, broadcast and reserved
// addresses.
func poolRanges(gw netip.Prefix, reserved map[netip.Addr]bool) []string {
	pfx := gw.Masked()
	first := pfx.Addr().Next()
	var last netip.Addr
	for a := first; pfx.Contains(a); a = a.Next() {
		last = a
	}
	// last is the broadcast address
	var out []string
	var start, prev netip.Addr
	flush := func() {
		if !start.IsValid() {
			return
		}
		s4, p4 := start.As4(), prev.As4()
		_ = s4
		out = append(out, fmt.Sprintf("%s-%d", start, p4[3]))
		start = netip.Addr{}
	}
	for a := first; a.Less(last); a = a.Next() {
		a4 := a.As4()
		if reserved[a] || (start.IsValid() && a4[2] != start.As4()[2]) {
			flush()
		}
		if reserved[a] {
			continue
		}
		if !start.IsValid() {
			start = a
		}
		prev = a
	}
	flush()
	return out
}

// L2TP tunnel netdev name (the session is the interface itself).
func l2tpTunnelName(id uint32) string { return fmt.Sprintf("l2tpt%d", id) }

func renderL2TPv3(ifc *config.Interface, b Bundle) {
	l := ifc.L2TPv3
	var w ini
	w.section("NetDev")
	w.kv("Name", l2tpTunnelName(l.TunnelID))
	w.kv("Kind", "l2tp")
	w.section("L2TP")
	w.kv("TunnelId", l.TunnelID)
	w.kv("PeerTunnelId", l.PeerTunnelID)
	w.kv("Remote", l.Remote)
	if l.Local != "" {
		w.kv("Local", l.Local)
	} else {
		w.kv("Local", "auto")
	}
	if port := l.UDPPort(); port != 0 {
		w.kv("EncapsulationType", "udp")
		w.kv("UDPSourcePort", port)
		w.kv("UDPDestinationPort", port)
	} else {
		w.kv("EncapsulationType", "ip")
	}
	w.section("L2TPSession")
	w.kv("Name", ifc.Name)
	w.kv("SessionId", l.SessionID)
	w.kv("PeerSessionId", l.PeerSessionID)
	w.kv("Layer2SpecificHeader", "default")
	b.add(netdevPath(ifc.Name), CompNetwork, 0o644, w.String())
}
