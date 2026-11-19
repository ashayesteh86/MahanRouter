package render

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/config"
	"github.com/ashayesteh86/MahanRouter/internal/pki"
)

// testCert is made once; a self-signed RSA key takes a moment.
var testCert, testKey = func() (string, string) {
	c, k, err := pki.SelfSignedCert("vpn.example.com", time.Hour)
	if err != nil {
		panic(err)
	}
	return c, k
}()

func pppConfig(t *testing.T) *config.Config {
	c := loadExample(t, "factory-default.yaml")
	c.Interfaces = append(c.Interfaces,
		config.Interface{Name: "pptp-out1", Type: config.IfPPTP, PPP: &config.PPPClient{Server: "203.0.113.5", Username: "ali", Password: "p@ss word"}},
		config.Interface{Name: "sstp-out1", Type: config.IfSSTP, PPP: &config.PPPClient{Server: "vpn.example.com:4443", Username: "sara", Password: "x"}},
		config.Interface{Name: "l2tp-out1", Type: config.IfL2TP, PPP: &config.PPPClient{Server: "198.51.100.7", Username: "reza", Password: "y", IPsecSecret: "shared key"}},
		config.Interface{Name: "eoip1", Type: config.IfL2TPv3, L2TPv3: &config.L2TPv3{Remote: "198.51.100.9", Port: 1710, TunnelID: 10, PeerTunnelID: 20, SessionID: 30, PeerSessionID: 40}},
	)
	c.InterfaceLists["WAN"] = append(c.InterfaceLists["WAN"], "pptp-out1", "sstp-out1", "l2tp-out1")
	c.PolicyRoutes = []config.PolicyRoute{{Interface: "sstp-out1", From: config.PolicyFromLAN, ExceptIran: true}}
	c.PPPServer = &config.PPPServer{
		Address: "10.80.0.1/24",
		PPTP:    &config.PPPServerPPTP{Enabled: true},
		L2TP:    &config.PPPServerL2TP{Enabled: true, IPsecSecret: "server key"},
		SSTP:    &config.PPPServerSSTP{Enabled: true, Domain: "vpn.example.com", CertPEM: testCert, KeyPEM: testKey},
		Users:   []config.PPPUser{{Name: "phone", Password: "s3cret"}, {Name: "office", Password: "z", IP: "10.80.0.50"}, {Name: "old", Password: "q", Disabled: true}},
	}
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPPPRender(t *testing.T) {
	c := pppConfig(t)
	b, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		PPPPeerFile("pptp-out1"):     {`pty "pptp 203.0.113.5 --nolaunchpppd`, "require-mppe-128", "remotename mr-pptp-out1", "ifname pptp-out1", "nodefaultroute", "persist"},
		PPPPeerFile("sstp-out1"):     {`pty "sstpc --ipparam mr-sstp-out1 --nolaunchpppd --save-server-route --tls-ext --cert-warn vpn.example.com:4443"`, "plugin sstp-pppd-plugin.so", "sstp-sock /var/run/sstpc/sstpc-mr-sstp-out1"},
		L2TPOptionsFile("l2tp-out1"): {"ifname l2tp-out1", `name "reza"`},
		XL2TPDConf:                   {"port = 1702", "[lac l2tp-out1]", "lns = 198.51.100.7", "pppoptfile = /etc/ppp/mr-l2tp-out1.l2tp"},
		"/etc/ppp/chap-secrets":      {"\"ali\"\tmr-pptp-out1\t\"p@ss word\"\t*"},
		SwanctlConf:                  {"remote_addrs = 198.51.100.7", "local_ts = dynamic[17/1702]", "id = 198.51.100.7", "auth = psk\n\t\t\tid = 198.51.100.7", `secret = "shared key"`, "mr-l2tp-server", `secret = "server key"`},
		AccelConf:                    {"[pptp]", "[l2tp]", "[sstp]", "ifname=ppps%d", "port=8445", "gw-ip-address=10.80.0.1", "10.80.0.2-49", "10.80.0.51-254", "dns1=1.1.1.1"},
		AccelSecrets:                 {"\"phone\"\t*\t\"s3cret\"\t*", "\"office\"\t*\t\"z\"\t10.80.0.50"},
		netdevPath("eoip1"):          {"Kind=l2tp", "Name=l2tpt10", "TunnelId=10", "PeerTunnelId=20", "UDPSourcePort=1710", "Name=eoip1", "SessionId=30"},
		networkPath("sstp-out1"):     {"KeepConfiguration=yes", "Table=1000"},
		NftablesFile:                 {`iifname "ppps*" counter drop`, `iifname "ppps*" oifname != {`},
	}
	for p, subs := range want {
		f, ok := b[p]
		if !ok {
			t.Errorf("%s not rendered", p)
			continue
		}
		for _, s := range subs {
			if !strings.Contains(f.Content, s) {
				t.Errorf("%s: missing %q in\n%s", p, s, f.Content)
			}
		}
	}
	if strings.Contains(b[AccelSecrets].Content, "old") {
		t.Error("disabled user rendered")
	}
	if strings.Contains(b[PPPPeerFile("pptp-out1")].Content, "defaultroute\n") && !strings.Contains(b[PPPPeerFile("pptp-out1")].Content, "nodefaultroute") {
		t.Error("client takes the default route")
	}

	// LAN access: no built-in drop, and ppps in a list becomes a wildcard.
	c.PPPServer.AllowLAN = true
	c.InterfaceLists["LAN"] = append(c.InterfaceLists["LAN"], config.PPPServerIf)
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	nft, err := Nftables(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(nft, "internet only") || !strings.Contains(nft, `"ppps*"`) {
		t.Errorf("allow_lan nft:\n%s", nft)
	}
}

func TestPPPDisabledChangesFile(t *testing.T) {
	c := pppConfig(t)
	on, _ := Render(c)
	c.Interfaces[len(c.Interfaces)-3].Disabled = true // sstp-out1
	off, _ := Render(c)
	if on[PPPPeerFile("sstp-out1")].Content == off[PPPPeerFile("sstp-out1")].Content {
		t.Error("disabling must change the peer file, or enabling again would not restart the unit")
	}
}

func TestPPPValidate(t *testing.T) {
	bad := []func(c *config.Config){
		func(c *config.Config) { c.Interfaces[len(c.Interfaces)-4].PPP.Password = `a"b` },
		func(c *config.Config) { c.Interfaces[len(c.Interfaces)-4].PPP.Server = "bad host!" },
		func(c *config.Config) { c.Interfaces[len(c.Interfaces)-4].PPP.IPsecSecret = "x" },
		func(c *config.Config) { c.Interfaces[len(c.Interfaces)-1].L2TPv3.Port = 1701 },
		func(c *config.Config) { c.PPPServer.Address = "10.80.0.0/24" },
		func(c *config.Config) { c.PPPServer.Users[1].IP = "10.99.0.5" },
		func(c *config.Config) { c.PPPServer.SSTP.KeyPEM = "nope" },
		func(c *config.Config) {
			c.PPPServer.Users = append(c.PPPServer.Users, config.PPPUser{Name: "phone", Password: "x"})
		},
		func(c *config.Config) {
			c.Interfaces = append(c.Interfaces, config.Interface{Name: "ppps1", Type: config.IfLoopback})
		},
	}
	for i, f := range bad {
		c := pppConfig(t)
		f(c)
		if err := config.Validate(c); err == nil {
			t.Errorf("case %d: expected a validation error", i)
		}
	}
}

func TestPoolRanges(t *testing.T) {
	got := poolRangesFor(t, "10.0.0.1/29", "10.0.0.3")
	if strings.Join(got, " ") != "10.0.0.2-2 10.0.0.4-6" {
		t.Errorf("got %v", got)
	}
	got = poolRangesFor(t, "10.1.0.1/23")
	if strings.Join(got, " ") != "10.1.0.2-255 10.1.1.0-254" {
		t.Errorf("got %v", got)
	}
}

func poolRangesFor(t *testing.T, gw string, reserved ...string) []string {
	t.Helper()
	p := netip.MustParsePrefix(gw)
	r := map[netip.Addr]bool{p.Addr(): true}
	for _, a := range reserved {
		r[netip.MustParseAddr(a)] = true
	}
	return poolRanges(p, r)
}
