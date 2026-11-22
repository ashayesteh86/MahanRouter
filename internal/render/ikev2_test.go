package render

import (
	"strings"
	"testing"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/config"
	"github.com/ashayesteh86/MahanRouter/internal/pki"
)

func ikev2Config(t *testing.T) *config.Config {
	t.Helper()
	c := loadExample(t, "factory-default.yaml")
	ca, cert, key, err := pki.ServerCertWithCA("vpn.example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c.PPPServer = &config.PPPServer{Address: "10.80.0.1/24",
		IKEv2: &config.PPPServerIKEv2{Enabled: true, Domain: "vpn.example.com", CertPEM: cert, KeyPEM: key, CAPEM: ca},
		Users: []config.PPPUser{{Name: "sara", Password: "pass one"}, {Name: "off", Password: "x12345678", Disabled: true}}}
	return c
}

func TestIKEv2Server(t *testing.T) {
	c := ikev2Config(t)
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	b, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	s := b[SwanctlConf].Content
	for _, want := range []string{
		"mr-ikev2 {\n\t\tversion = 2", "auth = eap-mschapv2", "certs = mr-ikev2.pem", "id = vpn.example.com",
		"local_ts = 0.0.0.0/0", "if_id_in = 82", "if_id_out = 82",
		"pools {\n\tmr-ikev2 {\n\t\taddrs = 10.82.0.2-10.82.0.254\n\t\tdns = 1.1.1.1,8.8.8.8",
		"id = \"sara\"\n\t\tsecret = \"pass one\"",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("swanctl config lacks %q", want)
		}
	}
	if strings.Contains(s, `"off"`) {
		t.Error("a disabled user must have no secret")
	}
	if f, ok := b[IKEv2Key]; !ok || f.Mode != 0o600 {
		t.Error("server key missing or readable")
	}
	if _, ok := b[IKEv2Cert]; !ok {
		t.Error("server certificate missing")
	}
	if f, ok := b[StrongswanConf]; !ok || !strings.Contains(f.Content, "dhcp {\n\t\t\tload = no") {
		t.Error("unused plugins are not switched off")
	}
	nd := b[netdevPath(config.IKEv2ServerIf)].Content
	if !strings.Contains(nd, "Kind=xfrm") || !strings.Contains(nd, "InterfaceId=82") {
		t.Errorf("netdev: %s", nd)
	}
	if nw := b[networkPath(config.IKEv2ServerIf)].Content; !strings.Contains(nw, "Address=10.82.0.1/24") || !strings.Contains(nw, "MTUBytes=1400") {
		t.Errorf("network: %s", nw)
	}
	nft := b[NftablesFile].Content
	for _, want := range []string{
		`udp dport { 500, 4500 } counter accept comment "ikev2 server"`,
		`iifname "ppps-ike" tcp flags syn tcp option maxseg size set 1360`,
		`iifname "ppps*" counter drop comment "ppp server: internet only"`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("nftables lacks %q", want)
		}
	}

	// split tunnel with LAN access offers the pool and the LAN only
	c.PPPServer.IKEv2.SplitTunnel, c.PPPServer.AllowLAN = true, true
	b, _ = Render(c)
	if s := b[SwanctlConf].Content; !strings.Contains(s, "local_ts = 10.82.0.0/24,192.168.88.0/24") {
		t.Errorf("split tunnel selectors: %s", s[strings.Index(s, "local_ts"):][:60])
	}

	// off: nothing is left
	c.PPPServer.IKEv2.Enabled = false
	c.PPPServer.PPTP = &config.PPPServerPPTP{Enabled: true}
	b, _ = Render(c)
	for _, p := range []string{SwanctlConf, IKEv2Key, IKEv2Cert, netdevPath(config.IKEv2ServerIf), StrongswanConf} {
		if _, ok := b[p]; ok {
			t.Errorf("%s rendered with the server off", p)
		}
	}
}

func TestIKEv2Validation(t *testing.T) {
	bad := map[string]func(c *config.Config){
		"wrong name":     func(c *config.Config) { c.PPPServer.IKEv2.Domain = "other.example.com" },
		"no name":        func(c *config.Config) { c.PPPServer.IKEv2.Domain = "" },
		"bad key":        func(c *config.Config) { c.PPPServer.IKEv2.KeyPEM = "x" },
		"bad ca":         func(c *config.Config) { c.PPPServer.IKEv2.CAPEM = "x" },
		"ppp overlap":    func(c *config.Config) { c.PPPServer.IKEv2.Address = "10.80.0.200/24" },
		"network addr":   func(c *config.Config) { c.PPPServer.IKEv2.Address = "10.82.0.0/24" },
		"quote password": func(c *config.Config) { c.PPPServer.Users[0].Password = `a"b` },
	}
	for name, f := range bad {
		c := ikev2Config(t)
		f(c)
		if err := config.Validate(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
