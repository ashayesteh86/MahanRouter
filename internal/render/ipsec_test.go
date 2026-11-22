package render

import (
	"strings"
	"testing"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

func TestIPsecSiteToSite(t *testing.T) {
	c := loadExample(t, "factory-default.yaml")
	c.IPsec = &config.IPsec{Tunnels: []config.IPsecTunnel{
		{Name: "hq", Remote: "203.0.113.10", PSK: "a long shared key", PFS: "modp1024", AllowRouter: true,
			LocalSubnets: []string{"192.168.88.0/24"}, RemoteSubnets: []string{"10.10.0.0/16", "10.20.0.0/24"}},
		{Name: "branch", IKEVersion: 1, PSK: "another key 123", RemoteID: "branch.example.com", LocalID: "hq.example.com",
			LocalSubnets: []string{"192.168.88.0/24"}, RemoteSubnets: []string{"10.30.0.0/24"}},
		{Name: "off", Disabled: true, Remote: "203.0.113.99", PSK: "unused key 1",
			LocalSubnets: []string{"192.168.88.0/24"}, RemoteSubnets: []string{"10.99.0.0/24"}},
	}}
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	b, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := b[SwanctlConf]
	if !ok {
		t.Fatal("no swanctl config")
	}
	s := f.Content
	for _, want := range []string{
		"mr-s2s-hq {\n\t\tversion = 2\n\t\tremote_addrs = 203.0.113.10\n",
		"mr-s2s-hq-1 {", "mr-s2s-hq-2 {", "remote_ts = 10.20.0.0/24",
		"esp_proposals = aes256-sha256-modp1024,",
		"start_action = trap|start",
		"mr-s2s-branch {\n\t\tversion = 1\n",
		"id = hq.example.com", "id = branch.example.com",
		"ike-mr-s2s-hq {\n\t\tid-1 = 203.0.113.10\n\t\tsecret = \"a long shared key\"",
		"dpd_action = clear",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("swanctl config lacks %q", want)
		}
	}
	if strings.Contains(s, "mr-s2s-off") || strings.Contains(s, "10.99.0.0") {
		t.Error("a disabled tunnel must not be rendered")
	}
	// the passive tunnel has no remote address and does not start
	br := s[strings.Index(s, "mr-s2s-branch {"):]
	br = br[:strings.Index(br, "\n\t}\n")]
	if strings.Contains(br, "remote_addrs") || strings.Contains(br, "start_action") {
		t.Errorf("passive tunnel: %s", br)
	}

	nft := b[NftablesFile].Content
	for _, want := range []string{
		`ip saddr 203.0.113.10 udp dport { 500, 4500 } counter accept comment "ipsec hq: IKE"`,
		`ip saddr 203.0.113.10 meta l4proto 50 counter accept`,
		`udp dport { 500, 4500 } counter accept comment "ipsec branch: IKE"`,
		`meta ipsec exists ip saddr { 10.10.0.0/16, 10.20.0.0/24 } counter accept comment "ipsec hq: remote site to router"`,
		`meta ipsec exists ip saddr { 10.10.0.0/16, 10.20.0.0/24 } ip daddr 192.168.88.0/24 counter accept`,
		`ip saddr 192.168.88.0/24 ip daddr 10.30.0.0/24 rt ipsec exists counter accept`,
		`ip saddr 192.168.88.0/24 ip daddr 10.30.0.0/24 counter accept comment "ipsec branch: no NAT"`,
		`tcp option maxseg size set rt mtu`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("nftables lacks %q", want)
		}
	}
	if strings.Contains(nft, `ipsec branch: remote site to router`) {
		t.Error("allow_router is off for branch")
	}
	// no NAT must come before the masquerade rule
	src := nft[strings.Index(nft, "chain srcnat"):]
	if strings.Index(src, "no NAT") > strings.Index(src, "masquerade") {
		t.Error("the no-NAT rule must come before masquerade")
	}
}

func TestIPsecValidation(t *testing.T) {
	base := func() *config.Config {
		c := loadExample(t, "factory-default.yaml")
		c.IPsec = &config.IPsec{Tunnels: []config.IPsecTunnel{{Name: "hq", Remote: "203.0.113.10", PSK: "a long shared key",
			LocalSubnets: []string{"192.168.88.0/24"}, RemoteSubnets: []string{"10.10.0.0/16"}}}}
		return c
	}
	if err := config.Validate(base()); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(t *config.IPsecTunnel){
		"short psk":      func(t *config.IPsecTunnel) { t.PSK = "short" },
		"quote in psk":   func(t *config.IPsecTunnel) { t.PSK = `bad"key12345` },
		"overlap":        func(t *config.IPsecTunnel) { t.RemoteSubnets = []string{"192.168.0.0/16"} },
		"host bits":      func(t *config.IPsecTunnel) { t.RemoteSubnets = []string{"10.10.0.1/16"} },
		"default route":  func(t *config.IPsecTunnel) { t.RemoteSubnets = []string{"0.0.0.0/0"} },
		"no subnets":     func(t *config.IPsecTunnel) { t.LocalSubnets = nil },
		"mixed families": func(t *config.IPsecTunnel) { t.RemoteSubnets = []string{"2001:db8:1::/64"} },
		"name":           func(t *config.IPsecTunnel) { t.Name = "Bad Name" },
		"dns without id": func(t *config.IPsecTunnel) { t.Remote = "vpn.example.com" },
		"bad pfs":        func(t *config.IPsecTunnel) { t.PFS = "group2" },
		"bad proposal":   func(t *config.IPsecTunnel) { t.ESPProposals = "aes256 sha1; rm" },
		"aggressive v2":  func(t *config.IPsecTunnel) { t.Aggressive = true },
		"ike version":    func(t *config.IPsecTunnel) { t.IKEVersion = 3 },
		"bad id":         func(t *config.IPsecTunnel) { t.LocalID = "a b" },
		"bad local":      func(t *config.IPsecTunnel) { t.Local = "wan" },
	}
	for name, f := range bad {
		c := base()
		f(&c.IPsec.Tunnels[0])
		if err := config.Validate(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := base()
	c.IPsec.Tunnels = append(c.IPsec.Tunnels, c.IPsec.Tunnels[0])
	c.IPsec.Tunnels[1].Name = "hq2"
	if err := config.Validate(c); err == nil {
		t.Error("two tunnels to one peer accepted")
	}
}
