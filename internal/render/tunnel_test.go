package render

import (
	"strings"
	"testing"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

func tunnelConfig(t *testing.T) *config.Config {
	c := loadExample(t, "factory-default.yaml")
	off := 0
	c.Interfaces = append(c.Interfaces,
		config.Interface{Name: "gre1", Type: config.IfGRE, Addressing: config.AddrStatic, Addresses: []string{"172.31.0.1/30"},
			Tunnel: &config.Tunnel{Local: "198.51.100.1", Remote: "203.0.113.9", Key: 42, TTL: 64}},
		config.Interface{Name: "ipip1", Type: config.IfIPIP, Addressing: config.AddrStatic, Addresses: []string{"172.31.1.1/30"},
			Tunnel: &config.Tunnel{Remote: "203.0.113.10"}},
		config.Interface{Name: "sit1", Type: config.If6to4, Addressing: config.AddrStatic, Addresses: []string{"2001:db8:1::1/64"},
			Tunnel: &config.Tunnel{Remote: "203.0.113.11"}},
		config.Interface{Name: "gre6a", Type: config.IfGRE6, Tunnel: &config.Tunnel{Local: "2001:db8::1", Remote: "2001:db8::9"}},
		config.Interface{Name: "eoip-br", Type: config.IfEoIP, Tunnel: &config.Tunnel{Remote: "203.0.113.12", TunnelID: 1234}},
		config.Interface{Name: "eoip6", Type: config.IfEoIPv6, Addressing: config.AddrStatic, Addresses: []string{"10.77.0.1/24"},
			Tunnel: &config.Tunnel{Remote: "2001:db8::12", TunnelID: 4095, Keepalive: &off, MAC: "02:00:00:00:00:01"}},
	)
	// EoIP carries Ethernet: it can join the LAN bridge.
	for i := range c.Interfaces {
		if c.Interfaces[i].Type == config.IfBridge {
			c.Interfaces[i].Members = append(c.Interfaces[i].Members, "eoip-br")
		}
	}
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTunnelRender(t *testing.T) {
	c := tunnelConfig(t)
	b, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		netdevPath("gre1"):      {"Kind=gre", "Independent=yes", "Local=198.51.100.1", "Remote=203.0.113.9", "Key=42", "TTL=64"},
		netdevPath("ipip1"):     {"Kind=ipip", "Local=any", "Remote=203.0.113.10"},
		netdevPath("sit1"):      {"Kind=sit", "Remote=203.0.113.11"},
		netdevPath("gre6a"):     {"Kind=ip6gre", "Remote=2001:db8::9"},
		EoIPConfPath("eoip-br"): {`"remote": "203.0.113.12"`, `"tunnel_id": 1234`, `"keepalive": 10`, `"ipv6": false`},
		EoIPConfPath("eoip6"):   {`"ipv6": true`, `"tunnel_id": 4095`, `"keepalive": 0`, `"mac": "02:00:00:00:00:01"`},
		networkPath("eoip-br"):  {"Bridge="},
		networkPath("eoip6"):    {"Address=10.77.0.1/24"},
		networkPath("gre1"):     {"Address=172.31.0.1/30"},
		NftablesFile: {
			`ip saddr 203.0.113.9 meta l4proto 47 counter accept`,
			`ip saddr 203.0.113.10 meta l4proto 4 counter accept`,
			`ip saddr 203.0.113.11 meta l4proto 41 counter accept`,
			`ip6 saddr 2001:db8::9 meta l4proto 47 counter accept`,
			`ip6 saddr 2001:db8::12 meta l4proto 97 counter accept`,
		},
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
	if _, ok := b[netdevPath("eoip-br")]; ok {
		t.Error("eoip must not get a netdev (mahan-eoip creates it)")
	}
	// The tunnel accepts come before the user's "drop invalid".
	nft := b[NftablesFile].Content
	if i, j := strings.Index(nft, "203.0.113.12 meta l4proto 47"), strings.Index(nft, "drop invalid"); i < 0 || j < 0 || i > j {
		t.Errorf("eoip accept must precede drop invalid:\n%s", nft)
	}

	// Disabling changes the EoIP file (so enabling restarts the unit)
	// and drops its firewall accept.
	on := b[EoIPConfPath("eoip-br")].Content
	c.Interface("eoip-br").Disabled = true
	b2, _ := Render(c)
	if b2[EoIPConfPath("eoip-br")].Content == on {
		t.Error("disabling must change the eoip file")
	}
	if strings.Contains(b2[NftablesFile].Content, "203.0.113.12") {
		t.Error("disabled tunnel still accepted")
	}
}

func TestTunnelValidate(t *testing.T) {
	bad := []func(c *config.Config){
		func(c *config.Config) { c.Interface("gre1").Tunnel.Remote = "" },
		func(c *config.Config) { c.Interface("gre1").Tunnel.Remote = "2001:db8::1" },
		func(c *config.Config) { c.Interface("gre6a").Tunnel.Remote = "203.0.113.1" },
		func(c *config.Config) { c.Interface("gre6a").Tunnel.Local = "" },
		func(c *config.Config) { c.Interface("eoip6").Tunnel.TunnelID = 4096 },
		func(c *config.Config) { c.Interface("eoip-br").Tunnel.TunnelID = 70000 },
		func(c *config.Config) { c.Interface("ipip1").Tunnel.Key = 5 },
		func(c *config.Config) { c.Interface("gre1").Tunnel.TunnelID = 5 },
		func(c *config.Config) { c.Interface("eoip6").Tunnel.MAC = "01:00:5e:00:00:01" },
		func(c *config.Config) { k := 1; c.Interface("gre1").Tunnel.Keepalive = &k },
		func(c *config.Config) {
			c.Interface("gre1").Addressing = config.AddrDHCP
			c.Interface("gre1").Addresses = nil
		},
		func(c *config.Config) { c.Interface("gre1").Tunnel = nil },
		// same endpoints twice
		func(c *config.Config) {
			c.Interfaces = append(c.Interfaces, config.Interface{Name: "eoip-dup", Type: config.IfEoIP, Tunnel: &config.Tunnel{Remote: "203.0.113.12", TunnelID: 1234}})
		},
		// a layer-3 tunnel cannot be a bridge member
		func(c *config.Config) {
			for i := range c.Interfaces {
				if c.Interfaces[i].Type == config.IfBridge {
					c.Interfaces[i].Members = append(c.Interfaces[i].Members, "gre1")
				}
			}
		},
	}
	for i, f := range bad {
		c := tunnelConfig(t)
		f(c)
		if err := config.Validate(c); err == nil {
			t.Errorf("case %d: expected a validation error", i)
		}
	}
	// 6to4 may leave the remote empty (relay), and then accepts from any.
	c := tunnelConfig(t)
	c.Interface("sit1").Tunnel.Remote = ""
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	b, _ := Render(c)
	if !strings.Contains(b[netdevPath("sit1")].Content, "Remote=any") || !strings.Contains(b[NftablesFile].Content, "meta nfproto ipv4 meta l4proto 41") {
		t.Error("6to4 relay")
	}
	// A GRE tunnel with another key to the same remote is fine.
	c = tunnelConfig(t)
	c.Interfaces = append(c.Interfaces, config.Interface{Name: "gre2", Type: config.IfGRE, Tunnel: &config.Tunnel{Local: "198.51.100.1", Remote: "203.0.113.9", Key: 43}})
	if err := config.Validate(c); err != nil {
		t.Error(err)
	}
}
