package render

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

const (
	keyA = "YAnzuGRJDO29VCGfGRwn5BsWKwQWnF0wg4MPDxUXcV0="
	keyB = "8Ym2pCA2I31dsa1Wgu6/j3wZ2Qlvl+BXX3dQUmvyp1Q="
)

func rozanehLink(t *testing.T, extra map[string]any) string {
	m := map[string]any{"server": "vpn.example.com:443", "sni": "vpn.example.com", "path": "/secret-path",
		"private_key": keyA, "server_public_key": keyB, "full_tunnel": true, "cover_traffic": true}
	for k, v := range extra {
		m[k] = v
	}
	data, _ := json.Marshal(m)
	return "rozaneh://config/" + base64.RawURLEncoding.EncodeToString(data)
}

func vpnConfig(t *testing.T) *config.Config {
	c := loadExample(t, "factory-default.yaml")
	c.Interfaces = append(c.Interfaces,
		config.Interface{Name: "rz1", Type: config.IfRozaneh, Rozaneh: &config.RozanehClient{Link: rozanehLink(t, map[string]any{"split": map[string]any{"mode": "all"}, "future_field": 1})}},
		config.Interface{Name: "rzs0", Type: config.IfRozanehServer, Addressing: config.AddrStatic, Addresses: []string{"10.77.0.1/24"},
			RozanehServer: &config.RozanehServer{Domain: "home.example.com", Path: "/a-long-path", PrivateKey: keyB,
				Peers: []config.RozanehPeer{{Name: "phone", PublicKey: keyA, IP: "10.77.0.2"}, {Name: "off", PublicKey: keyB, IP: "10.77.0.3", Disabled: true}}}},
	)
	c.InterfaceLists["WAN"] = append(c.InterfaceLists["WAN"], "rz1")
	c.PolicyRoutes = []config.PolicyRoute{
		{Interface: "rz1", From: config.PolicyFromLAN, ExceptIran: true, DNSViaTunnel: true, BlockIfDown: true},
	}
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRozanehRender(t *testing.T) {
	b, err := Render(vpnConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	client := map[string]any{}
	if err := json.Unmarshal([]byte(b[RozanehConfPath("rz1")].Content), &client); err != nil {
		t.Fatal(err)
	}
	if client["tun_name"] != "rz1" || client["full_tunnel"] != false || client["split"] != nil || client["future_field"] != nil {
		t.Fatalf("client conf: %v", client)
	}
	srv := b[RozanehConfPath("rzs0")].Content
	for _, want := range []string{`"acme_domain": "home.example.com"`, `"listen": ":8443"`, `"fallback_url": "builtin"`, `"peers_from_config": true`, `"dns": [
    "10.77.0.1"`} {
		if !strings.Contains(srv, want) {
			t.Errorf("server conf lacks %s:\n%s", want, srv)
		}
	}
	if strings.Contains(srv, `"off"`) {
		t.Error("disabled peer rendered")
	}
	lo := b[networkPath("lo-routes")].Content
	for _, want := range []string{"FirewallMark=0x10000", "SuppressPrefixLength=0", "Table=1000", "Type=unreachable"} {
		if !strings.Contains(lo, want) {
			t.Errorf("lo network lacks %s:\n%s", want, lo)
		}
	}
	rz := b[networkPath("rz1")].Content
	if !strings.Contains(rz, "Table=1000") || !strings.Contains(rz, "KeepConfiguration=yes") || strings.Contains(rz, "Address=") {
		t.Errorf("rz1 network:\n%s", rz)
	}
	if strings.Contains(b[networkPath("rzs0")].Content, "Address=") {
		t.Error("networkd must not own the rozaneh server address")
	}
	nft := b[NftablesFile].Content
	for _, want := range []string{"set pr_iran_v4", "chain policy_pre", "ip daddr != @pr_iran_v4 meta mark set 0x10000", `meta skuid "unbound"`, "type route hook output"} {
		if !strings.Contains(nft, want) {
			t.Errorf("nft lacks %q", want)
		}
	}
	checkTool(t, "nft", "-c", "-f", writeTemp(t, nft))
}

func TestRozanehValidation(t *testing.T) {
	c := vpnConfig(t)
	c.Interfaces[len(c.Interfaces)-1].RozanehServer.Peers[0].IP = "10.78.0.2"
	c.Interfaces[len(c.Interfaces)-2].Rozaneh.Link = "rozaneh://config/!!"
	c.PolicyRoutes = append(c.PolicyRoutes, config.PolicyRoute{Interface: "rz1", From: "devices"})
	err := config.Validate(c)
	if err == nil {
		t.Fatal("expected problems")
	}
	for _, want := range []string{"not a client address", "rozaneh.link", "already has a policy route", "at least one device"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestIranList(t *testing.T) {
	l := IranV4()
	if len(l) < 1000 {
		t.Fatalf("only %d prefixes", len(l))
	}
}
