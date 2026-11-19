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

func TestV2RayRender(t *testing.T) {
	c := vpnConfig(t)
	pbk := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	c.Interfaces = append(c.Interfaces, config.Interface{Name: "v2r1", Type: config.IfV2Ray, V2Ray: &config.V2RayClient{
		Link: "vless://bf000d23-0752-40b4-affe-68f7707a9661@203.0.113.5:443?security=reality&sni=www.microsoft.com&pbk=" + pbk + "&sid=ab&flow=xtls-rprx-vision"}})
	c.InterfaceLists["WAN"] = append(c.InterfaceLists["WAN"], "v2r1")
	c.PolicyRoutes = append(c.PolicyRoutes, config.PolicyRoute{Interface: "v2r1", From: config.PolicyFromDevices, Devices: []string{"192.168.88.20"}, DNSViaTunnel: true})
	c.V2RayServer = &config.V2RayServer{PublicPort: 2053, RealityPrivateKey: pbk, RealityShortID: "0123abcd", Users: []config.V2RayUser{
		{Name: "phone", Secret: "bf000d23-0752-40b4-affe-68f7707a9661"}, {Name: "old", Secret: "bf000d23-0752-40b4-affe-68f7707a9662", Disabled: true}}}
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	b, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	cl := b[V2RayConfPath("v2r1")].Content
	for _, w := range []string{`"interface_name": "v2r1"`, `"auto_route": false`, `"final": "proxy"`, `"default_domain_resolver": "bootstrap"`, `"172.19.1.1/30"`} {
		if !strings.Contains(cl, w) {
			t.Errorf("client conf lacks %s:\n%s", w, cl)
		}
	}
	sv := b[V2RayServerConf].Content
	for _, w := range []string{`"listen_port": 8444`, `"server": "www.microsoft.com"`, `"server_port": 443`, `"ip_is_private": true`, `"flow": "xtls-rprx-vision"`} {
		if !strings.Contains(sv, w) {
			t.Errorf("server conf lacks %s:\n%s", w, sv)
		}
	}
	if strings.Contains(sv, `"old"`) {
		t.Error("disabled user rendered")
	}
	lo := b[networkPath("lo-routes")].Content
	if !strings.Contains(lo, "FirewallMark=0x20001") || !strings.Contains(lo, "Table=2001") {
		t.Errorf("dns table rule missing:\n%s", lo)
	}
	if !strings.Contains(b[networkPath("v2r1")].Content, "Table=2001") {
		t.Error("tunnel lacks dns table route")
	}
	nft := b[NftablesFile].Content
	if !strings.Contains(nft, "meta mark set 0x20001") || !strings.Contains(nft, "ip saddr { 192.168.88.20 }") {
		t.Error("nft policy for v2r1 missing")
	}
	checkTool(t, "nft", "-c", "-f", writeTemp(t, nft))

	c.V2RayServer.PublicPort = 0
	c.Interfaces[len(c.Interfaces)-2].RozanehServer.PublicPort = 0 // both on 443
	if err := config.Validate(c); err == nil || !strings.Contains(err.Error(), "already used by the Rozaneh server") {
		t.Errorf("port clash not caught: %v", err)
	}
}
