package render

import (
	"encoding/json"
	"path"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// EoIPDir holds one mahan-eoip config per EoIP / EoIPv6 interface.
const EoIPDir = "/etc/mahan-router/eoip"

// EoIPConfPath is an EoIP interface's mahan-eoip config.
func EoIPConfPath(n string) string { return path.Join(EoIPDir, n+".json") }

// EoIPUnit runs mahan-eoip for one interface.
func EoIPUnit(n string) string { return "mahan-eoip@" + n + ".service" }

// netdevKind maps the kernel tunnel types to networkd's Kind=.
var netdevKind = map[string]string{
	config.IfGRE:  "gre",
	config.IfIPIP: "ipip",
	config.If6to4: "sit",
	config.IfGRE6: "ip6gre",
}

// renderIPTunnel writes a GRE / IPIP / 6to4 / GRE6 netdev, or the
// mahan-eoip config of an EoIP / EoIPv6 interface.
func renderIPTunnel(ifc *config.Interface, b Bundle) {
	t := ifc.Tunnel
	if config.IsEoIP(ifc.Type) {
		conf := struct {
			Name      string `json:"name"`
			IPv6      bool   `json:"ipv6"`
			Local     string `json:"local,omitempty"`
			Remote    string `json:"remote"`
			TunnelID  int    `json:"tunnel_id"`
			TTL       int    `json:"ttl,omitempty"`
			Keepalive int    `json:"keepalive"`
			MAC       string `json:"mac,omitempty"`
			// Disabled only changes the file, so that enabling the
			// interface again restarts its (stopped) unit.
			Disabled bool `json:"disabled,omitempty"`
		}{ifc.Name, ifc.Type == config.IfEoIPv6, t.Local, t.Remote, t.TunnelID, t.TTL, t.KeepaliveSec(), t.MAC, ifc.Disabled}
		j, _ := json.MarshalIndent(conf, "", "  ")
		b.add(EoIPConfPath(ifc.Name), CompVPN, 0o644, string(j)+"\n")
		// mahan-eoip sets the TAP's MAC; without this udev's default
		// MACAddressPolicy=persistent may replace it, with one that is the
		// same on routers cloned from one image.
		var l ini
		l.section("Match")
		l.kv("OriginalName", ifc.Name)
		l.kv("Driver", "tun")
		l.section("Link")
		l.kv("MACAddressPolicy", "none")
		b.add(linkPath(ifc.Name), CompNetwork, 0o644, l.String())
		return
	}
	var w ini
	w.section("NetDev")
	w.kv("Name", ifc.Name)
	w.kv("Kind", netdevKind[ifc.Type])
	w.section("Tunnel")
	// Not bound to an underlying link: the route to Remote decides.
	w.kv("Independent", "yes")
	w.kv("Local", orAny(t.Local))
	w.kv("Remote", orAny(t.Remote))
	if t.TTL > 0 {
		w.kv("TTL", t.TTL)
	}
	if t.Key != 0 {
		w.kv("Key", t.Key)
	}
	b.add(netdevPath(ifc.Name), CompNetwork, 0o644, w.String())
}

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}
