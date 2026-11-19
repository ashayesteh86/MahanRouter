package render

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"path"
	"strings"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// Rozaneh paths and units.
const (
	RozanehDir      = "/etc/mahan-router/rozaneh"
	RozanehStateDir = "/var/lib/mahan-router/rozaneh"
)

// RozanehConfPath is the JSON config of a Rozaneh interface.
func RozanehConfPath(n string) string { return path.Join(RozanehDir, n+".json") }

// RozanehUnit is the systemd instance running a Rozaneh interface.
func RozanehUnit(ifc *config.Interface) string {
	if ifc.Type == config.IfRozanehServer {
		return RozanehServerUnit(ifc.Name)
	}
	return RozanehClientUnit(ifc.Name)
}

// RozanehClientUnit and RozanehServerUnit name the template instances.
func RozanehClientUnit(n string) string { return "mahan-rozaneh-client@" + n + ".service" }
func RozanehServerUnit(n string) string { return "mahan-rozaneh-server@" + n + ".service" }

// rozanehClientKeys are the client.json fields this rozaneh build knows;
// its loader rejects unknown ones, and links from newer servers may add some.
var rozanehClientKeys = []string{"server", "sni", "path", "private_key", "server_public_key", "mtu", "cover_traffic", "method", "dns"}

type rozanehPeer struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	IP        string `json:"ip"`
}

type rozanehServerConf struct {
	Listen          string        `json:"listen"`
	CertFile        string        `json:"cert_file,omitempty"`
	KeyFile         string        `json:"key_file,omitempty"`
	ACMEDomain      string        `json:"acme_domain,omitempty"`
	ACMEEmail       string        `json:"acme_email,omitempty"`
	ACMECacheDir    string        `json:"acme_cache_dir,omitempty"`
	FallbackURL     string        `json:"fallback_url"`
	Path            string        `json:"path"`
	PrivateKey      string        `json:"private_key"`
	TunName         string        `json:"tun_name"`
	TunAddress      string        `json:"tun_address"`
	MTU             int           `json:"mtu,omitempty"`
	DNS             []string      `json:"dns"`
	Cover           bool          `json:"cover_traffic"`
	Peers           []rozanehPeer `json:"peers"`
	PeersFromConfig bool          `json:"peers_from_config"`
	StateFile       string        `json:"state_file"`
}

func renderRozaneh(c *config.Config, b Bundle) error {
	for i := range c.Interfaces {
		ifc := &c.Interfaces[i]
		if ifc.Disabled {
			continue
		}
		switch ifc.Type {
		case config.IfRozaneh:
			m, err := config.DecodeRozanehLink(ifc.Rozaneh.Link)
			if err != nil {
				return fmt.Errorf("%s: %w", ifc.Name, err)
			}
			out := map[string]any{}
			for _, k := range rozanehClientKeys {
				if v, ok := m[k]; ok {
					out[k] = v
				}
			}
			out["tun_name"] = ifc.Name
			out["full_tunnel"] = false // the router routes by policy instead
			if ifc.Rozaneh.Method != "" {
				out["method"] = ifc.Rozaneh.Method
			}
			if ifc.MTU != 0 {
				out["mtu"] = ifc.MTU
			}
			data, _ := json.MarshalIndent(out, "", "  ")
			b.add(RozanehConfPath(ifc.Name), CompVPN, 0o600, string(data)+"\n")
		case config.IfRozanehServer:
			s := ifc.RozanehServer
			pub, listen := s.Ports()
			_ = pub
			gw := netip.MustParsePrefix(ifc.Addresses[0])
			conf := rozanehServerConf{
				Listen: fmt.Sprintf(":%d", listen), FallbackURL: "builtin", Path: s.Path, PrivateKey: s.PrivateKey,
				TunName: ifc.Name, TunAddress: gw.String(), MTU: ifc.MTU, DNS: s.ClientDNS,
				Cover: s.CoverTraffic == nil || *s.CoverTraffic, Peers: []rozanehPeer{}, PeersFromConfig: true,
				StateFile: path.Join(RozanehStateDir, ifc.Name, "state.json"),
			}
			if len(conf.DNS) == 0 {
				conf.DNS = []string{gw.Addr().String()}
			}
			if s.CoverURL != "" {
				conf.FallbackURL = s.CoverURL
			}
			if s.CertPEM != "" {
				conf.CertFile = path.Join(RozanehDir, ifc.Name+".crt")
				conf.KeyFile = path.Join(RozanehDir, ifc.Name+".key")
				b.add(conf.CertFile, CompVPN, 0o600, strings.TrimSpace(s.CertPEM)+"\n")
				b.add(conf.KeyFile, CompVPN, 0o600, strings.TrimSpace(s.KeyPEM)+"\n")
			} else {
				conf.ACMEDomain, conf.ACMEEmail = s.Domain, s.ACMEEmail
				conf.ACMECacheDir = path.Join(RozanehStateDir, ifc.Name, "acme")
			}
			for _, p := range s.Peers {
				if !p.Disabled {
					conf.Peers = append(conf.Peers, rozanehPeer{Name: p.Name, PublicKey: p.PublicKey, IP: p.IP})
				}
			}
			data, _ := json.MarshalIndent(conf, "", "  ")
			b.add(RozanehConfPath(ifc.Name), CompVPN, 0o600, string(data)+"\n")
		}
	}
	return nil
}

// ---- policy routing ----

//go:embed geoip/ir4.txt
var iranV4 string

// IranV4 returns the embedded Iranian IPv4 prefixes.
func IranV4() []string {
	var out []string
	for _, l := range strings.Split(iranV4, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// Destinations that never go through a policy tunnel.
var privateV4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"}

// PolicyTable and PolicyMark are the routing table and packet mark of
// policy route i.
func PolicyTable(i int) int { return 1000 + i }
func PolicyMark(i int) int  { return 0x10000 + i }

// PolicyDNSTable and PolicyDNSMark carry the router's own DNS through the
// tunnel. They have no kill switch: while the tunnel is down, DNS must still
// work so the tunnel program can resolve its server and reconnect.
func PolicyDNSTable(i int) int { return 2000 + i }
func PolicyDNSMark(i int) int  { return 0x20000 + i }

// activePolicies returns enabled policy routes with their index.
func activePolicies(c *config.Config) map[int]config.PolicyRoute {
	out := map[int]config.PolicyRoute{}
	for i, r := range c.PolicyRoutes {
		if !r.Disabled {
			out[i] = r
		}
	}
	return out
}

// policyRoutesFor returns the [Route] sections for a tunnel's .network.
func policyRoutesFor(c *config.Config, ifc string, w *ini) {
	for i, r := range c.PolicyRoutes {
		if r.Disabled || r.Interface != ifc {
			continue
		}
		for _, table := range []int{PolicyTable(i), PolicyDNSTable(i)} {
			w.section("Route")
			w.kv("Destination", "0.0.0.0/0")
			w.kv("Table", table)
			w.kv("Scope", "link")
		}
	}
}

// policyLo adds the rules and kill-switch routes, which must outlive the
// tunnel interface, to the loopback .network.
func policyLo(c *config.Config, w *ini) bool {
	any := false
	for i, r := range c.PolicyRoutes {
		if r.Disabled {
			continue
		}
		any = true
		mark := fmt.Sprintf("0x%x", PolicyMark(i))
		// Routes more specific than a default (LAN, static, site-to-site)
		// still win; only the default route is replaced.
		w.section("RoutingPolicyRule")
		w.kv("FirewallMark", mark)
		w.kv("Table", "main")
		w.kv("SuppressPrefixLength", 0)
		w.kv("Priority", 10000+2*i)
		w.section("RoutingPolicyRule")
		w.kv("FirewallMark", mark)
		w.kv("Table", PolicyTable(i))
		w.kv("Priority", 10001+2*i)
		if r.DNSViaTunnel {
			w.section("RoutingPolicyRule")
			w.kv("FirewallMark", fmt.Sprintf("0x%x", PolicyDNSMark(i)))
			w.kv("Table", PolicyDNSTable(i))
			w.kv("Priority", 10500+i)
		}
		if r.BlockIfDown {
			w.section("Route")
			w.kv("Destination", "0.0.0.0/0")
			w.kv("Table", PolicyTable(i))
			w.kv("Type", "unreachable")
			w.kv("Metric", 4096)
		}
	}
	return any
}

// nftPolicy renders the sets and mangle chains that mark policy traffic.
func nftPolicy(c *config.Config, w *strings.Builder) {
	pols := activePolicies(c)
	if len(pols) == 0 {
		return
	}
	iran := false
	for _, r := range pols {
		iran = iran || r.ExceptIran
	}
	fmt.Fprintf(w, "\tset pr_private_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n\n", strings.Join(privateV4, ", "))
	if iran {
		fmt.Fprintf(w, "\tset pr_iran_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { %s }\n\t}\n\n", strings.Join(IranV4(), ", "))
	}
	wan := c.InterfaceLists["WAN"]
	lan := c.InterfaceLists["LAN"]
	var pre, out []string
	for i := range c.PolicyRoutes {
		r, ok := pols[i]
		if !ok {
			continue
		}
		var m []string
		if r.From == config.PolicyFromLAN && len(lan) > 0 {
			m = append(m, "iifname "+nftSet(without(lan, r.Interface)))
		} else {
			m = append(m, "iifname != "+nftSet(append(append([]string{}, wan...), r.Interface, "lo")))
		}
		if r.From == config.PolicyFromDevices {
			m = append(m, "ip saddr { "+strings.Join(r.Devices, ", ")+" }")
		}
		m = append(m, "ct direction original", "meta mark 0", "ip daddr != @pr_private_v4")
		if r.ExceptIran {
			m = append(m, "ip daddr != @pr_iran_v4")
		}
		mark := fmt.Sprintf("meta mark set 0x%x", PolicyMark(i))
		pre = append(pre, strings.Join(m, " ")+" "+mark+" comment "+quote("policy "+r.Interface))
		if r.DNSViaTunnel {
			out = append(out, fmt.Sprintf("meta skuid %s meta mark 0 meta l4proto { tcp, udp } th dport 53 ip daddr != @pr_private_v4 meta mark set 0x%x comment %s",
				quote("unbound"), PolicyDNSMark(i), quote("dns via "+r.Interface)))
		}
	}
	w.WriteString("\tchain policy_pre {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	for _, l := range pre {
		fmt.Fprintf(w, "\t\t%s\n", l)
	}
	w.WriteString("\t}\n\n")
	if len(out) > 0 {
		w.WriteString("\tchain policy_out {\n\t\ttype route hook output priority mangle; policy accept;\n")
		for _, l := range out {
			fmt.Fprintf(w, "\t\t%s\n", l)
		}
		w.WriteString("\t}\n\n")
	}
}

func nftSet(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = quote(n)
	}
	return "{ " + strings.Join(q, ", ") + " }"
}

func without(list []string, x string) []string {
	var out []string
	for _, v := range list {
		if v != x {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		out = []string{"mahan-empty-list"}
	}
	return out
}
