package render

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// ---- Kea DHCPv4 ----

type keaOption struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

type keaReservation struct {
	HWAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address"`
	Hostname  string `json:"hostname,omitempty"`
}

type keaPool struct {
	Pool string `json:"pool"`
}

type keaSubnet struct {
	ID     int    `json:"id"`
	Subnet string `json:"subnet"`
	// No "interface" key: Kea rejects names that do not exist yet, and a
	// commit may create the VLAN and its DHCP server together. Kea picks
	// the subnet from the receiving interface's address instead.
	Pools        []keaPool        `json:"pools"`
	Options      []keaOption      `json:"option-data,omitempty"`
	Reservations []keaReservation `json:"reservations,omitempty"`
	Valid        int              `json:"valid-lifetime,omitempty"`
}

// renderKea always writes the file (with zero subnets when DHCP is off) so
// the service can be stopped cleanly and a later enable starts from a
// known config.
func renderKea(c *config.Config, b Bundle) error {
	var ifaces []string
	var subnets []keaSubnet
	for i, d := range c.DHCPServers {
		if d.Disabled {
			continue
		}
		ifc := c.Interface(d.Interface)
		subnet, err := config.InterfaceSubnet4(ifc)
		if err != nil {
			return err
		}
		self, _ := config.InterfaceAddr4(ifc)
		s := keaSubnet{ID: i + 1, Subnet: subnet.String()}
		for _, p := range d.Pools {
			a, z, _ := strings.Cut(p, "-")
			s.Pools = append(s.Pools, keaPool{Pool: a + " - " + z})
		}
		gw := d.Gateway
		if gw == "" {
			gw = self.String()
		}
		s.Options = append(s.Options, keaOption{Name: "routers", Data: gw})
		dns := d.DNSServers
		if len(dns) == 0 && c.DNS.Enabled && contains(c.DNS.ListenOn, d.Interface) {
			dns = []string{self.String()}
		}
		if len(dns) == 0 {
			dns = c.DNS.Forwarders
		}
		if len(dns) > 0 {
			s.Options = append(s.Options, keaOption{Name: "domain-name-servers", Data: strings.Join(dns, ", ")})
		}
		if d.Domain != "" {
			s.Options = append(s.Options, keaOption{Name: "domain-name", Data: d.Domain})
		}
		if d.LeaseTime != "" {
			dur, _ := time.ParseDuration(d.LeaseTime)
			s.Valid = int(dur.Seconds())
		}
		for _, l := range d.StaticLeases {
			s.Reservations = append(s.Reservations, keaReservation{HWAddress: strings.ToLower(l.MAC), IPAddress: l.Address, Hostname: l.Hostname})
		}
		ifaces = append(ifaces, d.Interface)
		subnets = append(subnets, s)
	}
	if ifaces == nil {
		ifaces = []string{}
	}
	if subnets == nil {
		subnets = []keaSubnet{}
	}
	doc := map[string]any{
		"Dhcp4": map[string]any{
			"interfaces-config": map[string]any{"interfaces": ifaces, "service-sockets-require-all": false, "service-sockets-max-retries": 30, "service-sockets-retry-wait-time": 2000},
			"control-socket":    map[string]any{"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"},
			"lease-database":    map[string]any{"type": "memfile", "persist": true, "name": "/var/lib/kea/kea-leases4.csv", "lfc-interval": 3600},
			"valid-lifetime":    43200,
			"renew-timer":       21600,
			"rebind-timer":      37800,
			"subnet4":           subnets,
			"loggers": []any{map[string]any{
				"name": "kea-dhcp4", "severity": "INFO",
				"output_options": []any{map[string]any{"output": "syslog"}},
			}},
		},
	}
	js, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	b.add(KeaFile, CompDHCP, 0o644, "// "+Header+"\n"+string(js)+"\n")
	return nil
}

var keaIfacesRe = regexp.MustCompile(`"interfaces": \[[^\]]*\]`)

// KeaCheckVariant returns the Kea config with interfaces set to "*" so
// kea-dhcp4 -t can check it before the interfaces it names are created.
func KeaCheckVariant(content string) string {
	return keaIfacesRe.ReplaceAllString(content, `"interfaces": ["*"]`)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- Unbound ----

func renderUnbound(c *config.Config, b Bundle) {
	d := c.DNS
	var w strings.Builder
	fmt.Fprintf(&w, "# %s\nserver:\n", Header)
	if !d.Enabled {
		w.WriteString("    # DNS service disabled\n    interface: 127.0.0.1\n")
		b.add(UnboundFile, CompDNS, 0o644, w.String())
		return
	}
	w.WriteString("    interface: 127.0.0.1\n    access-control: 127.0.0.0/8 allow\n")
	allow := map[string]bool{}
	for _, name := range d.ListenOn {
		ifc := c.Interface(name)
		for _, a := range ifc.Addresses {
			pf, err := netip.ParsePrefix(a)
			if err != nil {
				continue
			}
			fmt.Fprintf(&w, "    interface: %s\n", pf.Addr())
			allow[pf.Masked().String()] = true
		}
	}
	for _, a := range d.AllowFrom {
		allow[a] = true
	}
	for _, a := range sortedKeys(allow) {
		fmt.Fprintf(&w, "    access-control: %s allow\n", a)
	}
	w.WriteString("    ip-freebind: yes\n    hide-identity: yes\n    hide-version: yes\n    prefetch: yes\n    qname-minimisation: yes\n")
	if d.CacheSizeMB > 0 {
		fmt.Fprintf(&w, "    msg-cache-size: %dm\n    rrset-cache-size: %dm\n", d.CacheSizeMB, d.CacheSizeMB*2)
	}
	hosts := sortedKeys(d.StaticHosts)
	for _, h := range hosts {
		ip := d.StaticHosts[h]
		rr := "A"
		if strings.Contains(ip, ":") {
			rr = "AAAA"
		}
		fqdn := strings.TrimSuffix(h, ".") + "."
		fmt.Fprintf(&w, "    local-data: \"%s %s %s\"\n", fqdn, rr, ip)
	}
	if len(d.Forwarders) > 0 {
		w.WriteString("\nforward-zone:\n    name: \".\"\n")
		for _, f := range d.Forwarders {
			fmt.Fprintf(&w, "    forward-addr: %s\n", f)
		}
	}
	b.add(UnboundFile, CompDNS, 0o644, w.String())
}

// ---- chrony ----

func renderChrony(c *config.Config, b Bundle) {
	var src strings.Builder
	src.WriteString("# " + Header + "\n")
	for _, s := range c.NTP.Servers {
		kw := "server"
		if strings.Contains(s, "pool") {
			kw = "pool"
		}
		fmt.Fprintf(&src, "%s %s iburst\n", kw, s)
	}
	b.add(ChronySrc, CompNTP, 0o644, src.String())
	var conf strings.Builder
	conf.WriteString("# " + Header + "\n")
	for _, a := range c.NTP.ServeTo {
		fmt.Fprintf(&conf, "allow %s\n", a)
	}
	b.add(ChronyConf, CompNTP, 0o644, conf.String())
}

// ---- FRRouting ----

// RoutingEnabled reports whether FRR needs to run.
func RoutingEnabled(c *config.Config) bool { return c.Routing.OSPF != nil || c.Routing.BGP != nil }

// Our static routes live in the kernel (installed by networkd), so for FRR
// "static" means its "kernel" source.
func frrSource(s string) string {
	if s == "static" {
		return "kernel"
	}
	return s
}

func renderFRR(c *config.Config, b Bundle) {
	rt := c.Routing
	daemon := func(on bool) string { return yesNo(on) }
	b.add(FRRDaemons, CompRouting, 0o640, fmt.Sprintf(`# %s
bgpd=%s
ospfd=%s
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=%s
fabricd=no
vrrpd=no
pathd=no
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1"
ospfd_options="  -A 127.0.0.1"
bfdd_options="   -A 127.0.0.1"
staticd_options="-A 127.0.0.1"
`, Header, daemon(rt.BGP != nil), daemon(rt.OSPF != nil), daemon(rt.BGP != nil)))

	var w strings.Builder
	fmt.Fprintf(&w, "! %s\nfrr defaults traditional\nhostname %s\nlog syslog informational\nservice integrated-vtysh-config\n!\n", Header, c.System.Hostname)
	if o := rt.OSPF; o != nil {
		w.WriteString("router ospf\n")
		if rt.RouterID != "" {
			fmt.Fprintf(&w, " ospf router-id %s\n", rt.RouterID)
		}
		for _, a := range o.Areas {
			nets := append([]string(nil), a.Networks...)
			sort.Strings(nets)
			for _, n := range nets {
				fmt.Fprintf(&w, " network %s area %s\n", n, a.ID)
			}
		}
		for _, p := range o.Passive {
			fmt.Fprintf(&w, " passive-interface %s\n", p)
		}
		for _, r := range o.Redistribute {
			fmt.Fprintf(&w, " redistribute %s\n", frrSource(r))
		}
		w.WriteString("exit\n!\n")
	}
	if g := rt.BGP; g != nil {
		fmt.Fprintf(&w, "router bgp %d\n", g.ASN)
		if rt.RouterID != "" {
			fmt.Fprintf(&w, " bgp router-id %s\n", rt.RouterID)
		}
		// Without this FRR 8+ refuses to exchange eBGP routes until route
		// maps exist; policy editing comes in a later phase.
		w.WriteString(" no bgp ebgp-requires-policy\n no bgp default ipv4-unicast\n")
		for _, n := range g.Neighbors {
			fmt.Fprintf(&w, " neighbor %s remote-as %d\n", n.Address, n.RemoteAS)
			if n.Description != "" {
				fmt.Fprintf(&w, " neighbor %s description %s\n", n.Address, strings.ReplaceAll(n.Description, "\n", " "))
			}
			if n.Password != "" {
				fmt.Fprintf(&w, " neighbor %s password %s\n", n.Address, n.Password)
			}
			if n.Multihop > 0 {
				fmt.Fprintf(&w, " neighbor %s ebgp-multihop %d\n", n.Address, n.Multihop)
			}
			if n.Disabled {
				fmt.Fprintf(&w, " neighbor %s shutdown\n", n.Address)
			}
		}
		for _, af := range []string{"ipv4", "ipv6"} {
			var lines []string
			for _, n := range g.Neighbors {
				if strings.Contains(n.Address, ":") == (af == "ipv6") {
					lines = append(lines, fmt.Sprintf("  neighbor %s activate", n.Address))
				}
			}
			for _, n := range g.Networks {
				if strings.Contains(n, ":") == (af == "ipv6") {
					lines = append(lines, "  network "+n)
				}
			}
			if len(lines) == 0 {
				continue
			}
			for _, r := range g.Redistribute {
				lines = append(lines, "  redistribute "+frrSource(r))
			}
			fmt.Fprintf(&w, " !\n address-family %s unicast\n%s\n exit-address-family\n", af, strings.Join(lines, "\n"))
		}
		w.WriteString("exit\n!\n")
	}
	b.add(FRRConf, CompRouting, 0o640, w.String())
}
