package render

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// File name prefixes keep link/netdev/network files ordered and let the
// applier recognise files it owns (everything starting with "mr-").
func linkPath(n string) string    { return path.Join(NetworkDir, "10-mr-"+n+".link") }
func netdevPath(n string) string  { return path.Join(NetworkDir, "20-mr-"+n+".netdev") }
func networkPath(n string) string { return path.Join(NetworkDir, "30-mr-"+n+".network") }

// WGKeyPath is where a WireGuard private key is written (readable by networkd only).
func WGKeyPath(n string) string { return path.Join(SecretsDir, n+".key") }

// WGPSKPath is where a WireGuard peer preshared key is written.
func WGPSKPath(n string, i int) string {
	return path.Join(SecretsDir, fmt.Sprintf("%s-peer%d.psk", n, i))
}

type ini struct{ b strings.Builder }

func (w *ini) section(name string) { fmt.Fprintf(&w.b, "\n[%s]\n", name) }
func (w *ini) kv(k string, v any)  { fmt.Fprintf(&w.b, "%s=%v\n", k, v) }
func (w *ini) String() string      { return "# " + Header + "\n" + w.b.String() }

func renderNetwork(c *config.Config, b Bundle) error {
	// Children attach to their parent's .network file.
	vlans := map[string][]string{}
	master := map[string]*config.Interface{}
	for i := range c.Interfaces {
		ifc := &c.Interfaces[i]
		if ifc.Type == config.IfVLAN {
			vlans[ifc.Parent] = append(vlans[ifc.Parent], ifc.Name)
		}
		for _, m := range ifc.Members {
			master[m] = ifc
		}
	}
	pppParents := map[string]bool{}
	for _, ifc := range c.Interfaces {
		if ifc.Type == config.IfPPPoE {
			pppParents[ifc.Parent] = true
		}
	}
	routes := map[string][]config.StaticRoute{}
	var blackholes []config.StaticRoute
	for _, r := range c.Routes {
		if r.Disabled {
			continue
		}
		if r.Blackhole {
			blackholes = append(blackholes, r)
			continue
		}
		dev := c.RouteInterface(r)
		if dev == "" {
			return fmt.Errorf("route %s: cannot find the interface for gateway %s", r.Destination, r.Gateway)
		}
		routes[dev] = append(routes[dev], r)
	}

	for _, ifc := range c.Interfaces {
		// .link: rename the physical port to its configured name.
		if ifc.Type == config.IfEthernet {
			var w ini
			w.section("Match")
			if ifc.MAC != "" {
				w.kv("PermanentMACAddress", strings.ToLower(ifc.MAC))
			} else {
				w.kv("OriginalName", ifc.MatchDevice)
			}
			w.section("Link")
			w.kv("Name", ifc.Name)
			w.kv("NamePolicy", "")
			if ifc.MTU != 0 {
				w.kv("MTUBytes", ifc.MTU)
			}
			b.add(linkPath(ifc.Name), CompNetwork, 0o644, w.String())
		}

		// .netdev: virtual interfaces.
		if err := renderNetdev(c, &ifc, b); err != nil {
			return err
		}

		// .network: L2 membership and L3 addressing.
		var w ini
		w.section("Match")
		w.kv("Name", ifc.Name)
		w.section("Link")
		w.kv("RequiredForOnline", "no")
		if ifc.MTU != 0 && ifc.Type != config.IfEthernet {
			w.kv("MTUBytes", ifc.MTU)
		}
		if ifc.Disabled {
			w.kv("ActivationPolicy", "always-down")
		}
		w.section("Network")
		if ifc.Comment != "" {
			w.kv("Description", ifc.Comment)
		}
		if ifc.Type == config.IfPPPoE || ifc.Type == config.IfRozaneh || ifc.Type == config.IfRozanehServer || config.IsSingBoxClient(ifc.Type) || ifc.Type == config.IfOpenVPN || config.IsPPPClient(ifc.Type) {
			// pppd / rozaneh own the addresses; networkd only shapes and
			// routes, and keeps its hands off.
			w.kv("KeepConfiguration", "yes")
			w.kv("LinkLocalAddressing", "no")
			w.kv("IPv6AcceptRA", "no")
			if ifc.Type != config.IfPPPoE && !config.IsPPPClient(ifc.Type) {
				w.kv("ConfigureWithoutCarrier", "yes")
			}
		} else {
			if m := master[ifc.Name]; m != nil {
				if m.Type == config.IfBridge {
					w.kv("Bridge", m.Name)
				} else {
					w.kv("Bond", m.Name)
				}
			}
			for _, v := range vlans[ifc.Name] {
				w.kv("VLAN", v)
			}
			switch ifc.Addressing {
			case config.AddrDHCP:
				w.kv("DHCP", "ipv4")
				w.kv("IPv6AcceptRA", "yes")
			default:
				w.kv("DHCP", "no")
				w.kv("IPv6AcceptRA", "no")
				if len(ifc.Addresses) == 0 {
					w.kv("LinkLocalAddressing", "no")
				}
			}
			if master[ifc.Name] != nil || pppParents[ifc.Name] {
				w.kv("LinkLocalAddressing", "no")
			}
			w.kv("ConfigureWithoutCarrier", "yes")
			for _, a := range ifc.Addresses {
				w.kv("Address", a)
			}
			if ifc.Addressing == config.AddrDHCP {
				w.section("DHCPv4")
				if ifc.DHCPUseDNS != nil {
					w.kv("UseDNS", yesNo(*ifc.DHCPUseDNS))
				}
				if ifc.DHCPRouteDist > 0 {
					w.kv("RouteMetric", ifc.DHCPRouteDist)
				}
			}
		}
		for _, r := range routes[ifc.Name] {
			w.section("Route")
			w.kv("Destination", r.Destination)
			if r.Gateway != "" {
				w.kv("Gateway", r.Gateway)
			} else {
				w.kv("Scope", "link")
			}
			if r.Distance > 0 {
				w.kv("Metric", r.Distance)
			}
		}
		policyRoutesFor(c, ifc.Name, &w)
		if ifc.Shaping != nil {
			w.section("CAKE")
			w.kv("Bandwidth", ifc.Shaping.Bandwidth)
		}
		b.add(networkPath(ifc.Name), CompNetwork, 0o644, w.String())
	}

	var lo ini
	lo.section("Match")
	lo.kv("Name", "lo")
	lo.section("Link")
	lo.kv("RequiredForOnline", "no")
	if policyLo(c, &lo) || len(blackholes) > 0 {
		w := &lo
		for _, r := range blackholes {
			w.section("Route")
			w.kv("Destination", r.Destination)
			w.kv("Type", "blackhole")
			if r.Distance > 0 {
				w.kv("Metric", r.Distance)
			}
		}
		b.add(networkPath("lo-routes"), CompNetwork, 0o644, w.String())
	}
	return nil
}

// bridgeMAC returns the MAC of the bridge's first Ethernet member, like
// RouterOS auto-mac. Without it the kernel/networkd picks a MAC that no
// NIC owns, and virtual switches that only deliver frames to the vNIC's
// own MAC (VMware vSwitch, Hyper-V, most clouds) drop all LAN traffic
// addressed to the router.
func bridgeMAC(c *config.Config, br *config.Interface) string {
	for _, m := range br.Members {
		if mi := c.Interface(m); mi != nil && mi.Type == config.IfEthernet && mi.MAC != "" {
			return strings.ToLower(mi.MAC)
		}
	}
	return ""
}

func renderNetdev(c *config.Config, ifc *config.Interface, b Bundle) error {
	if ifc.Type == config.IfL2TPv3 {
		if ifc.L2TPv3 != nil {
			renderL2TPv3(ifc, b)
		}
		return nil
	}
	if config.IsIPTunnel(ifc.Type) {
		if ifc.Tunnel != nil {
			renderIPTunnel(ifc, b)
		}
		return nil
	}
	var w ini
	w.section("NetDev")
	w.kv("Name", ifc.Name)
	switch ifc.Type {
	case config.IfVLAN:
		w.kv("Kind", "vlan")
		w.section("VLAN")
		w.kv("Id", ifc.VLANID)
	case config.IfBridge:
		w.kv("Kind", "bridge")
		if mac := bridgeMAC(c, ifc); mac != "" {
			w.kv("MACAddress", mac)
		}
		w.section("Bridge")
		w.kv("STP", yesNo(ifc.STP))
	case config.IfBond:
		w.kv("Kind", "bond")
		w.section("Bond")
		mode := ifc.BondMode
		if mode == "" {
			mode = "802.3ad"
		}
		w.kv("Mode", mode)
		if mode == "802.3ad" {
			w.kv("LACPTransmitRate", "fast")
			w.kv("TransmitHashPolicy", "layer3+4")
		}
		w.kv("MIIMonitorSec", "100ms")
	case config.IfLoopback:
		w.kv("Kind", "dummy")
	case config.IfWireGuard:
		wg := ifc.WireGuard
		w.kv("Kind", "wireguard")
		w.section("WireGuard")
		w.kv("PrivateKeyFile", WGKeyPath(ifc.Name))
		b.add(WGKeyPath(ifc.Name), CompNetwork, 0o640, wg.PrivateKey+"\n")
		if wg.ListenPort > 0 {
			w.kv("ListenPort", wg.ListenPort)
		}
		for i, p := range wg.Peers {
			w.section("WireGuardPeer")
			if p.Comment != "" {
				fmt.Fprintf(&w.b, "# %s\n", strings.ReplaceAll(p.Comment, "\n", " "))
			}
			w.kv("PublicKey", p.PublicKey)
			if p.PresharedKey != "" {
				w.kv("PresharedKeyFile", WGPSKPath(ifc.Name, i))
				b.add(WGPSKPath(ifc.Name, i), CompNetwork, 0o640, p.PresharedKey+"\n")
			}
			ips := append([]string(nil), p.AllowedIPs...)
			sort.Strings(ips)
			w.kv("AllowedIPs", strings.Join(ips, ","))
			if p.Endpoint != "" {
				w.kv("Endpoint", p.Endpoint)
			}
			if p.PersistentKeepalive > 0 {
				w.kv("PersistentKeepalive", p.PersistentKeepalive)
			}
			if p.RouteAllowedIPs {
				w.kv("RouteTable", "main")
			}
		}
	default:
		return nil // ethernet and ppp interfaces have no netdev
	}
	b.add(netdevPath(ifc.Name), CompNetwork, 0o644, w.String())
	return nil
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// PPPoEUnit is the systemd template instance running pppd for an interface.
func PPPoEUnit(name string) string { return "mahan-pppoe@" + name + ".service" }
