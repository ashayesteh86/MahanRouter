package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ValidationError collects every problem found, so the user sees all of
// them at once instead of fixing one per commit attempt.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid config:\n  - " + strings.Join(e.Problems, "\n  - ")
}

type validator struct {
	c    *Config
	errs []string
}

func (v *validator) add(format string, a ...any) { v.errs = append(v.errs, fmt.Sprintf(format, a...)) }

var (
	ifNameRe   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
	listNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,48}$`)
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	bwRe       = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?[kKmMgG]?$`)
	portRe     = regexp.MustCompile(`^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$`)
)

var bondModes = map[string]bool{"balance-rr": true, "active-backup": true, "balance-xor": true,
	"broadcast": true, "802.3ad": true, "balance-tlb": true, "balance-alb": true}

var connStates = map[string]bool{"established": true, "related": true, "new": true, "invalid": true, "untracked": true}

var protocols = map[string]bool{"tcp": true, "udp": true, "icmp": true, "icmpv6": true, "gre": true,
	"esp": true, "ah": true, "sctp": true, "ospf": true}

// Validate checks the config for structural and semantic errors.
func Validate(c *Config) error {
	v := &validator{c: c}
	v.system()
	names := v.interfaces()
	if c.PPPServer != nil {
		// PPP server sessions (ppps0, ppps1, ...) as one pseudo interface.
		names[PPPServerIf] = &Interface{Name: PPPServerIf, Type: "ppp_server"}
	}
	v.interfaceLists(names)
	v.routes(names)
	v.routing()
	v.firewall(names)
	v.dhcp(names)
	v.dns(names)
	v.ntp()
	v.policyRoutes(names)
	v.v2rayServer()
	v.pppChecks()
	v.tunnelChecks()
	v.ipsec()
	servers := 0
	for _, ifc := range c.Interfaces {
		if ifc.Type == IfRozanehServer {
			servers++
		}
	}
	if servers > 1 {
		v.add("interfaces: only one rozaneh_server is supported")
	}
	if len(v.errs) > 0 {
		return &ValidationError{Problems: v.errs}
	}
	return nil
}

// isTunnel reports interface types created by a userspace VPN program.
func isTunnel(t string) bool {
	return t == IfRozaneh || t == IfRozanehServer || IsSingBoxClient(t) || IsPPPClient(t) || t == IfOpenVPN || isL3IPTunnel(t)
}

// isL3IPTunnel: GRE, IPIP, 6to4 and GRE6 carry IP, not Ethernet (EoIP
// does, so it can be a bridge member or carry VLANs).
func isL3IPTunnel(t string) bool { return IsIPTunnel(t) && !IsEoIP(t) }

func (v *validator) system() {
	if v.c.Version != SchemaVersion {
		v.add("version: must be %d (got %d)", SchemaVersion, v.c.Version)
	}
	if !hostnameRe.MatchString(v.c.System.Hostname) {
		v.add("system.hostname: %q is not a valid hostname", v.c.System.Hostname)
	}
	if tz := v.c.System.Timezone; tz != "" {
		if _, err := time.LoadLocation(tz); err != nil {
			v.add("system.timezone: unknown zone %q", tz)
		}
	}
}

func (v *validator) interfaces() map[string]*Interface {
	names := map[string]*Interface{}
	macs := map[string]string{}
	for i := range v.c.Interfaces {
		ifc := &v.c.Interfaces[i]
		p := fmt.Sprintf("interfaces[%s]", ifc.Name)
		if !ifNameRe.MatchString(ifc.Name) {
			v.add("interfaces[%d]: name %q must be 1-15 chars of letters, digits, _ . -", i, ifc.Name)
			continue
		}
		if _, dup := names[ifc.Name]; dup {
			v.add("%s: duplicate interface name", p)
		}
		names[ifc.Name] = ifc
		if ifc.MTU != 0 && (ifc.MTU < 576 || ifc.MTU > 9216) {
			v.add("%s: mtu %d out of range 576-9216", p, ifc.MTU)
		}
		switch ifc.Type {
		case IfEthernet:
			if ifc.MAC == "" && ifc.MatchDevice == "" {
				v.add("%s: ethernet needs mac or match_device", p)
			}
			if ifc.MAC != "" {
				hw, err := net.ParseMAC(ifc.MAC)
				if err != nil {
					v.add("%s: bad mac %q", p, ifc.MAC)
				} else if other, ok := macs[hw.String()]; ok {
					v.add("%s: mac already used by %s", p, other)
				} else {
					macs[hw.String()] = ifc.Name
				}
			}
		case IfVLAN:
			if ifc.Parent == "" {
				v.add("%s: vlan needs parent", p)
			}
			if ifc.VLANID < 1 || ifc.VLANID > 4094 {
				v.add("%s: vlan_id must be 1-4094", p)
			}
		case IfBridge:
			// members may be empty (an internal bridge).
		case IfBond:
			if len(ifc.Members) == 0 {
				v.add("%s: bond needs members", p)
			}
			if ifc.BondMode != "" && !bondModes[ifc.BondMode] {
				v.add("%s: unknown bond_mode %q", p, ifc.BondMode)
			}
		case IfPPPoE:
			if ifc.Parent == "" {
				v.add("%s: pppoe needs parent", p)
			}
			if ifc.PPPoE == nil || ifc.PPPoE.Username == "" {
				v.add("%s: pppoe needs pppoe.username", p)
			}
			if ifc.Addressing != "" && ifc.Addressing != AddrNone && ifc.Addressing != AddrDHCP {
				// address comes from the peer
				v.add("%s: pppoe addressing is negotiated, leave it empty", p)
			}
		case IfWireGuard:
			if ifc.WireGuard == nil {
				v.add("%s: wireguard section missing", p)
				break
			}
			if !wgKey(ifc.WireGuard.PrivateKey) {
				v.add("%s: wireguard.private_key is not a base64 32-byte key", p)
			}
			if lp := ifc.WireGuard.ListenPort; lp < 0 || lp > 65535 {
				v.add("%s: wireguard.listen_port out of range", p)
			}
			for j, peer := range ifc.WireGuard.Peers {
				pp := fmt.Sprintf("%s.wireguard.peers[%d]", p, j)
				if !wgKey(peer.PublicKey) {
					v.add("%s: public_key is not a base64 32-byte key", pp)
				}
				if peer.PresharedKey != "" && !wgKey(peer.PresharedKey) {
					v.add("%s: preshared_key is not a base64 32-byte key", pp)
				}
				if len(peer.AllowedIPs) == 0 {
					v.add("%s: allowed_ips required", pp)
				}
				for _, a := range peer.AllowedIPs {
					if _, err := netip.ParsePrefix(a); err != nil {
						v.add("%s: allowed_ips %q is not a prefix", pp, a)
					}
				}
				if peer.Endpoint != "" {
					if _, port, err := net.SplitHostPort(peer.Endpoint); err != nil || port == "" {
						v.add("%s: endpoint %q must be host:port", pp, peer.Endpoint)
					}
				}
			}
		case IfLoopback:
		case IfRozaneh, IfRozanehServer:
			v.rozaneh(p, ifc)
		case IfV2Ray:
			v.v2rayClient(p, ifc)
		case IfSSH:
			v.sshClient(p, ifc)
		case IfPPTP, IfL2TP, IfSSTP:
			v.pppClient(p, ifc)
		case IfL2TPv3:
			v.l2tpv3(p, ifc)
		case IfOpenVPN:
			v.openvpnClient(p, ifc)
		case IfGRE, IfIPIP, IfEoIP, If6to4, IfEoIPv6, IfGRE6:
			v.ipTunnel(p, ifc)
		default:
			v.add("%s: unknown type %q", p, ifc.Type)
		}
		switch ifc.Addressing {
		case "", AddrNone, AddrDHCP:
			if ifc.Addressing == AddrDHCP && (ifc.Type == IfWireGuard || isTunnel(ifc.Type)) {
				v.add("%s: dhcp on %s is not possible", p, ifc.Type)
			}
		case AddrStatic:
			if len(ifc.Addresses) == 0 {
				v.add("%s: static addressing needs addresses", p)
			}
		default:
			v.add("%s: addressing must be static, dhcp or none", p)
		}
		if len(ifc.Addresses) > 0 && ifc.Addressing != "" && ifc.Addressing != AddrStatic {
			v.add("%s: addresses given but addressing is %q", p, ifc.Addressing)
		}
		for _, a := range ifc.Addresses {
			if _, err := netip.ParsePrefix(a); err != nil {
				v.add("%s: address %q must be in CIDR form like 192.168.88.1/24", p, a)
			}
		}
		if ifc.Shaping != nil && !bwRe.MatchString(ifc.Shaping.Bandwidth) {
			v.add("%s: shaping.bandwidth %q must look like 95M or 1G", p, ifc.Shaping.Bandwidth)
		}
	}

	// Second pass: references between interfaces.
	owner := map[string]string{} // member -> bridge/bond
	for _, ifc := range v.c.Interfaces {
		p := fmt.Sprintf("interfaces[%s]", ifc.Name)
		if ifc.Type == IfVLAN || ifc.Type == IfPPPoE {
			par, ok := names[ifc.Parent]
			switch {
			case ifc.Parent == "":
			case !ok:
				v.add("%s: parent %q does not exist", p, ifc.Parent)
			case par.Type == IfWireGuard || par.Type == IfPPPoE || par.Type == IfLoopback || isTunnel(par.Type):
				v.add("%s: parent %q of type %s cannot carry %s", p, ifc.Parent, par.Type, ifc.Type)
			}
		}
		for _, m := range ifc.Members {
			mi, ok := names[m]
			if !ok {
				v.add("%s: member %q does not exist", p, m)
				continue
			}
			if m == ifc.Name {
				v.add("%s: cannot be a member of itself", p)
			}
			if prev, taken := owner[m]; taken {
				v.add("%s: member %q already belongs to %s", p, m, prev)
			}
			owner[m] = ifc.Name
			if ifc.Type == IfBond && mi.Type != IfEthernet {
				v.add("%s: bond member %q must be ethernet", p, m)
			}
			if mi.Type == IfWireGuard || mi.Type == IfPPPoE || mi.Type == IfLoopback || isTunnel(mi.Type) {
				v.add("%s: %s interface %q cannot be a member", p, mi.Type, m)
			}
			if len(mi.Addresses) > 0 || mi.Addressing == AddrDHCP {
				v.add("%s: member %q must not have its own IP addressing", p, m)
			}
		}
	}
	return names
}

func wgKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func (v *validator) interfaceLists(names map[string]*Interface) {
	for list, members := range v.c.InterfaceLists {
		if !listNameRe.MatchString(list) {
			v.add("interface_lists: bad list name %q", list)
		}
		for _, m := range members {
			if _, ok := names[m]; !ok {
				v.add("interface_lists[%s]: interface %q does not exist", list, m)
			}
		}
	}
}

func (v *validator) routes(names map[string]*Interface) {
	for i, r := range v.c.Routes {
		p := fmt.Sprintf("routes[%d]", i)
		dst, err := netip.ParsePrefix(r.Destination)
		if err != nil {
			v.add("%s: dst %q must be a prefix like 0.0.0.0/0", p, r.Destination)
			continue
		}
		if r.Blackhole {
			if r.Gateway != "" || r.Interface != "" {
				v.add("%s: blackhole route takes no gateway or interface", p)
			}
			continue
		}
		if r.Gateway == "" && r.Interface == "" {
			v.add("%s: needs gateway, interface or blackhole", p)
		}
		if r.Gateway != "" {
			gw, err := netip.ParseAddr(r.Gateway)
			if err != nil {
				v.add("%s: gateway %q is not an IP address", p, r.Gateway)
			} else if gw.Is4() != dst.Addr().Is4() {
				v.add("%s: gateway family does not match dst", p)
			}
		}
		if r.Interface != "" {
			if _, ok := names[r.Interface]; !ok {
				v.add("%s: interface %q does not exist", p, r.Interface)
			}
		} else if r.Gateway != "" && v.c.RouteInterface(r) == "" {
			v.add("%s: gateway %s is not inside any static interface subnet; set interface", p, r.Gateway)
		}
		if r.Distance < 0 || r.Distance > 255 {
			v.add("%s: distance must be 0-255", p)
		}
	}
}

func (v *validator) routing() {
	rt := v.c.Routing
	if rt.RouterID != "" {
		if a, err := netip.ParseAddr(rt.RouterID); err != nil || !a.Is4() {
			v.add("routing.router_id must be an IPv4 address")
		}
	}
	redist := map[string]bool{"connected": true, "static": true, "ospf": true, "bgp": true, "kernel": true}
	if o := rt.OSPF; o != nil {
		if len(o.Areas) == 0 {
			v.add("routing.ospf: needs at least one area")
		}
		for _, a := range o.Areas {
			if _, err := netip.ParseAddr(a.ID); err != nil {
				if _, err2 := strconv.ParseUint(a.ID, 10, 32); err2 != nil {
					v.add("routing.ospf.areas: id %q must be a number or dotted quad", a.ID)
				}
			}
			for _, n := range a.Networks {
				if pf, err := netip.ParsePrefix(n); err != nil || !pf.Addr().Is4() {
					v.add("routing.ospf.areas[%s]: network %q must be an IPv4 prefix", a.ID, n)
				}
			}
		}
		for _, r := range o.Redistribute {
			if !redist[r] || r == "ospf" {
				v.add("routing.ospf.redistribute: unknown source %q", r)
			}
		}
	}
	if b := rt.BGP; b != nil {
		if b.ASN == 0 {
			v.add("routing.bgp.asn is required")
		}
		for _, n := range b.Neighbors {
			if _, err := netip.ParseAddr(n.Address); err != nil {
				v.add("routing.bgp.neighbors: %q is not an IP address", n.Address)
			}
			if n.RemoteAS == 0 {
				v.add("routing.bgp.neighbors[%s]: remote_as required", n.Address)
			}
		}
		for _, n := range b.Networks {
			if _, err := netip.ParsePrefix(n); err != nil {
				v.add("routing.bgp.networks: %q is not a prefix", n)
			}
		}
		for _, r := range b.Redistribute {
			if !redist[r] || r == "bgp" {
				v.add("routing.bgp.redistribute: unknown source %q", r)
			}
		}
	}
}

func (v *validator) firewall(names map[string]*Interface) {
	fw := v.c.Firewall
	dyn := fw.DynamicLists()
	for list, entries := range fw.AddressLists {
		if !listNameRe.MatchString(list) {
			v.add("firewall.address_lists: bad list name %q", list)
		}
		for _, e := range entries {
			if !validAddrOrPrefix(e) && !validRange(e) {
				v.add("firewall.address_lists[%s]: %q is not an address, prefix or range", list, e)
			} else if dyn[list] {
				if _, err := netip.ParseAddr(e); err != nil {
					v.add("firewall.address_lists[%s]: list is filled by rules, so static entries must be single addresses (got %q)", list, e)
				}
			}
		}
	}
	for chain, pol := range map[string]string{"input": fw.Policy.Input, "forward": fw.Policy.Forward, "output": fw.Policy.Output} {
		if pol != "" && pol != ActAccept && pol != ActDrop {
			v.add("firewall.policy.%s must be accept or drop", chain)
		}
	}
	filterActs := map[string]bool{ActAccept: true, ActDrop: true, ActReject: true, ActReturn: true, ActAddSrcList: true, ActAddDstList: true}
	for i, r := range fw.Filter {
		p := fmt.Sprintf("firewall.filter[%d]", i)
		if r.Chain != "input" && r.Chain != "forward" && r.Chain != "output" {
			v.add("%s: chain must be input, forward or output", p)
		}
		if !filterActs[r.Action] {
			v.add("%s: action %q not allowed in filter", p, r.Action)
		}
		if r.ToAddress != "" || r.ToPort != "" {
			v.add("%s: to_address/to_port only apply to NAT rules", p)
		}
		v.rule(p, r, names)
	}
	natActs := map[string]map[string]bool{
		"srcnat": {ActMasquerade: true, ActSrcNAT: true, ActAccept: true, ActReturn: true},
		"dstnat": {ActDstNAT: true, ActRedirect: true, ActAccept: true, ActReturn: true},
	}
	for i, r := range fw.NAT {
		p := fmt.Sprintf("firewall.nat[%d]", i)
		acts, ok := natActs[r.Chain]
		if !ok {
			v.add("%s: chain must be srcnat or dstnat", p)
		} else if !acts[r.Action] {
			v.add("%s: action %q not allowed in %s", p, r.Action, r.Chain)
		}
		if r.Chain == "srcnat" && (r.InInterface != "" || r.InInterfaceList != "") {
			v.add("%s: srcnat cannot match in_interface", p)
		}
		if r.Chain == "dstnat" && (r.OutInterface != "" || r.OutInterfaceList != "") {
			v.add("%s: dstnat cannot match out_interface", p)
		}
		switch r.Action {
		case ActSrcNAT, ActDstNAT:
			if r.ToAddress == "" {
				v.add("%s: %s needs to_address", p, r.Action)
			} else if _, err := netip.ParseAddr(r.ToAddress); err != nil && !validRange(r.ToAddress) {
				v.add("%s: to_address %q is not an address or range", p, r.ToAddress)
			}
		case ActRedirect:
			if r.ToPort == "" {
				v.add("%s: redirect needs to_port", p)
			}
		}
		if r.ToPort != "" {
			if !portRe.MatchString(r.ToPort) || strings.Contains(r.ToPort, ",") {
				v.add("%s: to_port %q must be a port or range", p, r.ToPort)
			}
			if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "sctp" {
				v.add("%s: to_port needs protocol tcp, udp or sctp", p)
			}
		}
		if r.Action == ActAddSrcList || r.Action == ActAddDstList {
			v.add("%s: address-list actions belong in filter", p)
		}
		v.rule(p, r, names)
	}
}

func (v *validator) rule(p string, r Rule, names map[string]*Interface) {
	for _, n := range []string{r.InInterface, r.OutInterface} {
		if n != "" && strings.TrimPrefix(n, "!") != "lo" {
			if _, ok := names[strings.TrimPrefix(n, "!")]; !ok {
				v.add("%s: interface %q does not exist", p, n)
			}
		}
	}
	for _, l := range []string{r.InInterfaceList, r.OutInterfaceList} {
		if l != "" {
			if _, ok := v.c.InterfaceLists[strings.TrimPrefix(l, "!")]; !ok {
				v.add("%s: interface list %q does not exist", p, l)
			}
		}
	}
	for _, l := range []string{r.SrcAddressList, r.DstAddressList} {
		if l != "" && !v.c.Firewall.HasAddressList(strings.TrimPrefix(l, "!")) {
			v.add("%s: address list %q is neither declared nor filled by a rule", p, l)
		}
	}
	if s := r.ConnectionNATState; s != "" && s != "dstnat" && s != "!dstnat" && s != "srcnat" && s != "!srcnat" {
		v.add("%s: connection_nat_state must be dstnat, !dstnat, srcnat or !srcnat", p)
	}
	var fam4, fam6 bool
	for _, a := range []string{r.SrcAddress, r.DstAddress} {
		if a == "" {
			continue
		}
		a = strings.TrimPrefix(a, "!")
		if !validAddrOrPrefix(a) && !validRange(a) {
			v.add("%s: %q is not an address, prefix or range", p, a)
			continue
		}
		if strings.Contains(a, ":") {
			fam6 = true
		} else {
			fam4 = true
		}
	}
	if fam4 && fam6 {
		v.add("%s: src_address and dst_address are different IP families", p)
	}
	if r.Protocol != "" {
		if _, err := strconv.Atoi(r.Protocol); err != nil && !protocols[r.Protocol] {
			v.add("%s: unknown protocol %q", p, r.Protocol)
		}
	}
	for _, port := range []string{r.SrcPort, r.DstPort} {
		if port == "" {
			continue
		}
		if !portRe.MatchString(strings.TrimPrefix(port, "!")) {
			v.add("%s: port %q must look like 80, 80,443 or 1000-2000", p, port)
		}
		if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "sctp" {
			v.add("%s: ports need protocol tcp, udp or sctp", p)
		}
	}
	if r.ConnectionState != "" {
		for _, s := range strings.Split(r.ConnectionState, ",") {
			if !connStates[strings.TrimSpace(s)] {
				v.add("%s: unknown connection_state %q", p, s)
			}
		}
	}
	if r.Action == ActAddSrcList || r.Action == ActAddDstList {
		if !listNameRe.MatchString(r.AddressList) {
			v.add("%s: address_list name required for %s", p, r.Action)
		}
		if r.AddressListTimeout != "" {
			if _, err := time.ParseDuration(r.AddressListTimeout); err != nil {
				v.add("%s: address_list_timeout %q must look like 30m or 1h", p, r.AddressListTimeout)
			}
		}
	}
}

func validAddrOrPrefix(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(s)
	return err == nil
}

func validRange(s string) bool {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return false
	}
	x, err1 := netip.ParseAddr(a)
	y, err2 := netip.ParseAddr(b)
	return err1 == nil && err2 == nil && x.Is4() == y.Is4() && !y.Less(x)
}

func (v *validator) dhcp(names map[string]*Interface) {
	seen := map[string]bool{}
	for i, d := range v.c.DHCPServers {
		p := fmt.Sprintf("dhcp_servers[%d]", i)
		ifc, ok := names[d.Interface]
		if !ok {
			v.add("%s: interface %q does not exist", p, d.Interface)
			continue
		}
		if seen[d.Interface] {
			v.add("%s: second DHCP server on %s", p, d.Interface)
		}
		seen[d.Interface] = true
		subnet, err := ifaceSubnet4(ifc)
		if err != nil {
			v.add("%s: %v", p, err)
			continue
		}
		if len(d.Pools) == 0 {
			v.add("%s: needs at least one pool", p)
		}
		for _, pool := range d.Pools {
			a, b, ok := strings.Cut(pool, "-")
			x, e1 := netip.ParseAddr(a)
			y, e2 := netip.ParseAddr(b)
			if !ok || e1 != nil || e2 != nil || y.Less(x) {
				v.add("%s: pool %q must be first-last", p, pool)
				continue
			}
			if !subnet.Contains(x) || !subnet.Contains(y) {
				v.add("%s: pool %q is outside %s", p, pool, subnet)
			}
		}
		for _, ip := range append([]string{d.Gateway}, d.DNSServers...) {
			if ip == "" {
				continue
			}
			if a, err := netip.ParseAddr(ip); err != nil || !a.Is4() {
				v.add("%s: %q is not an IPv4 address", p, ip)
			}
		}
		if d.LeaseTime != "" {
			if dur, err := time.ParseDuration(d.LeaseTime); err != nil || dur < time.Minute {
				v.add("%s: lease_time %q must be a duration of at least 1m", p, d.LeaseTime)
			}
		}
		macs := map[string]bool{}
		for _, l := range d.StaticLeases {
			hw, err := net.ParseMAC(l.MAC)
			if err != nil {
				v.add("%s: static lease mac %q invalid", p, l.MAC)
			} else if macs[hw.String()] {
				v.add("%s: static lease mac %s listed twice", p, hw)
			} else {
				macs[hw.String()] = true
			}
			if a, err := netip.ParseAddr(l.Address); err != nil || !subnet.Contains(a) {
				v.add("%s: static lease %q not inside %s", p, l.Address, subnet)
			}
		}
	}
}

// ifaceSubnet4 returns the first static IPv4 subnet of an interface.
func ifaceSubnet4(ifc *Interface) (netip.Prefix, error) {
	for _, a := range ifc.Addresses {
		if pf, err := netip.ParsePrefix(a); err == nil && pf.Addr().Is4() {
			return pf.Masked(), nil
		}
	}
	return netip.Prefix{}, errors.New("interface " + ifc.Name + " has no static IPv4 address to serve DHCP on")
}

// InterfaceAddr4 returns the first static IPv4 address (without mask).
func InterfaceAddr4(ifc *Interface) (netip.Addr, bool) {
	for _, a := range ifc.Addresses {
		if pf, err := netip.ParsePrefix(a); err == nil && pf.Addr().Is4() {
			return pf.Addr(), true
		}
	}
	return netip.Addr{}, false
}

// InterfaceSubnet4 is the exported form of ifaceSubnet4.
func InterfaceSubnet4(ifc *Interface) (netip.Prefix, error) { return ifaceSubnet4(ifc) }

func (v *validator) dns(names map[string]*Interface) {
	d := v.c.DNS
	for _, f := range d.Forwarders {
		host := f
		if h, _, err := net.SplitHostPort(f); err == nil {
			host = h
		}
		if _, err := netip.ParseAddr(strings.Split(host, "#")[0]); err != nil {
			v.add("dns.forwarders: %q is not an IP address", f)
		}
	}
	for _, l := range d.ListenOn {
		ifc, ok := names[l]
		if !ok {
			v.add("dns.listen_on: interface %q does not exist", l)
		} else if _, ok := InterfaceAddr4(ifc); !ok {
			v.add("dns.listen_on: interface %q has no static IPv4 address", l)
		}
	}
	for _, a := range d.AllowFrom {
		if _, err := netip.ParsePrefix(a); err != nil {
			v.add("dns.allow_from: %q is not a prefix", a)
		}
	}
	for host, ip := range d.StaticHosts {
		if _, err := netip.ParseAddr(ip); err != nil {
			v.add("dns.static_hosts[%s]: %q is not an IP address", host, ip)
		}
	}
	if d.Enabled && len(d.ListenOn) == 0 {
		v.add("dns: enabled but listen_on is empty")
	}
}

func (v *validator) ntp() {
	for _, a := range v.c.NTP.ServeTo {
		if _, err := netip.ParsePrefix(a); err != nil {
			v.add("ntp.serve_to: %q is not a prefix", a)
		}
	}
}
