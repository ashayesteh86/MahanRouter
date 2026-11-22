package render

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// Table is the nftables table owned by Mahan Router. Other tables (Docker,
// containers) are left alone.
const Table = "inet mahan"

// RuleTag returns the comment tag that identifies a rule's counters,
// e.g. "f3" for firewall.filter[3] and "n0" for firewall.nat[0].
func RuleTag(kind string, idx int) string { return fmt.Sprintf("%s%d", kind, idx) }

// Nftables renders the ruleset. Loading it replaces the whole mahan table
// atomically: the "add/delete" pair makes the delete safe on first load.
func Nftables(c *config.Config) (string, error) {
	fw := c.Firewall
	var w strings.Builder
	fmt.Fprintf(&w, "#!/usr/sbin/nft -f\n# %s\n\ntable %s\ndelete table %s\n\ntable %s {\n", Header, Table, Table, Table)

	// Address lists: one set per family, so rules work for IPv4 and IPv6.
	dyn := fw.DynamicLists()
	lists := map[string]bool{}
	for n := range fw.AddressLists {
		lists[n] = true
	}
	for n := range dyn {
		lists[n] = true
	}
	for _, name := range sortedKeys(lists) {
		var v4, v6 []string
		for _, e := range fw.AddressLists[name] {
			if strings.Contains(e, ":") {
				v6 = append(v6, e)
			} else {
				v4 = append(v4, e)
			}
		}
		for _, fam := range []struct {
			suffix, typ string
			elems       []string
		}{{"v4", "ipv4_addr", v4}, {"v6", "ipv6_addr", v6}} {
			fmt.Fprintf(&w, "\tset al_%s_%s {\n\t\ttype %s\n", setName(name), fam.suffix, fam.typ)
			if dyn[name] {
				w.WriteString("\t\tflags dynamic,timeout\n")
			} else {
				w.WriteString("\t\tflags interval\n\t\tauto-merge\n")
			}
			if len(fam.elems) > 0 {
				fmt.Fprintf(&w, "\t\telements = { %s }\n", strings.Join(fam.elems, ", "))
			}
			w.WriteString("\t}\n\n")
		}
	}

	nftPolicy(c, &w)

	pol := func(p string) string {
		if p == "" {
			return config.ActAccept
		}
		return p
	}
	chains := []struct{ name, hook, prio, policy string }{
		{"input", "filter hook input", "filter", pol(fw.Policy.Input)},
		{"forward", "filter hook forward", "filter", pol(fw.Policy.Forward)},
		{"output", "filter hook output", "filter", pol(fw.Policy.Output)},
		{"dstnat", "nat hook prerouting", "dstnat", "accept"},
		{"srcnat", "nat hook postrouting", "srcnat", "accept"},
	}
	for _, ch := range chains {
		fmt.Fprintf(&w, "\tchain %s {\n\t\ttype %s priority %s; policy %s;\n", ch.name, ch.hook, ch.prio, ch.policy)
		rules, kind := fw.Filter, "f"
		if ch.name == "dstnat" || ch.name == "srcnat" {
			rules, kind = fw.NAT, "n"
		}
		for _, l := range builtinRules(c, ch.name) {
			fmt.Fprintf(&w, "\t\t%s\n", l)
		}
		for i, r := range rules {
			if r.Chain != ch.name || r.Disabled {
				continue
			}
			lines, err := nftRule(c, r, RuleTag(kind, i))
			if err != nil {
				return "", fmt.Errorf("firewall %s rule %d: %w", ch.name, i, err)
			}
			for _, l := range lines {
				fmt.Fprintf(&w, "\t\t%s\n", l)
			}
		}
		w.WriteString("\t}\n\n")
	}
	w.WriteString("}\n")
	return w.String(), nil
}

// nftIfName turns the PPP server pseudo interface into a wildcard that
// matches every session interface (ppps0, ppps1, ...).
func nftIfName(n string) string {
	if n == config.PPPServerIf {
		return n + "*"
	}
	return n
}

// builtinRules come before the user's rules of a chain:
//   - PPTP clients get their GRE packets: without the PPTP conntrack
//     helper the replies do not match the outgoing call and look new.
//   - Site-to-site IPsec tunnels: IKE and ESP from the peer, traffic
//     between the two sites, and no NAT on it (ipsec.go).
//   - An L2TP server with an IPsec secret takes L2TP only inside IPsec.
//   - PPP server clients without LAN access stay on the internet only.
//   - GRE / IPIP / EoIP / 6to4 / EoIPv6 / GRE6 tunnels take their packets
//     from the configured remote. EoIP needs this before the "drop
//     invalid" rule: conntrack only understands GRE version 1 as PPTP and
//     marks every EoIP packet invalid.
func builtinRules(c *config.Config, chain string) []string {
	var out []string
	if chain == "input" {
		out = append(out, tunnelAccepts(c)...)
		for _, ifc := range c.Interfaces {
			if ifc.Type == config.IfPPTP && !ifc.Disabled {
				out = append(out, fmt.Sprintf("meta l4proto 47 counter accept comment %s", quote("pptp client GRE")))
				break
			}
		}
	}
	out = append(out, ipsecRules(c, chain)...)
	s := c.PPPServer
	if chain == "input" && s.L2TPOn() && s.L2TP.IPsecSecret != "" {
		// With a secret set, plain L2TP (without IPsec) is refused.
		out = append(out, fmt.Sprintf("udp dport 1701 meta ipsec missing counter drop comment %s", quote("l2tp server: only inside ipsec")))
	}
	if s == nil || s.AllowLAN {
		return out
	}
	ppp := quote(config.PPPServerIf + "*")
	only := quote("ppp server: internet only")
	switch chain {
	case "input":
		out = append(out, fmt.Sprintf("iifname %s counter drop comment %s", ppp, only))
	case "forward":
		wan := c.InterfaceLists["WAN"]
		if len(wan) == 0 {
			return append(out, fmt.Sprintf("iifname %s counter drop comment %s", ppp, only))
		}
		q := make([]string, len(wan))
		for i, m := range wan {
			q[i] = quote(nftIfName(m))
		}
		out = append(out, fmt.Sprintf("iifname %s oifname != { %s } counter drop comment %s", ppp, strings.Join(q, ", "), only))
	}
	return out
}

// tunnelProto is the IP protocol each tunnel type arrives as.
var tunnelProto = map[string]int{
	config.IfGRE: 47, config.IfEoIP: 47, config.IfGRE6: 47,
	config.IfIPIP: 4, config.If6to4: 41, config.IfEoIPv6: 97,
}

func tunnelAccepts(c *config.Config) []string {
	var out []string
	seen := map[string]bool{}
	for _, ifc := range c.Interfaces {
		if !config.IsIPTunnel(ifc.Type) || ifc.Tunnel == nil || ifc.Disabled {
			continue
		}
		fam := "ip"
		if config.TunnelIPv6(ifc.Type) {
			fam = "ip6"
		}
		var r string
		if ifc.Tunnel.Remote == "" { // 6to4 relay: from anywhere
			r = fmt.Sprintf("meta nfproto ipv4 meta l4proto %d counter accept comment %s", tunnelProto[ifc.Type], quote(ifc.Type+" tunnels"))
		} else {
			r = fmt.Sprintf("%s saddr %s meta l4proto %d counter accept comment %s", fam, ifc.Tunnel.Remote, tunnelProto[ifc.Type], quote(ifc.Type+" tunnel "+ifc.Name))
		}
		key := r[:strings.Index(r, " counter")]
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}

// l4proto gives protocols without an nft keyword by number: the router
// has no /etc/protocols to look names up in.
func l4proto(p string) string {
	if n, ok := map[string]string{"gre": "47", "esp": "50", "ah": "51", "ospf": "89", "sctp": "132"}[p]; ok {
		return n
	}
	return p
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// setName maps a list name to a valid nft identifier.
func setName(s string) string { return strings.ReplaceAll(s, "-", "_") }

func neg(s string) (string, bool) {
	if strings.HasPrefix(s, "!") {
		return s[1:], true
	}
	return s, false
}

func op(negated bool) string {
	if negated {
		return "!= "
	}
	return ""
}

// family of a rule: "" (both), "ip" or "ip6".
func ruleFamily(r config.Rule) string {
	for _, a := range []string{r.SrcAddress, r.DstAddress, r.ToAddress} {
		a, _ = neg(a)
		if a == "" {
			continue
		}
		if strings.Contains(a, ":") {
			return "ip6"
		}
		return "ip"
	}
	switch r.Protocol {
	case "icmp":
		return "ip"
	case "icmpv6":
		return "ip6"
	}
	return ""
}

// nftRule renders one rule. A rule that references address lists without
// fixing the IP family becomes two nft rules (IPv4 set and IPv6 set).
func nftRule(c *config.Config, r config.Rule, tag string) ([]string, error) {
	fam := ruleFamily(r)
	usesLists := r.SrcAddressList != "" || r.DstAddressList != "" || r.Action == config.ActAddSrcList || r.Action == config.ActAddDstList
	fams := []string{fam}
	if fam == "" && usesLists {
		fams = []string{"ip", "ip6"}
	}
	var out []string
	for _, f := range fams {
		l, err := nftRuleFamily(c, r, tag, f)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

func nftRuleFamily(c *config.Config, r config.Rule, tag, fam string) (string, error) {
	var m []string
	add := func(s string, a ...any) { m = append(m, fmt.Sprintf(s, a...)) }

	ifMatch := func(key, name string) {
		if name == "" {
			return
		}
		n, ng := neg(name)
		add("%s %s%s", key, op(ng), quote(nftIfName(n)))
	}
	listMatch := func(key, list string) {
		if list == "" {
			return
		}
		n, ng := neg(list)
		members := c.InterfaceLists[n]
		if len(members) == 0 {
			// Empty list: a positive match never matches, a negated one always does.
			if !ng {
				add("%s %s", key, quote("mahan-empty-list"))
			}
			return
		}
		q := make([]string, len(members))
		for i, mbr := range members {
			q[i] = quote(nftIfName(mbr))
		}
		add("%s %s{ %s }", key, op(ng), strings.Join(q, ", "))
	}
	ifMatch("iifname", r.InInterface)
	ifMatch("oifname", r.OutInterface)
	listMatch("iifname", r.InInterfaceList)
	listMatch("oifname", r.OutInterfaceList)

	if fam != "" && (r.SrcAddress != "" || r.DstAddress != "" || r.SrcAddressList != "" || r.DstAddressList != "") {
		// family is implied by the address matches below
	} else if fam != "" && r.Protocol != "icmp" && r.Protocol != "icmpv6" {
		add("meta nfproto %s", map[string]string{"ip": "ipv4", "ip6": "ipv6"}[fam])
	}
	addrMatch := func(dir, a string) {
		if a == "" {
			return
		}
		v, ng := neg(a)
		add("%s %saddr %s%s", fam, dir, op(ng), v)
	}
	addrMatch("s", r.SrcAddress)
	addrMatch("d", r.DstAddress)
	suffix := map[string]string{"ip": "v4", "ip6": "v6"}[fam]
	setMatch := func(dir, list string) {
		if list == "" {
			return
		}
		v, ng := neg(list)
		add("%s %saddr %s@al_%s_%s", fam, dir, op(ng), setName(v), suffix)
	}
	setMatch("s", r.SrcAddressList)
	setMatch("d", r.DstAddressList)

	if r.Protocol != "" {
		if r.SrcPort == "" && r.DstPort == "" {
			add("meta l4proto %s", l4proto(r.Protocol))
		}
		ports := func(dir, p string) {
			if p == "" {
				return
			}
			v, ng := neg(p)
			parts := strings.Split(v, ",")
			if len(parts) == 1 {
				add("%s %sport %s%s", r.Protocol, dir, op(ng), v)
			} else {
				add("%s %sport %s{ %s }", r.Protocol, dir, op(ng), strings.Join(parts, ", "))
			}
		}
		ports("s", r.SrcPort)
		ports("d", r.DstPort)
	}
	if r.ConnectionState != "" {
		var st []string
		for _, s := range strings.Split(r.ConnectionState, ",") {
			st = append(st, strings.TrimSpace(s))
		}
		if len(st) == 1 {
			add("ct state %s", st[0])
		} else {
			add("ct state { %s }", strings.Join(st, ", "))
		}
	}
	if s := r.ConnectionNATState; s != "" {
		v, ng := neg(s)
		if ng {
			add("ct status & %s == 0", natBit(v))
		} else {
			add("ct status & %s == %s", natBit(v), natBit(v))
		}
	}
	add("counter")
	if r.Log {
		prefix := "mr " + tag + " "
		if r.Comment != "" {
			prefix += r.Comment + " "
		}
		if len(prefix) > 60 {
			prefix = prefix[:60]
		}
		add("log prefix %s", quote(prefix))
	}

	switch r.Action {
	case config.ActAccept, config.ActDrop, config.ActReturn:
		add("%s", r.Action)
	case config.ActReject:
		if r.Protocol == "tcp" {
			add("reject with tcp reset")
		} else {
			add("reject")
		}
	case config.ActMasquerade:
		if r.ToPort != "" {
			add("masquerade to :%s", r.ToPort)
		} else {
			add("masquerade")
		}
	case config.ActSrcNAT, config.ActDstNAT:
		verb := "snat"
		if r.Action == config.ActDstNAT {
			verb = "dnat"
		}
		target := r.ToAddress
		tf := "ip"
		if strings.Contains(target, ":") {
			tf = "ip6"
			if r.ToPort != "" {
				target = "[" + target + "]"
			}
		}
		if r.ToPort != "" {
			target += ":" + r.ToPort
		}
		add("%s %s to %s", verb, tf, target)
	case config.ActRedirect:
		add("redirect to :%s", r.ToPort)
	case config.ActAddSrcList, config.ActAddDstList:
		dir := "s"
		if r.Action == config.ActAddDstList {
			dir = "d"
		}
		timeout := ""
		if r.AddressListTimeout != "" {
			d, _ := time.ParseDuration(r.AddressListTimeout)
			timeout = fmt.Sprintf(" timeout %ds", int(d.Seconds()))
		}
		add("add @al_%s_%s { %s %saddr%s }", setName(r.AddressList), suffix, fam, dir, timeout)
	default:
		return "", fmt.Errorf("unsupported action %q", r.Action)
	}
	comment := tag
	if r.Comment != "" {
		comment += " " + r.Comment
	}
	if len(comment) > 120 {
		comment = comment[:120]
	}
	add("comment %s", quote(comment))
	return strings.Join(m, " "), nil
}

// natBit maps RouterOS connection-nat-state names to conntrack status bits.
func natBit(s string) string {
	if s == "srcnat" {
		return "snat"
	}
	return "dnat"
}
