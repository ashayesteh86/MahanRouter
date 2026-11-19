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
		add("%s %s%s", key, op(ng), quote(n))
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
			q[i] = quote(mbr)
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
			add("meta l4proto %s", r.Protocol)
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
