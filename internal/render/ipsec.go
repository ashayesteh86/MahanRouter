package render

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// Site-to-site IPsec (strongSwan, policy based). The lists are wide on
// purpose so the usual RouterOS, FortiGate and Cisco defaults match
// without tuning; ike_proposals / esp_proposals narrow them.
const (
	s2sIKE = "aes256-sha256-modp2048,aes256-sha256-ecp256,aes256-sha1-modp2048,aes128-sha256-modp2048," +
		"aes128-sha1-modp2048,aes256-sha256-modp1024,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024"
	s2sESP = "aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1,aes256gcm16,3des-sha1"
)

// IPsecConnName is the swanctl connection of a site-to-site tunnel.
func IPsecConnName(n string) string { return "mr-s2s-" + n }

// espProposals adds the PFS group: none, one group, or (not set) without
// a group first and then with the two common ones, so either side's
// choice is accepted.
func espProposals(t *config.IPsecTunnel) string {
	if t.ESPProposals != "" {
		return t.ESPProposals
	}
	base := strings.Split(s2sESP, ",")
	with := func(g string) []string {
		out := make([]string, len(base))
		for i, p := range base {
			out[i] = p + "-" + g
		}
		return out
	}
	switch t.PFS {
	case "none":
		return s2sESP
	case "":
		return strings.Join(append(append(base, with("modp2048")...), with("modp1024")...), ",")
	}
	return strings.Join(with(t.PFS), ",")
}

func ipsecSiteToSite(c *config.Config, conns, secrets *strings.Builder) int {
	n := 0
	for _, t := range c.IPsecTunnels() {
		pairs := t.SubnetPairs()
		if len(pairs) == 0 {
			continue
		}
		n++
		name := IPsecConnName(t.Name)
		ike := t.IKEProposals
		if ike == "" {
			ike = s2sIKE
		}
		fmt.Fprintf(conns, "\t%s {\n\t\tversion = %d\n", name, t.Version())
		if t.Local != "" {
			fmt.Fprintf(conns, "\t\tlocal_addrs = %s\n", t.Local)
		}
		if t.Remote != "" {
			fmt.Fprintf(conns, "\t\tremote_addrs = %s\n", t.Remote)
		}
		if t.Aggressive {
			conns.WriteString("\t\taggressive = yes\n")
		}
		fmt.Fprintf(conns, "\t\tproposals = %s\n\t\tmobike = no\n\t\tdpd_delay = 30s\n", ike)
		if t.Initiates() {
			conns.WriteString("\t\tkeyingtries = 0\n")
		}
		conns.WriteString("\t\tlocal {\n\t\t\tauth = psk\n")
		if t.LocalID != "" {
			fmt.Fprintf(conns, "\t\t\tid = %s\n", t.LocalID)
		} else if t.Version() == 1 {
			// IKEv1 main mode looks the key up before it knows the peer's
			// ID, and only through connections that name a local ID.
			// %any still sends this router's address as its ID.
			conns.WriteString("\t\t\tid = %any\n")
		}
		conns.WriteString("\t\t}\n\t\tremote {\n\t\t\tauth = psk\n")
		if id := t.PeerID(); id != "" {
			fmt.Fprintf(conns, "\t\t\tid = %s\n", id)
		}
		conns.WriteString("\t\t}\n\t\tchildren {\n")
		esp := espProposals(t)
		for i, p := range pairs {
			fmt.Fprintf(conns, "\t\t\t%s-%d {\n\t\t\t\tmode = tunnel\n\t\t\t\tlocal_ts = %s\n\t\t\t\tremote_ts = %s\n\t\t\t\tesp_proposals = %s\n",
				name, i+1, p[0], p[1], esp)
			if t.Initiates() {
				// The policy is installed at once (no plain packets leave
				// while the tunnel is down) and the tunnel is started.
				conns.WriteString("\t\t\t\tstart_action = trap|start\n\t\t\t\tdpd_action = restart\n\t\t\t\tclose_action = trap\n")
			} else {
				conns.WriteString("\t\t\t\tdpd_action = clear\n")
			}
			conns.WriteString("\t\t\t}\n")
		}
		conns.WriteString("\t\t}\n\t}\n")

		// The key belongs to the peer's ID and, when known, its address:
		// IKEv1 main mode can only search by address.
		fmt.Fprintf(secrets, "\tike-%s {\n", name)
		if id := t.PeerID(); id != "" {
			fmt.Fprintf(secrets, "\t\tid-1 = %s\n", id)
			if t.RemoteIsAddr() && id != t.Remote {
				fmt.Fprintf(secrets, "\t\tid-2 = %s\n", t.Remote)
			}
		}
		fmt.Fprintf(secrets, "\t\tsecret = %s\n\t}\n", quote(t.PSK))
	}
	return n
}

// ipsecFamilies splits a tunnel's subnets by family ("ip", "ip6").
func ipsecFamilies(list []string) map[string][]string {
	out := map[string][]string{}
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		if p.Addr().Is4() {
			out["ip"] = append(out["ip"], s)
		} else {
			out["ip6"] = append(out["ip6"], s)
		}
	}
	return out
}

func nftAddrs(l []string) string {
	if len(l) == 1 {
		return l[0]
	}
	return "{ " + strings.Join(l, ", ") + " }"
}

// ipsecRules are the firewall rules a site-to-site tunnel needs:
//   - input: IKE (UDP 500, 4500) and ESP from the peer, and the remote
//     subnets to the router itself when allow_router is set;
//   - forward: decrypted traffic from the remote subnets to the local
//     ones, and local to remote when it leaves through the tunnel, with
//     the TCP MSS lowered to what fits inside ESP;
//   - srcnat: no NAT between the two sites.
func ipsecRules(c *config.Config, chain string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(rule, comment string) {
		if !seen[rule] {
			seen[rule] = true
			out = append(out, rule+" counter accept comment "+quote(comment))
		}
	}
	for _, t := range c.IPsecTunnels() {
		if len(t.SubnetPairs()) == 0 {
			continue
		}
		tag := "ipsec " + t.Name
		loc, rem := ipsecFamilies(t.LocalSubnets), ipsecFamilies(t.RemoteSubnets)
		switch chain {
		case "input":
			from := ""
			if a, err := netip.ParseAddr(t.Remote); err == nil {
				from = "ip saddr " + t.Remote + " "
				if a.Is6() {
					from = "ip6 saddr " + t.Remote + " "
				}
			}
			add(from+"udp dport { 500, 4500 }", tag+": IKE")
			add(from+"meta l4proto 50", tag+": ESP")
			if t.AllowRouter {
				for _, fam := range []string{"ip", "ip6"} {
					if len(rem[fam]) > 0 && len(loc[fam]) > 0 {
						add(fmt.Sprintf("meta ipsec exists %s saddr %s", fam, nftAddrs(rem[fam])), tag+": remote site to router")
					}
				}
			}
		case "forward":
			for _, fam := range []string{"ip", "ip6"} {
				if len(rem[fam]) == 0 || len(loc[fam]) == 0 {
					continue
				}
				l, r := nftAddrs(loc[fam]), nftAddrs(rem[fam])
				mss := fmt.Sprintf("%s saddr %s %s daddr %s rt ipsec exists tcp flags syn tcp option maxseg size set rt mtu comment %s", fam, l, fam, r, quote(tag+": MSS"))
				if !seen[mss] {
					seen[mss] = true
					out = append(out, mss)
				}
				add(fmt.Sprintf("%s saddr %s %s daddr %s rt ipsec exists", fam, l, fam, r), tag+": to remote site")
				add(fmt.Sprintf("meta ipsec exists %s saddr %s %s daddr %s", fam, r, fam, l), tag+": from remote site")
			}
		case "srcnat":
			for _, fam := range []string{"ip", "ip6"} {
				if len(rem[fam]) == 0 || len(loc[fam]) == 0 {
					continue
				}
				add(fmt.Sprintf("%s saddr %s %s daddr %s", fam, nftAddrs(loc[fam]), fam, nftAddrs(rem[fam])), tag+": no NAT")
			}
		}
	}
	return out
}
