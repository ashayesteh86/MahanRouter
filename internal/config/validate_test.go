package config

import (
	"strings"
	"testing"
)

const base = `
version: 1
system: { hostname: r1 }
interfaces:
  - { name: ether1, type: ethernet, mac: "52:54:00:00:00:01", addressing: dhcp }
  - { name: ether2, type: ethernet, mac: "52:54:00:00:00:02", addressing: static, addresses: [192.168.1.1/24] }
interface_lists: { WAN: [ether1], LAN: [ether2] }
`

func problems(t *testing.T, doc string) string {
	t.Helper()
	c, err := Parse([]byte(doc))
	if err != nil {
		return err.Error()
	}
	if err := Validate(c); err != nil {
		return err.Error()
	}
	return ""
}

func TestValidBase(t *testing.T) {
	if p := problems(t, base); p != "" {
		t.Fatal(p)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct{ name, extra, want string }{
		{"unknown key", "\nfirewal: {}\n", "field firewal not found"},
		{"bad vlan", "  - { name: v1, type: vlan, parent: ether2, vlan_id: 5000 }\n", "vlan_id must be 1-4094"},
		{"missing parent", "  - { name: v1, type: vlan, parent: nope, vlan_id: 5 }\n", `parent "nope" does not exist`},
		{"long name", "  - { name: averyveryverylongname, type: loopback }\n", "must be 1-15 chars"},
		{"dup mac", "  - { name: ether3, type: ethernet, mac: \"52:54:00:00:00:01\" }\n", "mac already used"},
		{"member with ip", "  - { name: br0, type: bridge, members: [ether2] }\n", "must not have its own IP"},
		{"bad wg key", "  - { name: wg0, type: wireguard, wireguard: { private_key: abc } }\n", "not a base64 32-byte key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := base
			if strings.HasPrefix(c.extra, "  -") {
				doc = strings.Replace(base, "interface_lists:", c.extra+"interface_lists:", 1)
			} else {
				doc += c.extra
			}
			if p := problems(t, doc); !strings.Contains(p, c.want) {
				t.Errorf("want %q in:\n%s", c.want, p)
			}
		})
	}
}

func TestFirewallValidation(t *testing.T) {
	cases := []struct{ rule, want string }{
		{`{ chain: input, action: masquerade }`, "not allowed in filter"},
		{`{ chain: input, action: drop, dst_port: "22" }`, "ports need protocol"},
		{`{ chain: input, action: drop, src_address_list: nope }`, "neither declared nor filled"},
		{`{ chain: input, action: drop, in_interface_list: NOPE }`, `interface list "NOPE" does not exist`},
		{`{ chain: input, action: drop, connection_state: weird }`, "unknown connection_state"},
		{`{ chain: input, action: drop, src_address: 10.0.0.1, dst_address: "::1" }`, "different IP families"},
		{`{ chain: input, action: drop, protocol: tcp, dst_port: "80-" }`, "must look like"},
	}
	for _, c := range cases {
		doc := base + "firewall:\n  filter:\n    - " + c.rule + "\n"
		if p := problems(t, doc); !strings.Contains(p, c.want) {
			t.Errorf("%s: want %q in:\n%s", c.rule, c.want, p)
		}
	}
	nat := base + "firewall:\n  nat:\n    - { chain: dstnat, action: dst-nat, protocol: tcp, dst_port: \"80\" }\n"
	if p := problems(t, nat); !strings.Contains(p, "needs to_address") {
		t.Errorf("dst-nat without to_address: %s", p)
	}
}

func TestDHCPValidation(t *testing.T) {
	doc := base + "dhcp_servers:\n  - { interface: ether2, pools: [192.168.2.10-192.168.2.20] }\n"
	if p := problems(t, doc); !strings.Contains(p, "outside 192.168.1.0/24") {
		t.Errorf("pool outside subnet: %s", p)
	}
	doc = base + "dhcp_servers:\n  - { interface: ether1, pools: [192.168.1.10-192.168.1.20] }\n"
	if p := problems(t, doc); !strings.Contains(p, "no static IPv4") {
		t.Errorf("dhcp on dhcp-client iface: %s", p)
	}
}

func TestRouteNeedsReachableGateway(t *testing.T) {
	doc := base + "routes:\n  - { dst: 10.0.0.0/8, gateway: 172.16.0.1 }\n"
	if p := problems(t, doc); !strings.Contains(p, "not inside any static interface subnet") {
		t.Errorf("got %s", p)
	}
	doc = base + "routes:\n  - { dst: 10.0.0.0/8, gateway: 192.168.1.254 }\n"
	if p := problems(t, doc); p != "" {
		t.Error(p)
	}
}

func TestFactoryDefaultValid(t *testing.T) {
	for _, n := range []int{0, 1, 5} {
		var nics []NIC
		for i := 0; i < n; i++ {
			nics = append(nics, NIC{Device: "eth", MAC: "52:54:00:00:01:0" + string(rune('0'+i))})
		}
		data, err := Marshal(FactoryDefault(nics))
		if err != nil {
			t.Fatal(err)
		}
		if p := problems(t, string(data)); p != "" {
			t.Errorf("%d NICs: %s", n, p)
		}
	}
}
