package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// NIC is a detected physical network port.
type NIC struct {
	Device string // current kernel name, e.g. enp1s0
	MAC    string
	Bus    string // sysfs device path, used for stable ordering
}

// DetectNICs lists physical Ethernet ports from sysfs (anything with a
// backing device, excluding wireless), ordered by bus path so ether1 is
// the first port on the board.
func DetectNICs(sysClassNet string) ([]NIC, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, err
	}
	var nics []NIC
	for _, e := range entries {
		base := filepath.Join(sysClassNet, e.Name())
		dev, err := filepath.EvalSymlinks(filepath.Join(base, "device"))
		if err != nil {
			continue // virtual interface
		}
		if _, err := os.Stat(filepath.Join(base, "wireless")); err == nil {
			continue
		}
		typ, _ := os.ReadFile(filepath.Join(base, "type"))
		if strings.TrimSpace(string(typ)) != "1" { // ARPHRD_ETHER
			continue
		}
		mac, _ := os.ReadFile(filepath.Join(base, "address"))
		nics = append(nics, NIC{Device: e.Name(), MAC: strings.TrimSpace(string(mac)), Bus: dev})
	}
	sort.Slice(nics, func(i, j int) bool { return nics[i].Bus < nics[j].Bus })
	return nics, nil
}

// FactoryDefault builds the out-of-box config, following the familiar
// RouterOS home/office default: ether1 is the DHCP WAN, every other port
// joins bridge-lan at 192.168.88.1/24 with DHCP, DNS cache, NAT and a
// safe firewall.
func FactoryDefault(nics []NIC) *Config {
	c := &Config{
		Version: SchemaVersion,
		System:  System{Hostname: "mahan-router"},
		InterfaceLists: map[string][]string{
			"WAN": {},
			"LAN": {},
		},
	}
	var lanPorts []string
	for i, n := range nics {
		name := fmt.Sprintf("ether%d", i+1)
		ifc := Interface{Name: name, Type: IfEthernet, MAC: n.MAC}
		if i == 0 {
			ifc.Comment = "WAN"
			ifc.Addressing = AddrDHCP
			c.InterfaceLists["WAN"] = append(c.InterfaceLists["WAN"], name)
		} else {
			lanPorts = append(lanPorts, name)
		}
		c.Interfaces = append(c.Interfaces, ifc)
	}
	c.Interfaces = append(c.Interfaces, Interface{
		Name: "bridge-lan", Type: IfBridge, Comment: "LAN", Members: lanPorts,
		Addressing: AddrStatic, Addresses: []string{"192.168.88.1/24"},
	})
	c.InterfaceLists["LAN"] = []string{"bridge-lan"}
	c.DHCPServers = []DHCPServer{{
		Interface: "bridge-lan", Pools: []string{"192.168.88.10-192.168.88.254"}, LeaseTime: "12h",
	}}
	c.DNS = DNS{Enabled: true, Forwarders: []string{"1.1.1.1", "8.8.8.8"}, ListenOn: []string{"bridge-lan"}}
	c.NTP = NTP{Servers: []string{"pool.ntp.org"}}
	c.Firewall = DefaultFirewall()
	return c
}

// DefaultFirewall is the safe default rule set (WAN/LAN interface lists).
func DefaultFirewall() Firewall {
	var fw Firewall
	fw.Filter = []Rule{
		{Chain: "input", Action: ActAccept, ConnectionState: "established,related,untracked", Comment: "accept established,related,untracked"},
		{Chain: "input", Action: ActDrop, ConnectionState: "invalid", Comment: "drop invalid"},
		{Chain: "input", Action: ActAccept, Protocol: "icmp", Comment: "accept ICMP"},
		{Chain: "input", Action: ActAccept, Protocol: "icmpv6", Comment: "accept ICMPv6"},
		{Chain: "input", Action: ActAccept, InInterface: "lo", Comment: "accept loopback"},
		{Chain: "input", Action: ActDrop, InInterfaceList: "!LAN", Comment: "drop all not coming from LAN"},
		{Chain: "forward", Action: ActAccept, ConnectionState: "established,related,untracked", Comment: "accept established,related,untracked"},
		{Chain: "forward", Action: ActDrop, ConnectionState: "invalid", Comment: "drop invalid"},
		{Chain: "forward", Action: ActDrop, ConnectionState: "new", ConnectionNATState: "!dstnat", InInterfaceList: "WAN", Comment: "drop all from WAN not DSTNATed"},
	}
	fw.NAT = []Rule{
		{Chain: "srcnat", Action: ActMasquerade, OutInterfaceList: "WAN", Comment: "masquerade"},
	}
	return fw
}
