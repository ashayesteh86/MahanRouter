// Package config defines the declarative Mahan Router configuration model.
//
// The whole device state is described by one YAML document. The agent
// validates it, renders service files from it and applies them. Every
// committed version is stored in Git so it can be diffed and rolled back.
package config

// SchemaVersion is the current configuration schema version.
const SchemaVersion = 1

// Config is the root of the configuration document.
type Config struct {
	Version        int                 `yaml:"version" json:"version"`
	System         System              `yaml:"system" json:"system"`
	Interfaces     []Interface         `yaml:"interfaces" json:"interfaces"`
	InterfaceLists map[string][]string `yaml:"interface_lists,omitempty" json:"interface_lists,omitempty"`
	Routes         []StaticRoute       `yaml:"routes,omitempty" json:"routes,omitempty"`
	Routing        Routing             `yaml:"routing,omitempty" json:"routing,omitempty"`
	Firewall       Firewall            `yaml:"firewall,omitempty" json:"firewall,omitempty"`
	DHCPServers    []DHCPServer        `yaml:"dhcp_servers,omitempty" json:"dhcp_servers,omitempty"`
	DNS            DNS                 `yaml:"dns,omitempty" json:"dns,omitempty"`
	NTP            NTP                 `yaml:"ntp,omitempty" json:"ntp,omitempty"`
}

// System holds device-wide settings.
type System struct {
	Hostname string `yaml:"hostname" json:"hostname"`
	Timezone string `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	// IPForwarding defaults to true; a router without it is a host.
	IPForwarding *bool `yaml:"ip_forwarding,omitempty" json:"ip_forwarding,omitempty"`
}

// Interface types.
const (
	IfEthernet  = "ethernet"
	IfVLAN      = "vlan"
	IfBridge    = "bridge"
	IfBond      = "bond"
	IfPPPoE     = "pppoe"
	IfWireGuard = "wireguard"
	IfLoopback  = "loopback"
)

// Addressing modes.
const (
	AddrStatic = "static"
	AddrDHCP   = "dhcp"
	AddrNone   = "none"
)

// Interface is one network interface. Name is the kernel interface name
// (max 15 characters), like ether1 / vlan10 / bridge-lan / wg0.
type Interface struct {
	Name     string `yaml:"name" json:"name"`
	Type     string `yaml:"type" json:"type"`
	Comment  string `yaml:"comment,omitempty" json:"comment,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	MTU      int    `yaml:"mtu,omitempty" json:"mtu,omitempty"`

	// Ethernet: the physical port is matched by MAC (preferred, survives
	// driver renumbering) or by its current kernel name, then renamed to Name.
	MAC         string `yaml:"mac,omitempty" json:"mac,omitempty"`
	MatchDevice string `yaml:"match_device,omitempty" json:"match_device,omitempty"`

	// VLAN
	Parent string `yaml:"parent,omitempty" json:"parent,omitempty"`
	VLANID int    `yaml:"vlan_id,omitempty" json:"vlan_id,omitempty"`

	// Bridge / bond
	Members  []string `yaml:"members,omitempty" json:"members,omitempty"`
	BondMode string   `yaml:"bond_mode,omitempty" json:"bond_mode,omitempty"`
	STP      bool     `yaml:"stp,omitempty" json:"stp,omitempty"`

	// PPPoE client (Parent is the Ethernet/VLAN it dials over)
	PPPoE *PPPoE `yaml:"pppoe,omitempty" json:"pppoe,omitempty"`

	// WireGuard
	WireGuard *WireGuard `yaml:"wireguard,omitempty" json:"wireguard,omitempty"`

	// Layer 3
	Addressing string   `yaml:"addressing,omitempty" json:"addressing,omitempty"`
	Addresses  []string `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	// DHCP client options
	DHCPUseDNS    *bool `yaml:"dhcp_use_dns,omitempty" json:"dhcp_use_dns,omitempty"`
	DHCPRouteDist int   `yaml:"dhcp_route_distance,omitempty" json:"dhcp_route_distance,omitempty"`

	// Shaping applies CAKE on egress of this interface (e.g. "95M").
	Shaping *Shaping `yaml:"shaping,omitempty" json:"shaping,omitempty"`
}

// PPPoE client settings.
type PPPoE struct {
	Username        string `yaml:"username" json:"username"`
	Password        string `yaml:"password" json:"password"`
	ServiceName     string `yaml:"service_name,omitempty" json:"service_name,omitempty"`
	AddDefaultRoute bool   `yaml:"add_default_route,omitempty" json:"add_default_route,omitempty"`
	UsePeerDNS      bool   `yaml:"use_peer_dns,omitempty" json:"use_peer_dns,omitempty"`
}

// WireGuard interface settings.
type WireGuard struct {
	PrivateKey string          `yaml:"private_key" json:"private_key"`
	ListenPort int             `yaml:"listen_port,omitempty" json:"listen_port,omitempty"`
	Peers      []WireGuardPeer `yaml:"peers,omitempty" json:"peers,omitempty"`
}

// WireGuardPeer is one remote WireGuard peer.
type WireGuardPeer struct {
	Comment             string   `yaml:"comment,omitempty" json:"comment,omitempty"`
	PublicKey           string   `yaml:"public_key" json:"public_key"`
	PresharedKey        string   `yaml:"preshared_key,omitempty" json:"preshared_key,omitempty"`
	AllowedIPs          []string `yaml:"allowed_ips" json:"allowed_ips"`
	Endpoint            string   `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	PersistentKeepalive int      `yaml:"persistent_keepalive,omitempty" json:"persistent_keepalive,omitempty"`
	// RouteAllowedIPs adds routes for AllowedIPs via this interface.
	RouteAllowedIPs bool `yaml:"route_allowed_ips,omitempty" json:"route_allowed_ips,omitempty"`
}

// Shaping configures CAKE egress shaping on an interface.
type Shaping struct {
	Bandwidth string `yaml:"bandwidth" json:"bandwidth"` // e.g. 95M, 1G
}

// StaticRoute is a static route.
type StaticRoute struct {
	Destination string `yaml:"dst" json:"dst"`
	Gateway     string `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	Interface   string `yaml:"interface,omitempty" json:"interface,omitempty"`
	Distance    int    `yaml:"distance,omitempty" json:"distance,omitempty"`
	Blackhole   bool   `yaml:"blackhole,omitempty" json:"blackhole,omitempty"`
	Comment     string `yaml:"comment,omitempty" json:"comment,omitempty"`
	Disabled    bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// Routing holds dynamic routing (FRRouting).
type Routing struct {
	RouterID string `yaml:"router_id,omitempty" json:"router_id,omitempty"`
	OSPF     *OSPF  `yaml:"ospf,omitempty" json:"ospf,omitempty"`
	BGP      *BGP   `yaml:"bgp,omitempty" json:"bgp,omitempty"`
}

// OSPF v2 settings.
type OSPF struct {
	Areas        []OSPFArea `yaml:"areas" json:"areas"`
	Redistribute []string   `yaml:"redistribute,omitempty" json:"redistribute,omitempty"` // connected, static, bgp
	Passive      []string   `yaml:"passive_interfaces,omitempty" json:"passive_interfaces,omitempty"`
}

// OSPFArea lists networks belonging to an area.
type OSPFArea struct {
	ID       string   `yaml:"id" json:"id"`
	Networks []string `yaml:"networks" json:"networks"`
}

// BGP settings.
type BGP struct {
	ASN          uint32        `yaml:"asn" json:"asn"`
	Neighbors    []BGPNeighbor `yaml:"neighbors" json:"neighbors"`
	Networks     []string      `yaml:"networks,omitempty" json:"networks,omitempty"`
	Redistribute []string      `yaml:"redistribute,omitempty" json:"redistribute,omitempty"`
}

// BGPNeighbor is one BGP peer.
type BGPNeighbor struct {
	Address     string `yaml:"address" json:"address"`
	RemoteAS    uint32 `yaml:"remote_as" json:"remote_as"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Password    string `yaml:"password,omitempty" json:"password,omitempty"`
	Multihop    int    `yaml:"ebgp_multihop,omitempty" json:"ebgp_multihop,omitempty"`
	Disabled    bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// Firewall chains, modelled on MikroTik's /ip firewall.
type Firewall struct {
	AddressLists map[string][]string `yaml:"address_lists,omitempty" json:"address_lists,omitempty"`
	// Policy per filter chain: accept or drop. Default: accept (like RouterOS).
	Policy struct {
		Input   string `yaml:"input,omitempty" json:"input,omitempty"`
		Forward string `yaml:"forward,omitempty" json:"forward,omitempty"`
		Output  string `yaml:"output,omitempty" json:"output,omitempty"`
	} `yaml:"policy,omitempty" json:"policy,omitempty"`
	Filter []Rule `yaml:"filter,omitempty" json:"filter,omitempty"`
	NAT    []Rule `yaml:"nat,omitempty" json:"nat,omitempty"`
}

// Rule actions.
const (
	ActAccept     = "accept"
	ActDrop       = "drop"
	ActReject     = "reject"
	ActMasquerade = "masquerade"
	ActSrcNAT     = "src-nat"
	ActDstNAT     = "dst-nat"
	ActRedirect   = "redirect"
	ActReturn     = "return"
	ActAddSrcList = "add-src-to-address-list"
	ActAddDstList = "add-dst-to-address-list"
)

// Rule is one firewall filter or NAT rule. Empty fields match anything.
type Rule struct {
	Chain    string `yaml:"chain" json:"chain"` // input/forward/output, srcnat/dstnat
	Action   string `yaml:"action" json:"action"`
	Comment  string `yaml:"comment,omitempty" json:"comment,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	Log      bool   `yaml:"log,omitempty" json:"log,omitempty"`

	InInterface      string `yaml:"in_interface,omitempty" json:"in_interface,omitempty"`
	OutInterface     string `yaml:"out_interface,omitempty" json:"out_interface,omitempty"`
	InInterfaceList  string `yaml:"in_interface_list,omitempty" json:"in_interface_list,omitempty"`
	OutInterfaceList string `yaml:"out_interface_list,omitempty" json:"out_interface_list,omitempty"`

	SrcAddress     string `yaml:"src_address,omitempty" json:"src_address,omitempty"`
	DstAddress     string `yaml:"dst_address,omitempty" json:"dst_address,omitempty"`
	SrcAddressList string `yaml:"src_address_list,omitempty" json:"src_address_list,omitempty"`
	DstAddressList string `yaml:"dst_address_list,omitempty" json:"dst_address_list,omitempty"`

	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"` // tcp, udp, icmp, icmpv6, gre, esp, or number
	SrcPort  string `yaml:"src_port,omitempty" json:"src_port,omitempty"` // "80", "80,443", "1000-2000"
	DstPort  string `yaml:"dst_port,omitempty" json:"dst_port,omitempty"`

	// ConnectionState: comma list of established, related, new, invalid, untracked.
	ConnectionState string `yaml:"connection_state,omitempty" json:"connection_state,omitempty"`
	// ConnectionNATState: dstnat, !dstnat, srcnat, !srcnat (RouterOS connection-nat-state).
	ConnectionNATState string `yaml:"connection_nat_state,omitempty" json:"connection_nat_state,omitempty"`

	// NAT targets.
	ToAddress string `yaml:"to_address,omitempty" json:"to_address,omitempty"`
	ToPort    string `yaml:"to_port,omitempty" json:"to_port,omitempty"`

	// Address-list actions.
	AddressList        string `yaml:"address_list,omitempty" json:"address_list,omitempty"`
	AddressListTimeout string `yaml:"address_list_timeout,omitempty" json:"address_list_timeout,omitempty"` // e.g. 1h
}

// DHCPServer serves one interface.
type DHCPServer struct {
	Interface    string        `yaml:"interface" json:"interface"`
	Disabled     bool          `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	Pools        []string      `yaml:"pools" json:"pools"` // "192.168.88.10-192.168.88.254"
	Gateway      string        `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	DNSServers   []string      `yaml:"dns_servers,omitempty" json:"dns_servers,omitempty"`
	Domain       string        `yaml:"domain,omitempty" json:"domain,omitempty"`
	LeaseTime    string        `yaml:"lease_time,omitempty" json:"lease_time,omitempty"` // e.g. 12h
	StaticLeases []StaticLease `yaml:"static_leases,omitempty" json:"static_leases,omitempty"`
}

// StaticLease reserves an address for a MAC.
type StaticLease struct {
	MAC      string `yaml:"mac" json:"mac"`
	Address  string `yaml:"address" json:"address"`
	Hostname string `yaml:"hostname,omitempty" json:"hostname,omitempty"`
}

// DNS is the local caching resolver / forwarder (Unbound).
type DNS struct {
	Enabled     bool              `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Forwarders  []string          `yaml:"forwarders,omitempty" json:"forwarders,omitempty"`
	ListenOn    []string          `yaml:"listen_on,omitempty" json:"listen_on,omitempty"` // interface names
	AllowFrom   []string          `yaml:"allow_from,omitempty" json:"allow_from,omitempty"`
	StaticHosts map[string]string `yaml:"static_hosts,omitempty" json:"static_hosts,omitempty"`
	CacheSizeMB int               `yaml:"cache_size_mb,omitempty" json:"cache_size_mb,omitempty"`
}

// NTP client/server (chrony).
type NTP struct {
	Servers []string `yaml:"servers,omitempty" json:"servers,omitempty"`
	ServeTo []string `yaml:"serve_to,omitempty" json:"serve_to,omitempty"` // CIDRs allowed to query us
}
