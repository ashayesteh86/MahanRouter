// Mirrors internal/config/types.go (JSON field names = YAML keys).

export interface Config {
  version: number;
  system: { hostname: string; timezone?: string; ip_forwarding?: boolean };
  interfaces: Iface[];
  interface_lists?: Record<string, string[]>;
  routes?: StaticRoute[];
  routing?: any;
  firewall?: Firewall;
  dhcp_servers?: DHCPServer[];
  dns?: DNS;
  ntp?: { servers?: string[]; serve_to?: string[] };
}

export interface Iface {
  name: string;
  type: "ethernet" | "vlan" | "bridge" | "bond" | "pppoe" | "wireguard" | "loopback";
  comment?: string;
  disabled?: boolean;
  mtu?: number;
  mac?: string;
  match_device?: string;
  parent?: string;
  vlan_id?: number;
  members?: string[];
  bond_mode?: string;
  stp?: boolean;
  pppoe?: { username: string; password: string; service_name?: string; add_default_route?: boolean; use_peer_dns?: boolean };
  wireguard?: { private_key: string; listen_port?: number; client_endpoint?: string; client_dns?: string; peers?: WGPeer[] };
  addressing?: "static" | "dhcp" | "none";
  addresses?: string[];
  dhcp_use_dns?: boolean;
  dhcp_route_distance?: number;
  shaping?: { bandwidth: string };
}

export interface WGPeer {
  comment?: string;
  public_key: string;
  preshared_key?: string;
  allowed_ips: string[];
  endpoint?: string;
  persistent_keepalive?: number;
  route_allowed_ips?: boolean;
}

export interface StaticRoute {
  dst: string;
  gateway?: string;
  interface?: string;
  distance?: number;
  blackhole?: boolean;
  comment?: string;
  disabled?: boolean;
}

export interface Rule {
  chain: string;
  action: string;
  comment?: string;
  disabled?: boolean;
  log?: boolean;
  in_interface?: string;
  out_interface?: string;
  in_interface_list?: string;
  out_interface_list?: string;
  src_address?: string;
  dst_address?: string;
  src_address_list?: string;
  dst_address_list?: string;
  protocol?: string;
  src_port?: string;
  dst_port?: string;
  connection_state?: string;
  connection_nat_state?: string;
  to_address?: string;
  to_port?: string;
  address_list?: string;
  address_list_timeout?: string;
}

export interface Firewall {
  address_lists?: Record<string, string[]>;
  policy?: { input?: string; forward?: string; output?: string };
  filter?: Rule[];
  nat?: Rule[];
}

export interface DHCPServer {
  interface: string;
  disabled?: boolean;
  pools: string[];
  gateway?: string;
  dns_servers?: string[];
  domain?: string;
  lease_time?: string;
  static_leases?: { mac: string; address: string; hostname?: string }[];
}

export interface DNS {
  enabled?: boolean;
  forwarders?: string[];
  listen_on?: string[];
  allow_from?: string[];
  static_hosts?: Record<string, string>;
  cache_size_mb?: number;
}

export interface Pending { revision: string; previous: string; deadline: string; seconds_left: number }
export interface Status { revision: string; has_candidate: boolean; pending: Pending | null }
export interface Revision { hash: string; short: string; author: string; time: string; message: string }
