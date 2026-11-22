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
  policy_routes?: PolicyRoute[];
  v2ray_server?: V2RayServer;
  ppp_server?: PPPServer;
  ipsec?: { tunnels?: IPsecTunnel[] };
}

export interface IPsecTunnel {
  name: string; comment?: string; disabled?: boolean; remote?: string; local?: string; ike_version?: 1 | 2; aggressive?: boolean;
  psk: string; local_id?: string; remote_id?: string; local_subnets: string[]; remote_subnets: string[];
  pfs?: string; ike_proposals?: string; esp_proposals?: string; passive?: boolean; allow_router?: boolean;
}

export interface PPPUser { name: string; password: string; ip?: string; disabled?: boolean }
export interface PPPServer {
  disabled?: boolean; address: string; client_dns?: string[]; mtu?: number; allow_lan?: boolean;
  pptp?: { enabled: boolean }; l2tp?: { enabled: boolean; ipsec_secret?: string };
  sstp?: { enabled: boolean; public_port?: number; listen_port?: number; domain?: string; cert_pem: string; key_pem: string };
  openvpn?: OpenVPNServer;
  users?: PPPUser[];
}
export interface OpenVPNServer {
  enabled: boolean; port?: number; protocol?: "tcp" | "udp"; address?: string; domain?: string; cert_pem: string; key_pem: string;
  cipher?: string; auth?: string; split_tunnel?: boolean;
}
export interface OpenVPNClient {
  config?: string; server?: string; port?: number; protocol?: "tcp" | "udp"; ca_pem?: string; fingerprint?: string;
  cert_pem?: string; key_pem?: string; cipher?: string; auth?: string; username?: string; password?: string;
}
export interface PPPClient { server: string; username: string; password: string; ipsec_secret?: string; verify_cert?: boolean }
export type TunnelType = "gre" | "ipip" | "eoip" | "6to4" | "eoipv6" | "gre6";
export interface Tunnel {
  local?: string; remote?: string; tunnel_id?: number; key?: number; ttl?: number; keepalive?: number; mac?: string;
}

export interface L2TPv3 {
  local?: string; remote: string; encapsulation?: "udp" | "ip"; port?: number;
  tunnel_id: number; peer_tunnel_id: number; session_id: number; peer_session_id: number;
}

export interface V2RayUser { name: string; secret: string; disabled?: boolean }
export interface V2RayServer {
  disabled?: boolean; protocol?: "vless_reality" | "shadowsocks"; public_port?: number; listen_port?: number; address?: string;
  reality_target?: string; reality_private_key?: string; reality_short_id?: string; ss_key?: string; allow_lan?: boolean; users?: V2RayUser[];
}

export interface PolicyRoute {
  interface: string; comment?: string; disabled?: boolean;
  from: "lan" | "devices"; devices?: string[];
  except_iran?: boolean; dns_via_tunnel?: boolean; block_if_down?: boolean;
}

export interface RozanehPeer { name: string; public_key: string; ip: string; disabled?: boolean }
export interface RozanehServer {
  domain: string; acme_email?: string; cert_pem?: string; key_pem?: string;
  public_port?: number; listen_port?: number; path: string; private_key: string;
  cover_url?: string; cover_traffic?: boolean; client_dns?: string[]; peers?: RozanehPeer[];
}

export interface Iface {
  name: string;
  type: "ethernet" | "vlan" | "bridge" | "bond" | "pppoe" | "wireguard" | "loopback" | "rozaneh" | "rozaneh_server" | "v2ray" | "pptp" | "l2tp" | "sstp" | "l2tpv3" | "openvpn" | "ssh" | TunnelType;
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
  rozaneh?: { link: string; method?: "auto" | "tunnel" | "dns" };
  rozaneh_server?: RozanehServer;
  v2ray?: { link: string };
  ssh?: SSHClient;
  ppp?: PPPClient;
  l2tpv3?: L2TPv3;
  openvpn?: OpenVPNClient;
  tunnel?: Tunnel;
  wireguard?: { private_key: string; listen_port?: number; client_endpoint?: string; client_dns?: string; peers?: WGPeer[] };
  addressing?: "static" | "dhcp" | "none";
  addresses?: string[];
  dhcp_use_dns?: boolean;
  dhcp_route_distance?: number;
  shaping?: { bandwidth: string };
}

export interface SSHClient {
  server: string; port?: number; username: string; password?: string;
  private_key?: string; passphrase?: string; host_keys?: string[];
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
