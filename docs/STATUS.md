# Status (2026-11-19, version 0.4.0)

## Built and tested

| Area | What | Tested how |
|---|---|---|
| Config model | Strict YAML schema v1; full validation that reports every problem at once | unit tests |
| Interfaces | ethernet (rename by MAC), VLAN, bridge (STP), bond (802.3ad etc.), dummy loopback, PPPoE client (pppd), WireGuard (networkd), MTU, disable | render tests; networkd files **not yet loaded by a real networkd** |
| Addressing | static, DHCP client (route metric, use DNS) | render tests |
| Routing | static routes (gateway/interface/blackhole/metric); OSPFv2 and BGP via FRR | `frr.conf` accepted by FRR 9.1 `vtysh -C`; no live adjacency test |
| Firewall | input/forward/output with policy, address lists (v4+v6, static+dynamic with timeout), interface lists, conn state, NAT state, ports, log, counters | `nft -c` + live traffic in the netns lab |
| NAT | masquerade, src-nat, dst-nat (port forward), redirect | netns lab |
| QoS | CAKE egress shaping per interface | render test only |
| DHCP server | Kea, pools, static leases, gateway/DNS/domain options | `kea-dhcp4 -t` |
| DNS | Unbound forwarder/cache, static hosts, access control | `unbound-checkconf` |
| NTP | chrony sources + serve to subnets | render only |
| Commit model | Git history, candidate/diff, commit-confirm with auto-rollback (also across restarts), manual rollback, restore on failed apply | unit tests + netns lab |
| API/CLI | REST over Unix socket / TCP+token, `mrctl` | netns lab |
| ISO | Debian 12 live + installer, BIOS + UEFI, open-vm-tools | QEMU (TCG): live boot, port rename to ether1/ether2 on e1000 + vmxnet3, WAN DHCP, Kea lease to a LAN client, NAT to the internet, Unbound; auto-install to disk, then boot from disk on BIOS and UEFI |
| Web panel | HTTPS on the LAN with login, sessions and lockout; dashboard, interfaces, firewall/NAT, DHCP, DNS, static routes, tools, diff/apply (safe mode)/history/rollback, YAML editor, panel users; Persian + English | Go unit tests; headless Chromium against a local agent: login, add a dst-nat rule, apply with confirm, confirm, history |
| VPN: WireGuard | Servers with QR client configs, site-to-site peers, live handshake/traffic | real router on VMware: client in a netns reached the LAN, DNS, panel and internet |
| VPN: Rozaneh | Client from a `rozaneh://` link, server with Let's Encrypt or own certificate | real router: client to a lab server; server reached from a lab client (LAN, panel, DNS, internet). Let's Encrypt issuance not tested. |
| VPN: V2Ray (sing-box 1.14.4) | Client from share links (vless/vmess/trojan/ss/hysteria2), server VLESS-Reality or Shadowsocks 2022 | real router: LAN device through a VLESS-Reality tunnel, DNS via tunnel, kill switch; lab client through the router's server |
| VPN: SSTP, L2TP/IPsec, PPTP (pppd, sstpc, xl2tpd, strongSwan; accel-ppp 1.15.0 server) | Clients routed by policy; one server for all three with shared users, sessions list and disconnect, self-signed SSTP certificate, internet-only or LAN access | lab with two routers in QEMU: all three clients against the router's own server in both directions (from LAN and WAN side), L2TP traffic seen only as ESP, LAN device through an SSTP tunnel, delete/disable/change; panel: client created and applied in headless Chromium. Not tried against Windows, iPhone or MikroTik. |
| VPN: L2TPv3 | Static tunnel (UDP or IP encapsulation), IP address or bridge member | same lab: ping across, port change rebuilds the tunnel |
| Policy routing | All LAN / chosen devices / all except Iranian addresses through a tunnel; DNS via tunnel; kill switch | real router, see above |
| Builds | static binaries for amd64/arm64/arm/mips/mipsle (~8 MB each) | built, not run on ARM/MIPS |

## Not built yet (phase 1 remainder)

- A/B partitions, read-only root and signed updates. The ISO installs a normal ext4 root.
- A test on real hardware. The ISO installs and boots on the user's VMware (BIOS); UEFI is tested in QEMU only.
- Web panel: forms for OSPF/BGP, bond/bridge VLAN filtering and per-user roles (today every panel user has full access).
- MikroTik-style interactive CLI (`/ip firewall filter add ...`) on top of the API.
- IPsec beyond L2TP (IKEv2 road warrior, site-to-site), OpenVPN.
- Let's Encrypt for the SSTP server (today: self-signed or your own certificate).
- VPN apps on real phones, and Windows/iPhone/MikroTik built-in clients, have not been tried against the router yet.
- Per-IP "simple queues" (tc HTB/CAKE trees).
- DHCPv6 / IPv6 RA on LAN; IPv6 BGP has been rendered but never tested.
- Bridge VLAN filtering (trunk/access ports on one bridge).
- Users, RBAC, RADIUS/LDAP, MFA. Today the API has one token plus the root-only socket.
- Secrets are stored in plain text in the config repo (`/var/lib/mahan-router`, mode 0700).
  The API `render` preview masks them, but `show running` does not.
- Monitoring: Prometheus exporter, SNMP, NetFlow.
- RouterOS `export` → YAML converter.

## Known limits

- The binaries are ~8 MB, too large for 16 MB-flash OpenWrt devices. The light
  edition will need a slimmer agent or a UCI translator, as noted in the review
  of the architecture doc.
- Changing a `.link` (port rename) takes effect on the next boot or udev add
  event, not live.
