package render

import (
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strconv"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// V2Ray (sing-box) paths and units.
const (
	V2RayDir        = "/etc/mahan-router/v2ray"
	V2RayServerConf = V2RayDir + "/server.json"
	V2RayServerUnit = "mahan-v2ray-server.service"
)

// V2RayConfPath is the sing-box config of a V2Ray client interface.
func V2RayConfPath(n string) string { return path.Join(V2RayDir, n+".json") }

// V2RayClientUnit runs a V2Ray client interface.
func V2RayClientUnit(n string) string { return "mahan-v2ray-client@" + n + ".service" }

// v2rayBootstrapDNS resolves server names for sing-box itself. It must not
// be the router's Unbound: with DNS-via-tunnel that would loop through the
// tunnel that is trying to connect.
const v2rayBootstrapDNS = "1.1.1.1"

var v2rayLog = map[string]any{"level": "warn", "timestamp": true}

func renderV2Ray(c *config.Config, b Bundle) error {
	n := 0
	for i := range c.Interfaces {
		ifc := &c.Interfaces[i]
		if ifc.Type != config.IfV2Ray {
			continue
		}
		n++
		if ifc.Disabled {
			continue
		}
		out, err := config.ParseV2RayLink(ifc.V2Ray.Link)
		if err != nil {
			return fmt.Errorf("%s: %w", ifc.Name, err)
		}
		mtu := ifc.MTU
		if mtu == 0 {
			mtu = 1400
		}
		conf := map[string]any{
			"log": v2rayLog,
			"dns": map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "bootstrap", "server": v2rayBootstrapDNS}}},
			"inbounds": []any{map[string]any{
				"type": "tun", "tag": "tun-in", "interface_name": ifc.Name,
				"address": []string{fmt.Sprintf("172.19.%d.1/30", n)}, "mtu": mtu,
				// The router routes by policy; sing-box only carries packets.
				"auto_route": false, "stack": "gvisor",
			}},
			"outbounds": []any{out, map[string]any{"type": "direct", "tag": "direct"}},
			"route":     map[string]any{"final": "proxy", "default_domain_resolver": "bootstrap"},
		}
		data, _ := json.MarshalIndent(conf, "", "  ")
		b.add(V2RayConfPath(ifc.Name), CompVPN, 0o600, string(data)+"\n")
	}
	if s := c.V2RayServer; s != nil && !s.Disabled {
		proto, _, listen, target := s.Defaults()
		in := map[string]any{"tag": "in", "listen": "::", "listen_port": listen}
		users := []any{}
		switch proto {
		case config.V2RayVLESSReality:
			host, port := splitTarget(target)
			for _, u := range s.Users {
				if !u.Disabled {
					users = append(users, map[string]any{"name": u.Name, "uuid": u.Secret, "flow": "xtls-rprx-vision"})
				}
			}
			in["type"] = "vless"
			in["users"] = users
			in["tls"] = map[string]any{
				"enabled": true, "server_name": host,
				"reality": map[string]any{
					"enabled":     true,
					"handshake":   map[string]any{"server": host, "server_port": port},
					"private_key": s.RealityPrivateKey,
					"short_id":    []string{s.RealityShortID},
				},
			}
		case config.V2RayShadowsocks:
			for _, u := range s.Users {
				if !u.Disabled {
					users = append(users, map[string]any{"name": u.Name, "password": u.Secret})
				}
			}
			in["type"] = "shadowsocks"
			in["method"] = config.V2RaySSMethod
			in["password"] = s.SSKey
			in["users"] = users
		}
		route := map[string]any{"final": "direct"}
		if !s.AllowLAN {
			route["rules"] = []any{map[string]any{"ip_is_private": true, "action": "reject"}}
		}
		conf := map[string]any{
			"log": v2rayLog, "inbounds": []any{in},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": route,
		}
		data, _ := json.MarshalIndent(conf, "", "  ")
		b.add(V2RayServerConf, CompVPN, 0o600, string(data)+"\n")
	}
	return nil
}

func splitTarget(t string) (string, int) {
	host, p, err := net.SplitHostPort(t)
	if err != nil {
		return t, 443
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		port = 443
	}
	return host, port
}
