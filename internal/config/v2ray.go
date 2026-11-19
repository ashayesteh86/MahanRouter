package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// V2RayClient connects through a V2Ray-family server (run by sing-box).
// Link is a share link: vless://, vmess://, trojan://, ss://, hysteria2://.
type V2RayClient struct {
	Link string `yaml:"link" json:"link"`
}

// V2RayServer runs a V2Ray-family server on the router for phones and
// laptops (v2rayNG, v2rayN, Hiddify, Streisand, sing-box apps).
type V2RayServer struct {
	Disabled bool `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	// Protocol: vless_reality (default; no domain or certificate needed)
	// or shadowsocks (2022-blake3-aes-128-gcm).
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	// PublicPort is what clients dial; the router redirects it from WAN to
	// ListenPort.
	PublicPort int `yaml:"public_port,omitempty" json:"public_port,omitempty"`
	ListenPort int `yaml:"listen_port,omitempty" json:"listen_port,omitempty"`
	// Address is the host put in client links (empty: the WAN IP).
	Address string `yaml:"address,omitempty" json:"address,omitempty"`
	// Reality: the real site whose TLS handshake is borrowed.
	RealityTarget     string `yaml:"reality_target,omitempty" json:"reality_target,omitempty"` // host:port
	RealityPrivateKey string `yaml:"reality_private_key,omitempty" json:"reality_private_key,omitempty"`
	RealityShortID    string `yaml:"reality_short_id,omitempty" json:"reality_short_id,omitempty"`
	// Shadowsocks 2022 server key (base64, 16 bytes).
	SSKey string `yaml:"ss_key,omitempty" json:"ss_key,omitempty"`
	// AllowLAN lets clients reach the LAN and this router; otherwise they
	// only get the internet.
	AllowLAN bool        `yaml:"allow_lan,omitempty" json:"allow_lan,omitempty"`
	Users    []V2RayUser `yaml:"users,omitempty" json:"users,omitempty"`
}

// V2RayUser is one client. Secret is the UUID (VLESS) or the base64
// 16-byte user key (Shadowsocks 2022).
type V2RayUser struct {
	Name     string `yaml:"name" json:"name"`
	Secret   string `yaml:"secret" json:"secret"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// V2Ray server defaults.
const (
	V2RayVLESSReality  = "vless_reality"
	V2RayShadowsocks   = "shadowsocks"
	V2RayPublicPort    = 443
	V2RayListenPort    = 8444
	V2RayDefaultTarget = "www.microsoft.com:443"
	V2RaySSMethod      = "2022-blake3-aes-128-gcm"
	v2rayDefaultFlow   = "xtls-rprx-vision"
)

// Defaults returns protocol and ports with defaults applied.
func (s *V2RayServer) Defaults() (proto string, public, listen int, target string) {
	proto, public, listen, target = s.Protocol, s.PublicPort, s.ListenPort, s.RealityTarget
	if proto == "" {
		proto = V2RayVLESSReality
	}
	if public == 0 {
		public = V2RayPublicPort
	}
	if listen == 0 {
		listen = V2RayListenPort
	}
	if target == "" {
		target = V2RayDefaultTarget
	}
	return
}

var (
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	shortIDRe = regexp.MustCompile(`^[0-9a-f]{0,16}$`)
)

// RealityKeyOK reports a base64url (no padding) X25519 key, as Xray and
// sing-box write them.
func RealityKeyOK(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func ssKeyOK(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 16
}

// ParseV2RayLink turns a share link into a sing-box outbound (tag "proxy").
func ParseV2RayLink(link string) (map[string]any, error) {
	link = strings.TrimSpace(link)
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return nil, errors.New("not a share link (vless://, vmess://, trojan://, ss://, hysteria2://)")
	}
	switch strings.ToLower(scheme) {
	case "vmess":
		return parseVMess(link[len("vmess://"):])
	case "ss":
		return parseSS(link)
	}
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("link is damaged: %w", err)
	}
	host, port, err := hostPort(u.Host)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	out := map[string]any{"tag": "proxy", "server": host, "server_port": port}
	secret := u.User.Username()
	switch strings.ToLower(u.Scheme) {
	case "vless":
		if !uuidRe.MatchString(secret) {
			return nil, errors.New("vless link has no valid UUID")
		}
		out["type"] = "vless"
		out["uuid"] = secret
		if f := q.Get("flow"); f != "" {
			out["flow"] = f
		}
	case "trojan":
		if secret == "" {
			return nil, errors.New("trojan link has no password")
		}
		out["type"] = "trojan"
		out["password"] = secret
		if q.Get("security") == "" {
			q.Set("security", "tls") // trojan is always TLS
		}
	case "hysteria2", "hy2":
		pw := secret
		if p, ok := u.User.Password(); ok {
			pw += ":" + p
		}
		if pw == "" {
			return nil, errors.New("hysteria2 link has no password")
		}
		out["type"] = "hysteria2"
		out["password"] = pw
		if o := q.Get("obfs"); o != "" {
			out["obfs"] = map[string]any{"type": o, "password": q.Get("obfs-password")}
		}
		tls := map[string]any{"enabled": true, "server_name": firstNonEmpty(q.Get("sni"), host)}
		if truthy(q.Get("insecure")) {
			tls["insecure"] = true
		}
		out["tls"] = tls
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported link type %q", u.Scheme)
	}
	if err := applyTLS(out, host, q.Get("security"), q.Get("sni"), q.Get("fp"), q.Get("alpn"), q.Get("pbk"), q.Get("sid"), truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure"))); err != nil {
		return nil, err
	}
	if err := applyTransport(out, firstNonEmpty(q.Get("type"), "tcp"), q.Get("path"), q.Get("host"), q.Get("serviceName"), q.Get("headerType")); err != nil {
		return nil, err
	}
	return out, nil
}

func parseVMess(body string) (map[string]any, error) {
	raw, err := decodeB64(strings.SplitN(body, "#", 2)[0])
	if err != nil {
		return nil, errors.New("vmess link is damaged")
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, errors.New("vmess link is damaged")
	}
	s := func(k string) string {
		switch x := v[k].(type) {
		case string:
			return x
		case float64:
			return strconv.Itoa(int(x))
		}
		return ""
	}
	port, err := strconv.Atoi(s("port"))
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("vmess link has no valid port")
	}
	if s("add") == "" || !uuidRe.MatchString(s("id")) {
		return nil, errors.New("vmess link has no server or UUID")
	}
	out := map[string]any{"tag": "proxy", "type": "vmess", "server": s("add"), "server_port": port, "uuid": s("id"),
		"security": firstNonEmpty(s("scy"), "auto")}
	if aid, _ := strconv.Atoi(s("aid")); aid > 0 {
		out["alter_id"] = aid
	}
	sec := ""
	if s("tls") == "tls" {
		sec = "tls"
	}
	if err := applyTLS(out, s("add"), sec, s("sni"), s("fp"), s("alpn"), "", "", false); err != nil {
		return nil, err
	}
	if err := applyTransport(out, firstNonEmpty(s("net"), "tcp"), s("path"), s("host"), s("path"), s("type")); err != nil {
		return nil, err
	}
	return out, nil
}

// parseSS reads SIP002 (ss://base64(method:pass)@host:port, or with the
// userinfo percent-encoded for 2022 ciphers) and the legacy fully-encoded
// form ss://base64(method:pass@host:port).
func parseSS(link string) (map[string]any, error) {
	body := strings.TrimPrefix(link[strings.Index(link, "://")+3:], "")
	body = strings.SplitN(body, "#", 2)[0]
	body = strings.SplitN(body, "?", 2)[0]
	body = strings.TrimSuffix(body, "/")
	var userinfo, hp string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		userinfo, hp = body[:at], body[at+1:]
		if dec, err := decodeB64(userinfo); err == nil && strings.Contains(string(dec), ":") {
			userinfo = string(dec)
		} else if un, err := url.PathUnescape(userinfo); err == nil {
			userinfo = un
		}
	} else {
		dec, err := decodeB64(body)
		if err != nil {
			return nil, errors.New("ss link is damaged")
		}
		at := strings.LastIndex(string(dec), "@")
		if at < 0 {
			return nil, errors.New("ss link is damaged")
		}
		userinfo, hp = string(dec[:at]), string(dec[at+1:])
	}
	method, pass, ok := strings.Cut(userinfo, ":")
	if !ok || method == "" || pass == "" {
		return nil, errors.New("ss link has no method or password")
	}
	host, port, err := hostPort(hp)
	if err != nil {
		return nil, err
	}
	return map[string]any{"tag": "proxy", "type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": pass}, nil
}

func applyTLS(out map[string]any, host, security, sni, fp, alpn, pbk, sid string, insecure bool) error {
	switch security {
	case "", "none":
		return nil
	case "tls", "reality":
	default:
		return fmt.Errorf("unsupported security %q", security)
	}
	tls := map[string]any{"enabled": true, "server_name": firstNonEmpty(sni, host)}
	if insecure {
		tls["insecure"] = true
	}
	if alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if fp != "" || security == "reality" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": firstNonEmpty(fp, "chrome")}
	}
	if security == "reality" {
		if !RealityKeyOK(pbk) {
			return errors.New("reality link has no valid public key (pbk)")
		}
		r := map[string]any{"enabled": true, "public_key": pbk}
		if sid != "" {
			r["short_id"] = sid
		}
		tls["reality"] = r
	}
	out["tls"] = tls
	return nil
}

func applyTransport(out map[string]any, network, path, host, service, header string) error {
	switch network {
	case "tcp", "raw", "":
		if header == "http" {
			return errors.New("tcp with HTTP header obfuscation is not supported")
		}
		return nil
	case "ws":
		t := map[string]any{"type": "ws", "path": firstNonEmpty(path, "/")}
		if p, q, ok := strings.Cut(path, "?"); ok {
			if vals, err := url.ParseQuery(q); err == nil && vals.Get("ed") != "" {
				if ed, err := strconv.Atoi(vals.Get("ed")); err == nil {
					t["path"] = firstNonEmpty(p, "/")
					t["max_early_data"] = ed
					t["early_data_header_name"] = "Sec-WebSocket-Protocol"
				}
			}
		}
		if host != "" {
			t["headers"] = map[string]any{"Host": host}
		}
		out["transport"] = t
	case "grpc":
		out["transport"] = map[string]any{"type": "grpc", "service_name": service}
	case "httpupgrade":
		t := map[string]any{"type": "httpupgrade", "path": firstNonEmpty(path, "/")}
		if host != "" {
			t["host"] = host
		}
		out["transport"] = t
	case "http", "h2":
		t := map[string]any{"type": "http", "path": firstNonEmpty(path, "/")}
		if host != "" {
			t["host"] = strings.Split(host, ",")
		}
		out["transport"] = t
	default:
		return fmt.Errorf("transport %q is not supported (use tcp, ws, grpc, httpupgrade or h2)", network)
	}
	return nil
}

func hostPort(s string) (string, int, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, errors.New("link has no host:port")
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 || h == "" {
		return "", 0, errors.New("link has no valid host:port")
	}
	return h, port, nil
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func truthy(s string) bool { return s == "1" || strings.EqualFold(s, "true") }

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (v *validator) v2rayClient(p string, ifc *Interface) {
	if ifc.V2Ray == nil {
		v.add("%s: v2ray section missing", p)
		return
	}
	if _, err := ParseV2RayLink(ifc.V2Ray.Link); err != nil {
		v.add("%s: v2ray.link: %v", p, err)
	}
	if len(ifc.Addresses) > 0 || ifc.Addressing == AddrDHCP || ifc.Addressing == AddrStatic {
		v.add("%s: the tunnel address is internal, leave addressing empty", p)
	}
}

func (v *validator) v2rayServer() {
	s := v.c.V2RayServer
	if s == nil {
		return
	}
	proto, pub, listen, target := s.Defaults()
	switch proto {
	case V2RayVLESSReality:
		if !RealityKeyOK(s.RealityPrivateKey) {
			v.add("v2ray_server: reality_private_key is not a base64url 32-byte key")
		}
		if !shortIDRe.MatchString(s.RealityShortID) || len(s.RealityShortID)%2 != 0 {
			v.add("v2ray_server: reality_short_id must be 0-16 hex digits, even length")
		}
		if h, _, err := hostPort(target); err != nil || !domainRe.MatchString(h) {
			v.add("v2ray_server: reality_target must be a real site as host:443")
		}
	case V2RayShadowsocks:
		if !ssKeyOK(s.SSKey) {
			v.add("v2ray_server: ss_key must be a base64 16-byte key")
		}
	default:
		v.add("v2ray_server: protocol must be vless_reality or shadowsocks")
	}
	if pub < 1 || pub > 65535 || listen < 1 || listen > 65535 {
		v.add("v2ray_server: ports out of range")
	}
	switch listen {
	case 22, 53, 80, 443, RozanehListenPort:
		v.add("v2ray_server: listen_port %d is used by the router itself", listen)
	}
	if rz := v.c.RozanehServerFor(); rz != nil {
		rp, rl := rz.RozanehServer.Ports()
		if rp == pub {
			v.add("v2ray_server: public_port %d is already used by the Rozaneh server", pub)
		}
		if rl == listen {
			v.add("v2ray_server: listen_port %d is already used by the Rozaneh server", listen)
		}
	}
	names := map[string]bool{}
	secrets := map[string]bool{}
	for i, u := range s.Users {
		pp := fmt.Sprintf("v2ray_server.users[%d]", i)
		if u.Name == "" || len(u.Name) > 64 || names[u.Name] {
			v.add("%s: name must be 1-64 characters and unique", pp)
		}
		names[u.Name] = true
		ok := uuidRe.MatchString(u.Secret)
		if proto == V2RayShadowsocks {
			ok = ssKeyOK(u.Secret)
		}
		if !ok {
			v.add("%s: secret is not a valid %s", pp, map[bool]string{true: "16-byte base64 key", false: "UUID"}[proto == V2RayShadowsocks])
		}
		if secrets[u.Secret] {
			v.add("%s: secret used twice", pp)
		}
		secrets[u.Secret] = true
	}
}
