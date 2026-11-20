package config

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// OpenVPN (MikroTik's /interface ovpn-client and ovpn-server). Only
// routed (tun, MikroTik mode=ip) tunnels: Ethernet over a tunnel is EoIP's
// job.
const IfOpenVPN = "openvpn"

// OpenVPNServerIf is the OpenVPN server's tun interface. It starts with
// the PPP server prefix, so the "ppps" pseudo interface (LAN list,
// firewall rules, internet-only rules) covers OpenVPN clients too.
const OpenVPNServerIf = PPPServerIf + "-ovpn"

// OpenVPN defaults.
const (
	OpenVPNPort     = 1194
	OpenVPNCipher   = "AES-256-CBC"
	OpenVPNAuth     = "SHA1"
	OpenVPNSubnet   = "10.81.0.1/24"
	openVPNMaxConf  = 64 << 10
	openVPNMaxLines = 2000
)

// OpenVPNCiphers are the data ciphers a client may pin (and the server's
// fallback for clients without cipher negotiation, like RouterOS 6).
var OpenVPNCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC", "AES-192-CBC", "AES-128-CBC"}

// OpenVPNAuths are the HMAC digests of the CBC ciphers.
var OpenVPNAuths = []string{"SHA1", "SHA256", "SHA512", "MD5"}

// OpenVPNClient is an OpenVPN client connection. It is either an imported
// .ovpn file (Config) or the simple fields MikroTik's ovpn-client has.
type OpenVPNClient struct {
	// Config is a whole .ovpn client file. Script and management options
	// are refused; device, logging and routing options are replaced.
	Config string `yaml:"config,omitempty" json:"config,omitempty"`

	Server   string `yaml:"server,omitempty" json:"server,omitempty"`
	Port     int    `yaml:"port,omitempty" json:"port,omitempty"`
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"` // tcp (default) or udp
	// The server is trusted by its CA certificate or by the SHA-256
	// fingerprint of its certificate (MikroTik: /certificate print detail).
	CAPEM       string `yaml:"ca_pem,omitempty" json:"ca_pem,omitempty"`
	Fingerprint string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	// Optional client certificate (MikroTik server: require-client-certificate).
	CertPEM string `yaml:"cert_pem,omitempty" json:"cert_pem,omitempty"`
	KeyPEM  string `yaml:"key_pem,omitempty" json:"key_pem,omitempty"`
	Cipher  string `yaml:"cipher,omitempty" json:"cipher,omitempty"`
	Auth    string `yaml:"auth,omitempty" json:"auth,omitempty"`

	// Username and Password, when the server asks for them (both forms).
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
}

// PortOr returns the port with its default.
func (o *OpenVPNClient) PortOr() int {
	if o.Port == 0 {
		return OpenVPNPort
	}
	return o.Port
}

// ProtoOr returns the protocol with its default.
func (o *OpenVPNClient) ProtoOr() string {
	if o.Protocol == "" {
		return "tcp"
	}
	return o.Protocol
}

// PPPServerOpenVPN is the OpenVPN server. It authenticates the PPP
// server's users (like MikroTik's ovpn-server with /ppp secret) and has
// its own client subnet.
type PPPServerOpenVPN struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Port     int    `yaml:"port,omitempty" json:"port,omitempty"`
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"` // tcp (default) or udp
	// Address is the router's address and the client subnet
	// (default 10.81.0.1/24); it must not overlap the PPP subnet.
	Address string `yaml:"address,omitempty" json:"address,omitempty"`
	// Domain is the name clients dial (for the exported .ovpn file).
	Domain  string `yaml:"domain,omitempty" json:"domain,omitempty"`
	CertPEM string `yaml:"cert_pem" json:"cert_pem"`
	KeyPEM  string `yaml:"key_pem" json:"key_pem"`
	// Cipher is used with clients that cannot negotiate one (RouterOS 6);
	// newer clients get AES-GCM. Auth is the HMAC of CBC ciphers.
	Cipher string `yaml:"cipher,omitempty" json:"cipher,omitempty"`
	Auth   string `yaml:"auth,omitempty" json:"auth,omitempty"`
	// SplitTunnel does not send clients' internet traffic through the
	// tunnel: they only get routes to this router (and the LAN when the
	// server allows LAN access).
	SplitTunnel bool `yaml:"split_tunnel,omitempty" json:"split_tunnel,omitempty"`
}

// Defaults returns port, protocol, subnet, cipher and auth with defaults.
func (o *PPPServerOpenVPN) Defaults() (port int, proto, addr, cipher, auth string) {
	port, proto, addr, cipher, auth = o.Port, o.Protocol, o.Address, o.Cipher, o.Auth
	if port == 0 {
		port = OpenVPNPort
	}
	if proto == "" {
		proto = "tcp"
	}
	if addr == "" {
		addr = OpenVPNSubnet
	}
	if cipher == "" {
		cipher = OpenVPNCipher
	}
	if auth == "" {
		auth = OpenVPNAuth
	}
	return
}

// OpenVPNOn reports whether the OpenVPN server runs.
func (s *PPPServer) OpenVPNOn() bool {
	return s != nil && !s.Disabled && s.OpenVPN != nil && s.OpenVPN.Enabled
}

func oneOf(s string, list []string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// OpenVPN options refused in an imported .ovpn: they run programs, open
// a management port, read other files of the router or make it a server.
var ovpnRefused = map[string]bool{
	"up": true, "down": true, "route-up": true, "route-pre-down": true, "ipchange": true,
	"tls-verify": true, "tls-export-cert": true, "plugin": true, "client-connect": true,
	"client-disconnect": true, "learn-address": true, "auth-user-pass-verify": true,
	"config": true, "cd": true, "chroot": true, "iproute": true, "mode": true, "server": true,
	"server-bridge": true, "tls-server": true, "client-config-dir": true, "setenv-safe": true,
	"management": true, "management-client": true, "management-hold": true,
	"management-query-passwords": true, "management-client-auth": true,
	"management-external-key": true, "management-external-cert": true,
	"providers": true, "engine": true, "dev-node": true, "tmp-dir": true,
}

// OpenVPN options of an imported .ovpn that the router sets itself.
var ovpnReplaced = map[string]bool{
	"dev": true, "dev-type": true, "auth-user-pass": true, "auth-nocache": true,
	"script-security": true, "daemon": true, "log": true, "log-append": true, "syslog": true,
	"writepid": true, "status": true, "status-version": true, "user": true, "group": true,
	"redirect-gateway": true, "redirect-private": true, "route-noexec": true, "verb": true,
	"persist-tun": true, "askpass": true, "mute": true, "suppress-timestamps": true,
	"block-outside-dns": true, "register-dns": true, "route-nopull": true, "pull-filter": true,
	"ifconfig-noexec": true, "route-delay": true,
}

// OVPNFile is a parsed .ovpn client file.
type OVPNFile struct {
	Lines     []string // what is kept, in order
	Remote    string   // first remote host
	UserPass  bool     // the server wants a user name and password
	HasCA     bool
	HasRemote bool
}

// ParseOVPN checks an imported .ovpn client file and drops the options
// the router sets itself.
func ParseOVPN(text string) (*OVPNFile, error) {
	if len(text) > openVPNMaxConf {
		return nil, fmt.Errorf("the .ovpn file is larger than %d KB", openVPNMaxConf>>10)
	}
	f := &OVPNFile{}
	lines := strings.Split(strings.ReplaceAll(text, "\r", ""), "\n")
	if len(lines) > openVPNMaxLines {
		return nil, fmt.Errorf("the .ovpn file has more than %d lines", openVPNMaxLines)
	}
	block := ""   // inside <tag> ... </tag>
	skip := false // the block is dropped
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		if strings.ContainsRune(l, 0) {
			return nil, fmt.Errorf("line %d: NUL byte", i+1)
		}
		if block != "" {
			if strings.EqualFold(l, "</"+block+">") {
				if !skip {
					f.Lines = append(f.Lines, l)
				}
				block, skip = "", false
				continue
			}
			if block == "connection" {
				// A <connection> holds ordinary options.
				if err := ovpnOption(f, l, i+1, true); err != nil {
					return nil, err
				}
				continue
			}
			if !skip {
				f.Lines = append(f.Lines, raw)
			}
			continue
		}
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if strings.HasPrefix(l, "<") && strings.HasSuffix(l, ">") && !strings.HasPrefix(l, "</") {
			block = strings.ToLower(strings.Trim(l, "<>"))
			switch block {
			case "ca":
				f.HasCA = true
			case "auth-user-pass":
				f.UserPass, skip = true, true
				continue
			case "connection", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret",
				"extra-certs", "pkcs12", "dh", "peer-fingerprint", "http-proxy-user-pass", "crl-verify":
			default:
				return nil, fmt.Errorf("line %d: unknown inline block <%s>", i+1, block)
			}
			f.Lines = append(f.Lines, l)
			continue
		}
		if err := ovpnOption(f, l, i+1, false); err != nil {
			return nil, err
		}
	}
	if block != "" {
		return nil, fmt.Errorf("inline block <%s> is not closed", block)
	}
	if !f.HasRemote {
		return nil, fmt.Errorf("the .ovpn file has no remote (server address)")
	}
	return f, nil
}

func ovpnOption(f *OVPNFile, l string, n int, inConn bool) error {
	fields := strings.Fields(l)
	name := strings.ToLower(strings.TrimPrefix(fields[0], "--"))
	switch {
	case ovpnRefused[name] || strings.HasPrefix(name, "management"):
		return fmt.Errorf("line %d: option %q is not allowed on the router", n, name)
	case name == "dev" || name == "dev-type":
		if len(fields) > 1 && strings.HasPrefix(fields[1], "tap") {
			return fmt.Errorf("line %d: TAP (ethernet) mode is not supported; use a tun (ip mode) server, or EoIP for layer 2", n)
		}
		return nil
	case name == "auth-user-pass":
		f.UserPass = true
		return nil
	case ovpnReplaced[name]:
		return nil
	case name == "remote":
		if len(fields) < 2 || !hostOK(fields[1]) {
			return fmt.Errorf("line %d: remote needs a host name or IP address", n)
		}
		if !f.HasRemote {
			f.Remote = fields[1]
		}
		f.HasRemote = true
	case name == "ca" || name == "peer-fingerprint":
		f.HasCA = true
	}
	for _, r := range l {
		if r < 0x20 && r != '\t' {
			return fmt.Errorf("line %d: control character", n)
		}
	}
	f.Lines = append(f.Lines, l)
	_ = inConn
	return nil
}

var fingerprintLen = 32

// NormFingerprint turns a SHA-256 fingerprint (hex, with or without
// colons) into OpenVPN's AA:BB:... form, or "" when it is not one.
func NormFingerprint(s string) string {
	h := strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(s))
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != fingerprintLen {
		return ""
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{x}))
	}
	return strings.Join(parts, ":")
}

func (v *validator) openvpnClient(p string, ifc *Interface) {
	o := ifc.OpenVPN
	if o == nil {
		v.add("%s: openvpn section missing", p)
		return
	}
	if len(ifc.Addresses) > 0 || ifc.Addressing == AddrStatic || ifc.Addressing == AddrDHCP {
		v.add("%s: the server assigns the address, leave addressing empty", p)
	}
	if o.Username != "" || o.Password != "" {
		if !pppSafe(o.Username) || !pppSafe(o.Password) {
			v.add("%s: openvpn.username and password must both be set, without quotes, backslashes or control characters", p)
		}
	}
	if o.Config != "" {
		if o.Server != "" || o.CAPEM != "" || o.Fingerprint != "" || o.CertPEM != "" || o.KeyPEM != "" || o.Port != 0 || o.Protocol != "" || o.Cipher != "" || o.Auth != "" {
			v.add("%s: openvpn: use either config (a .ovpn file) or the server fields, not both", p)
		}
		f, err := ParseOVPN(o.Config)
		if err != nil {
			v.add("%s: openvpn.config: %v", p, err)
			return
		}
		if f.UserPass && o.Username == "" {
			v.add("%s: this .ovpn file asks for a user name and password", p)
		}
		if !f.HasCA {
			v.add("%s: openvpn.config has no CA certificate (<ca>) or peer-fingerprint", p)
		}
		return
	}
	if !hostOK(o.Server) {
		v.add("%s: openvpn.server must be a host name or IP address (or give a .ovpn config)", p)
	}
	if o.Port < 0 || o.Port > 65535 {
		v.add("%s: openvpn.port out of range", p)
	}
	if o.Protocol != "" && o.Protocol != "tcp" && o.Protocol != "udp" {
		v.add("%s: openvpn.protocol must be tcp or udp", p)
	}
	if o.Cipher != "" && !oneOf(o.Cipher, OpenVPNCiphers) {
		v.add("%s: openvpn.cipher must be one of %s", p, strings.Join(OpenVPNCiphers, ", "))
	}
	if o.Auth != "" && !oneOf(o.Auth, OpenVPNAuths) {
		v.add("%s: openvpn.auth must be one of %s", p, strings.Join(OpenVPNAuths, ", "))
	}
	switch {
	case o.CAPEM != "" && o.Fingerprint != "":
		v.add("%s: openvpn: give ca_pem or fingerprint, not both", p)
	case o.CAPEM != "":
		if !strings.Contains(o.CAPEM, "-----BEGIN CERTIFICATE-----") {
			v.add("%s: openvpn.ca_pem is not a PEM certificate", p)
		}
	case o.Fingerprint != "":
		if NormFingerprint(o.Fingerprint) == "" {
			v.add("%s: openvpn.fingerprint must be a SHA-256 fingerprint (64 hex digits)", p)
		}
	default:
		v.add("%s: openvpn: the server's CA certificate (ca_pem) or certificate fingerprint is required", p)
	}
	if (o.CertPEM == "") != (o.KeyPEM == "") {
		v.add("%s: openvpn: cert_pem and key_pem go together", p)
	} else if o.CertPEM != "" {
		if _, err := tls.X509KeyPair([]byte(o.CertPEM), []byte(o.KeyPEM)); err != nil {
			v.add("%s: openvpn: cert_pem/key_pem are not a valid certificate and key: %v", p, err)
		}
	}
	if o.CertPEM == "" && o.Username == "" {
		v.add("%s: openvpn: a user name and password or a client certificate is required", p)
	}
}

func (v *validator) openvpnServer(gw netip.Prefix) {
	s := v.c.PPPServer
	o := s.OpenVPN
	port, proto, addr, cipher, auth := o.Defaults()
	if port < 1 || port > 65535 {
		v.add("ppp_server.openvpn.port out of range")
	}
	if proto != "tcp" && proto != "udp" {
		v.add("ppp_server.openvpn.protocol must be tcp or udp")
	}
	ov, err := netip.ParsePrefix(addr)
	switch {
	case err != nil || !ov.Addr().Is4() || ov.Bits() < 16 || ov.Bits() > 29:
		v.add("ppp_server.openvpn.address must be an IPv4 address with a /16 to /29 subnet, like %s", OpenVPNSubnet)
	case ov.Addr() == ov.Masked().Addr():
		v.add("ppp_server.openvpn.address must be a host address, like %s", OpenVPNSubnet)
	case gw.IsValid() && ov.Overlaps(gw):
		v.add("ppp_server.openvpn.address %s overlaps the PPP subnet %s; give OpenVPN its own subnet", addr, gw.Masked())
	}
	if !oneOf(cipher, OpenVPNCiphers) {
		v.add("ppp_server.openvpn.cipher must be one of %s", strings.Join(OpenVPNCiphers, ", "))
	}
	if !oneOf(auth, OpenVPNAuths) {
		v.add("ppp_server.openvpn.auth must be one of %s", strings.Join(OpenVPNAuths, ", "))
	}
	if o.Domain != "" && !hostOK(o.Domain) {
		v.add("ppp_server.openvpn.domain %q is not a host name", o.Domain)
	}
	if _, err := tls.X509KeyPair([]byte(o.CertPEM), []byte(o.KeyPEM)); err != nil {
		v.add("ppp_server.openvpn: cert_pem/key_pem are not a valid certificate and key: %v", err)
	}
	if !o.Enabled {
		return
	}
	key := proto + "/" + strconv.Itoa(port)
	switch key {
	case "tcp/22", "tcp/53", "udp/53", "tcp/80", "tcp/443", "udp/1701", "tcp/1723", "udp/500", "udp/4500":
		v.add("ppp_server.openvpn: %s is used by the router itself", key)
	}
	if s.SSTPOn() && proto == "tcp" {
		if pub, listen := s.SSTP.Ports(); port == pub || port == listen {
			v.add("ppp_server.openvpn: TCP port %d is used by the SSTP server", port)
		}
	}
	if vs := v.c.V2RayServer; vs != nil {
		if _, vp, vl, _ := vs.Defaults(); vp == port || vl == port {
			v.add("ppp_server.openvpn: port %d is already used by the V2Ray server", port)
		}
	}
	if rz := v.c.RozanehServerFor(); rz != nil {
		if rp, rl := rz.RozanehServer.Ports(); rp == port || rl == port {
			v.add("ppp_server.openvpn: port %d is already used by the Rozaneh server", port)
		}
	}
}
