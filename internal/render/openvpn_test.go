package render

import (
	"strings"
	"testing"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

const testOVPN = `# provider file
client
dev tun
proto udp
remote vpn.example.net 1194
remote-cert-tls server
auth-user-pass
redirect-gateway def1
verb 4
<ca>
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</ca>
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
00ff
-----END OpenVPN Static key V1-----
</tls-crypt>
`

func ovpnConfig(t *testing.T) *config.Config {
	c := loadExample(t, "factory-default.yaml")
	c.Interfaces = append(c.Interfaces,
		config.Interface{Name: "ovpn-out1", Type: config.IfOpenVPN, OpenVPN: &config.OpenVPNClient{
			Server: "mt.example.com", Port: 1195, CAPEM: testCert, Username: "ali", Password: "p w"}},
		config.Interface{Name: "ovpn-out2", Type: config.IfOpenVPN, OpenVPN: &config.OpenVPNClient{
			Server: "198.51.100.4", Protocol: "udp", Fingerprint: strings.Repeat("ab", 32), Cipher: "AES-128-GCM", Auth: "SHA256", CertPEM: testCert, KeyPEM: testKey}},
		config.Interface{Name: "ovpn-imp", Type: config.IfOpenVPN, OpenVPN: &config.OpenVPNClient{Config: testOVPN, Username: "u", Password: "p"}},
	)
	c.PPPServer = &config.PPPServer{
		Address:  "10.80.0.1/24",
		AllowLAN: true,
		OpenVPN:  &config.PPPServerOpenVPN{Enabled: true, CertPEM: testCert, KeyPEM: testKey},
		Users:    []config.PPPUser{{Name: "phone", Password: "s3cret"}, {Name: "old", Password: "q", Disabled: true}},
	}
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOpenVPNRender(t *testing.T) {
	c := ovpnConfig(t)
	b, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		OpenVPNConfPath("ovpn-out1"): {"client\n", "remote mt.example.com 1195\nproto tcp-client\n", "data-ciphers-fallback AES-256-CBC", "auth SHA1", "<ca>\n-----BEGIN CERTIFICATE-----",
			"dev ovpn-out1\ndev-type tun\n", "route-noexec", `pull-filter ignore "redirect-gateway"`, "auth-user-pass " + OpenVPNAuthPath("ovpn-out1")},
		OpenVPNAuthPath("ovpn-out1"): {"ali\np w\n"},
		OpenVPNConfPath("ovpn-out2"): {"proto udp\nnobind\n", "data-ciphers AES-128-GCM:AES-256-GCM:", "data-ciphers-fallback AES-128-GCM", "auth SHA256",
			"peer-fingerprint AB:AB:", "<cert>", "<key>"},
		OpenVPNConfPath("ovpn-imp"): {"remote vpn.example.net 1194", "<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----\n00ff\n", "remote-cert-tls server", "dev ovpn-imp"},
		OpenVPNConfPath(config.OpenVPNServerIf): {"mode server\ntls-server\ndev ppps-ovpn\n", "proto tcp-server\nport 1194\n",
			"ifconfig 10.81.0.1 255.255.255.0\nifconfig-pool 10.81.0.2 10.81.0.254 255.255.255.0\n",
			`push "redirect-gateway def1 bypass-dhcp"`, `push "dhcp-option DNS 1.1.1.1"`, "data-ciphers-fallback AES-256-CBC", "<dh>",
			"verify-client-cert none", `auth-user-pass-verify "/usr/sbin/mrctl ovpn-auth /etc/mahan-router/openvpn/ppps-ovpn.users" via-file`,
			"management " + OpenVPNMgmt + " unix"},
		OpenVPNUsers:             {`"phone": "s3cret"`},
		networkPath("ovpn-out1"): {"KeepConfiguration=yes"},
	}
	for p, subs := range want {
		f, ok := b[p]
		if !ok {
			t.Errorf("%s not rendered", p)
			continue
		}
		for _, s := range subs {
			if !strings.Contains(f.Content, s) {
				t.Errorf("%s: missing %q in\n%s", p, s, f.Content)
			}
		}
	}
	imp := b[OpenVPNConfPath("ovpn-imp")].Content
	for _, bad := range []string{"redirect-gateway def1", "verb 4", "dev tun\n", "\nauth-user-pass\n"} {
		if strings.Contains(imp, bad) {
			t.Errorf("imported config keeps %q:\n%s", bad, imp)
		}
	}
	if strings.Contains(b[OpenVPNUsers].Content, "old") {
		t.Error("disabled user can log in")
	}
	if b[OpenVPNConfPath("ovpn-out1")].Mode != 0o600 || b[OpenVPNUsers].Mode != 0o600 {
		t.Error("secrets must be 0600")
	}
	if _, ok := b[OpenVPNAuthPath("ovpn-out2")]; ok {
		t.Error("certificate-only client got an auth file")
	}
	// The PPP server is not started for OpenVPN alone.
	if c.PPPServer.Running() || !c.PPPServer.OpenVPNOn() {
		t.Error("Running/OpenVPNOn")
	}

	// Split tunnel with LAN access pushes the LAN instead of the default route.
	c.PPPServer.OpenVPN.SplitTunnel = true
	c.PPPServer.OpenVPN.Address = "10.81.0.130/25"
	b, _ = Render(c)
	srv := b[OpenVPNConfPath(config.OpenVPNServerIf)].Content
	if strings.Contains(srv, "redirect-gateway") || !strings.Contains(srv, `push "route 192.168.88.0 255.255.255.0"`) {
		t.Errorf("split tunnel:\n%s", srv)
	}
	if !strings.Contains(srv, "ifconfig-pool 10.81.0.131 10.81.0.254 255.255.255.128") {
		t.Errorf("pool:\n%s", srv)
	}
}

func TestOpenVPNValidate(t *testing.T) {
	bad := []func(c *config.Config){
		func(c *config.Config) { c.Interface("ovpn-out1").OpenVPN.CAPEM = "" },
		func(c *config.Config) { c.Interface("ovpn-out1").OpenVPN.Fingerprint = "abcd" },
		func(c *config.Config) { c.Interface("ovpn-out1").OpenVPN.Protocol = "sctp" },
		func(c *config.Config) { c.Interface("ovpn-out1").OpenVPN.Cipher = "BF-CBC" },
		func(c *config.Config) { c.Interface("ovpn-out1").OpenVPN.Password = "" },
		func(c *config.Config) { c.Interface("ovpn-out1").OpenVPN.Password = "a\"b" },
		func(c *config.Config) { c.Interface("ovpn-out2").OpenVPN.KeyPEM = "" },
		func(c *config.Config) { c.Interface("ovpn-imp").OpenVPN.Username = ""; c.Interface("ovpn-imp").OpenVPN.Password = "" },
		func(c *config.Config) { c.Interface("ovpn-imp").OpenVPN.Server = "x.example.com" },
		func(c *config.Config) { c.Interface("ovpn-imp").OpenVPN.Config += "up /tmp/x.sh\n" },
		func(c *config.Config) { c.Interface("ovpn-imp").OpenVPN.Config += "plugin /tmp/x.so\n" },
		func(c *config.Config) { c.Interface("ovpn-imp").OpenVPN.Config += "management 0.0.0.0 7505\n" },
		func(c *config.Config) { c.Interface("ovpn-imp").OpenVPN.Config += "dev tap0\n" },
		func(c *config.Config) { c.Interface("ovpn-imp").OpenVPN.Config += "<foo>\nbar\n</foo>\n" },
		func(c *config.Config) { c.Interface("ovpn-imp").OpenVPN.Config += "<connection>\nremote a.example.com\nup /x\n</connection>\n" },
		func(c *config.Config) { c.Interface("ovpn-imp").OpenVPN.Config = "client\n<ca>\nx\n</ca>\n" },
		func(c *config.Config) { c.Interface("ovpn-imp").OpenVPN.Config = strings.Replace(testOVPN, "</ca>", "", 1) },
		func(c *config.Config) { c.Interface("ovpn-out1").Addressing = config.AddrStatic },
		func(c *config.Config) { c.PPPServer.OpenVPN.Address = "10.80.0.200/24" },
		func(c *config.Config) { c.PPPServer.OpenVPN.Address = "10.81.0.0/24" },
		func(c *config.Config) { c.PPPServer.OpenVPN.Port = 443 },
		func(c *config.Config) { c.PPPServer.OpenVPN.Protocol = "udp"; c.PPPServer.OpenVPN.Port = 500 },
		func(c *config.Config) { c.PPPServer.OpenVPN.KeyPEM = "" },
		func(c *config.Config) { c.PPPServer.OpenVPN.Auth = "SHA3" },
		func(c *config.Config) {
			c.PPPServer.SSTP = &config.PPPServerSSTP{Enabled: true, CertPEM: testCert, KeyPEM: testKey, PublicPort: 1194, ListenPort: 8445}
		},
		// the server's interface name is reserved
		func(c *config.Config) { c.Interface("ovpn-out1").Name = config.OpenVPNServerIf },
	}
	for i, f := range bad {
		c := ovpnConfig(t)
		f(c)
		if err := config.Validate(c); err == nil {
			t.Errorf("case %d: expected a validation error", i)
		}
	}
	// A .ovpn with a <connection> list and a key file passes.
	c := ovpnConfig(t)
	c.Interface("ovpn-imp").OpenVPN.Config = testOVPN + "<connection>\nremote b.example.com 443 tcp\n</connection>\n"
	if err := config.Validate(c); err != nil {
		t.Error(err)
	}
	if config.NormFingerprint("AB:"+strings.Repeat("cd:", 30)+"EF") != "AB:"+strings.Repeat("CD:", 30)+"EF" {
		t.Error("fingerprint form")
	}
}
