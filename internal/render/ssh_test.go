package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

const testSSHHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx5bm90dGhlcmlnaHRrZXlub3R0aGVyaWdodGtleW5v"

func TestSSHTunnel(t *testing.T) {
	c := loadExample(t, "factory-default.yaml")
	c.Interfaces = append(c.Interfaces,
		config.Interface{Name: "ssh1", Type: config.IfSSH, SSH: &config.SSHClient{
			Server: "vps.example.com", Port: 2222, Username: "tunnel", Password: "p w", HostKeys: []string{testSSHHostKey}}},
		config.Interface{Name: "ssh2", Type: config.IfSSH, Disabled: true, SSH: &config.SSHClient{
			Server: "198.51.100.4", Username: "root", PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"}},
	)
	c.InterfaceLists["WAN"] = append(c.InterfaceLists["WAN"], "ssh1")
	c.PolicyRoutes = []config.PolicyRoute{{Interface: "ssh1", From: config.PolicyFromLAN, DNSViaTunnel: true}}
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	b, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b[V2RayConfPath("ssh2")]; ok {
		t.Error("a disabled tunnel must have no config file")
	}
	f, ok := b[V2RayConfPath("ssh1")]
	if !ok {
		t.Fatal("no sing-box config for ssh1")
	}
	var conf struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
		DNS struct {
			Final string `json:"final"`
		} `json:"dns"`
	}
	if err := json.Unmarshal([]byte(f.Content), &conf); err != nil {
		t.Fatal(err)
	}
	o := conf.Outbounds[0]
	if o["type"] != "ssh" || o["server"] != "vps.example.com" || o["server_port"] != float64(2222) || o["user"] != "tunnel" || o["password"] != "p w" {
		t.Errorf("outbound: %v", o)
	}
	if a, _ := json.Marshal(o["host_key_algorithms"]); string(a) != `["ssh-ed25519"]` {
		t.Errorf("host_key_algorithms: %s", a)
	}
	if conf.Inbounds[0]["interface_name"] != "ssh1" || conf.DNS.Final != "tunnel" {
		t.Errorf("inbound %v, dns final %q", conf.Inbounds[0], conf.DNS.Final)
	}
	// DNS is answered over the tunnel; every other UDP packet is refused.
	if len(conf.Route.Rules) != 2 || conf.Route.Rules[0]["action"] != "hijack-dns" || conf.Route.Rules[1]["network"] != "udp" || conf.Route.Rules[1]["action"] != "reject" {
		t.Errorf("route rules: %v", conf.Route.Rules)
	}
	if f.Mode != 0o600 {
		t.Errorf("mode %o: the file holds the password", f.Mode)
	}
}

func TestSSHTunnelValidation(t *testing.T) {
	bad := map[string]config.SSHClient{
		"password or a private key": {Server: "a.example.com", Username: "u"},
		"ssh.server":                {Server: "-oProxyCommand=x", Username: "u", Password: "p"},
		"ssh.username":              {Server: "a.example.com", Username: "a b", Password: "p"},
		"not a private key":         {Server: "a.example.com", Username: "u", PrivateKey: "ssh-ed25519 AAAA"},
		"ssh.host_keys":             {Server: "a.example.com", Username: "u", Password: "p", HostKeys: []string{"a.example.com ssh-ed25519 AAAA"}},
	}
	for want, s := range bad {
		c := loadExample(t, "factory-default.yaml")
		s := s
		c.Interfaces = append(c.Interfaces, config.Interface{Name: "ssh1", Type: config.IfSSH, SSH: &s})
		if err := config.Validate(c); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want error with %q, got %v", want, err)
		}
	}
}
