package config

import (
	"encoding/base64"
	"encoding/pem"
	"strings"
)

// IfSSH is an SSH tunnel: the router logs in to an ordinary SSH server and
// sends TCP traffic through it (sing-box TUN with an SSH outbound, the same
// engine as the V2Ray client). The server needs no VPN software, only
// AllowTcpForwarding, which is OpenSSH's default.
const IfSSH = "ssh"

// SSHPort is the default SSH server port.
const SSHPort = 22

// IsSingBoxClient reports the client tunnels run by sing-box.
func IsSingBoxClient(t string) bool { return t == IfV2Ray || t == IfSSH }

// SSHClient is the login of an SSH tunnel. Give a password, a private key,
// or both.
type SSHClient struct {
	Server   string `yaml:"server" json:"server"`
	Port     int    `yaml:"port,omitempty" json:"port,omitempty"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
	// PrivateKey is an OpenSSH or PEM private key; Passphrase unlocks it.
	PrivateKey string `yaml:"private_key,omitempty" json:"private_key,omitempty"`
	Passphrase string `yaml:"passphrase,omitempty" json:"passphrase,omitempty"`
	// HostKeys pins the server ("ssh-ed25519 AAAA..." lines). Empty means
	// any host key is accepted, like ssh with StrictHostKeyChecking=no.
	HostKeys []string `yaml:"host_keys,omitempty" json:"host_keys,omitempty"`
}

// PortOr returns the port with the default applied.
func (s *SSHClient) PortOr() int {
	if s.Port == 0 {
		return SSHPort
	}
	return s.Port
}

// Outbound is the sing-box outbound of the tunnel.
func (s *SSHClient) Outbound() map[string]any {
	out := map[string]any{"type": "ssh", "tag": "proxy", "server": s.Server, "server_port": s.PortOr(), "user": s.Username}
	if s.Password != "" {
		out["password"] = s.Password
	}
	if k := strings.TrimSpace(s.PrivateKey); k != "" {
		out["private_key"] = k + "\n"
		if s.Passphrase != "" {
			out["private_key_passphrase"] = s.Passphrase
		}
	}
	if len(s.HostKeys) > 0 {
		out["host_key"] = s.HostKeys
		// Ask only for the pinned key types: otherwise the server may
		// present another of its keys, which would not match.
		var algos []string
		seen := map[string]bool{}
		for _, k := range s.HostKeys {
			t, _, _ := strings.Cut(strings.TrimSpace(k), " ")
			if seen[t] {
				continue
			}
			seen[t] = true
			if t == "ssh-rsa" {
				algos = append(algos, "rsa-sha2-512", "rsa-sha2-256")
			}
			algos = append(algos, t)
		}
		out["host_key_algorithms"] = algos
	}
	return out
}

// SSHTargetOK checks the server name and port (1-65535 or 0 for default).
func SSHTargetOK(s *SSHClient) bool { return hostOK(s.Server) && s.Port >= 0 && s.Port <= 65535 }

// SSHHostKeyOK checks one "type base64" public key line.
func SSHHostKeyOK(k string) bool {
	f := strings.Fields(k)
	if len(f) != 2 || !(strings.HasPrefix(f[0], "ssh-") || strings.HasPrefix(f[0], "ecdsa-") || strings.HasPrefix(f[0], "sk-")) {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(f[1])
	return err == nil && len(b) >= 32
}

func (v *validator) sshClient(p string, ifc *Interface) {
	s := ifc.SSH
	if s == nil {
		v.add("%s: ssh section missing", p)
		return
	}
	if !hostOK(s.Server) {
		v.add("%s: ssh.server %q must be a host name or IP address", p, s.Server)
	}
	if s.Port < 0 || s.Port > 65535 {
		v.add("%s: ssh.port out of range", p)
	}
	if s.Username == "" || len(s.Username) > 64 || strings.ContainsAny(s.Username, " \t\r\n\x00") {
		v.add("%s: ssh.username is required and may not contain spaces", p)
	}
	if strings.ContainsAny(s.Password, "\r\n\x00") || len(s.Password) > 256 {
		v.add("%s: ssh.password may not contain line breaks", p)
	}
	key := strings.TrimSpace(s.PrivateKey)
	if s.Password == "" && key == "" {
		v.add("%s: ssh needs a password or a private key", p)
	}
	if key != "" {
		if blk, _ := pem.Decode([]byte(key + "\n")); blk == nil || !strings.HasSuffix(blk.Type, "PRIVATE KEY") {
			v.add("%s: ssh.private_key is not a private key (it starts with -----BEGIN ... PRIVATE KEY-----)", p)
		}
	}
	if s.Passphrase != "" && key == "" {
		v.add("%s: ssh.passphrase is only for a private key", p)
	}
	if len(s.HostKeys) > 8 {
		v.add("%s: ssh.host_keys: at most 8", p)
	}
	for _, k := range s.HostKeys {
		if !SSHHostKeyOK(k) {
			v.add("%s: ssh.host_keys: %q is not a public key like \"ssh-ed25519 AAAA...\"", p, k)
		}
	}
	if len(ifc.Addresses) > 0 || ifc.Addressing == AddrDHCP || ifc.Addressing == AddrStatic {
		v.add("%s: the tunnel address is internal, leave addressing empty", p)
	}
}
