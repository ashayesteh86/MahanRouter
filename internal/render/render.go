// Package render turns a validated Config into the files each service
// reads (nftables, systemd-networkd, Kea, Unbound, chrony, FRR, pppd).
//
// Rendering is pure: no file is touched and no command is run, so the same
// code drives the commit path, the preview API and the golden-file tests.
package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// Components, in the order they are applied.
const (
	CompSystem   = "system"
	CompNetwork  = "network"
	CompFirewall = "firewall"
	CompPPP      = "ppp"
	CompRouting  = "routing"
	CompDHCP     = "dhcp"
	CompDNS      = "dns"
	CompNTP      = "ntp"
)

// Order is the apply order of components.
var Order = []string{CompSystem, CompNetwork, CompFirewall, CompPPP, CompRouting, CompDHCP, CompDNS, CompNTP}

// File is one rendered file.
type File struct {
	Component string `json:"component"`
	Mode      uint32 `json:"mode"`
	Group     string `json:"group,omitempty"` // owning group, when the service does not run as root
	Content   string `json:"content"`
}

// Bundle maps absolute paths to rendered files.
type Bundle map[string]File

func (b Bundle) add(path, comp string, mode uint32, content string) {
	f := File{Component: comp, Mode: mode, Content: content}
	switch {
	case strings.HasPrefix(path, SecretsDir):
		f.Group = "systemd-network"
	case strings.HasPrefix(path, "/etc/frr/"):
		f.Group = "frr"
	}
	b[path] = f
}

// Paths returns the bundle paths sorted.
func (b Bundle) Paths() []string {
	out := make([]string, 0, len(b))
	for p := range b {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Header marks every managed file.
const Header = "Managed by Mahan Router. Do not edit: changes are overwritten on the next commit."

// Paths of well-known managed files.
const (
	NftablesFile = "/etc/nftables.d/mahan-router.nft"
	NftablesConf = "/etc/nftables.conf"
	KeaFile      = "/etc/kea/kea-dhcp4.conf"
	UnboundFile  = "/etc/unbound/unbound.conf.d/mahan-router.conf"
	ChronySrc    = "/etc/chrony/sources.d/mahan-router.sources"
	ChronyConf   = "/etc/chrony/conf.d/mahan-router.conf"
	FRRConf      = "/etc/frr/frr.conf"
	FRRDaemons   = "/etc/frr/daemons"
	SysctlFile   = "/etc/sysctl.d/90-mahan-router.conf"
	HostnameFile = "/etc/hostname"
	NetworkDir   = "/etc/systemd/network"
	SecretsDir   = "/etc/mahan-router/secrets"
	PPPPeersDir  = "/etc/ppp/peers"
)

// Render produces the full bundle for a config. The config must already
// have passed config.Validate.
func Render(c *config.Config) (Bundle, error) {
	b := Bundle{}
	renderSystem(c, b)
	if err := renderNetwork(c, b); err != nil {
		return nil, err
	}
	nft, err := Nftables(c)
	if err != nil {
		return nil, err
	}
	b.add(NftablesFile, CompFirewall, 0o644, nft)
	b.add(NftablesConf, CompFirewall, 0o755, "#!/usr/sbin/nft -f\n# "+Header+"\ninclude \"/etc/nftables.d/*.nft\"\n")
	renderPPP(c, b)
	renderFRR(c, b)
	if err := renderKea(c, b); err != nil {
		return nil, err
	}
	renderUnbound(c, b)
	renderChrony(c, b)
	return b, nil
}

func renderSystem(c *config.Config, b Bundle) {
	b.add(HostnameFile, CompSystem, 0o644, c.System.Hostname+"\n")
	fwd := 0
	if c.System.Forwarding() {
		fwd = 1
	}
	b.add(SysctlFile, CompSystem, 0o644, fmt.Sprintf(`# %s
net.ipv4.ip_forward = %d
net.ipv6.conf.all.forwarding = %d
net.ipv4.conf.all.rp_filter = 2
net.ipv4.tcp_syncookies = 1
net.netfilter.nf_conntrack_max = 262144
`, Header, fwd, fwd))
}

// quote makes a string safe inside double quotes for nft/pppd/frr.
func quote(s string) string {
	s = strings.NewReplacer(`"`, `'`, "\n", " ", "\\", "/").Replace(s)
	return `"` + s + `"`
}
