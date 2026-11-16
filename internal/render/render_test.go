package render

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

func loadExample(t *testing.T, name string) *config.Config {
	t.Helper()
	c, err := config.Load(filepath.Join("..", "..", "examples", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func renderExample(t *testing.T, name string) Bundle {
	b, err := Render(loadExample(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeTemp(t *testing.T, content string) string {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// checkTool runs a service's own config checker when it is installed.
func checkTool(t *testing.T, tool string, args ...string) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("%s not installed", tool)
	}
	out, err := exec.Command(tool, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", tool, args, err, out)
	}
}

func TestExamplesRender(t *testing.T) {
	for _, ex := range []string{"branch-office.yaml", "factory-default.yaml"} {
		t.Run(ex, func(t *testing.T) {
			b := renderExample(t, ex)
			for _, p := range []string{NftablesFile, KeaFile, UnboundFile, FRRConf, HostnameFile} {
				if _, ok := b[p]; !ok {
					t.Errorf("missing %s", p)
				}
			}
		})
	}
}

func TestNftablesSyntax(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nft -c needs root")
	}
	for _, ex := range []string{"branch-office.yaml", "factory-default.yaml"} {
		b := renderExample(t, ex)
		checkTool(t, "nft", "-c", "-f", writeTemp(t, b[NftablesFile].Content))
	}
}

func TestKeaSyntax(t *testing.T) {
	b := renderExample(t, "branch-office.yaml")
	// Kea's AppArmor profile only lets it read /etc/kea.
	p := "/etc/kea/.mr-test.conf"
	if err := os.WriteFile(p, []byte(KeaCheckVariant(b[KeaFile].Content)), 0o600); err != nil {
		t.Skip("cannot write to /etc/kea:", err)
	}
	defer os.Remove(p)
	checkTool(t, "kea-dhcp4", "-t", p)
}

func TestUnboundSyntax(t *testing.T) {
	b := renderExample(t, "branch-office.yaml")
	checkTool(t, "unbound-checkconf", writeTemp(t, b[UnboundFile].Content))
}

func TestNftRules(t *testing.T) {
	b := renderExample(t, "branch-office.yaml")
	nft := b[NftablesFile].Content
	for _, want := range []string{
		`iifname { "pppoe-out1", "ether2" } meta nfproto ipv4 tcp dport 8443 counter dnat ip to 192.168.10.20:443`,
		`ip saddr @al_blocked_v4 counter drop`,
		`ip6 saddr @al_blocked_v6 counter drop`,
		`add @al_ssh_scanners_v4 { ip saddr timeout 3600s }`,
		`iifname != { "bridge-lan", "vlan20", "wg-hq" } counter log prefix`,
		`ct status & dnat == 0`,
		`oifname { "pppoe-out1", "ether2" } counter masquerade`,
		`tcp dport { 22, 443 }`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("nft ruleset lacks %q", want)
		}
	}
	if t.Failed() {
		t.Log(nft)
	}
}

func TestNetworkd(t *testing.T) {
	b := renderExample(t, "branch-office.yaml")
	want := map[string][]string{
		"/etc/systemd/network/10-mr-ether1.link":        {"PermanentMACAddress=52:54:00:00:00:01", "Name=ether1"},
		"/etc/systemd/network/30-mr-ether3.network":     {"Bridge=bridge-lan"},
		"/etc/systemd/network/30-mr-bridge-lan.network": {"Address=192.168.10.1/24", "VLAN=vlan20"},
		"/etc/systemd/network/20-mr-vlan20.netdev":      {"Kind=vlan", "Id=20"},
		"/etc/systemd/network/20-mr-wg-hq.netdev":       {"PrivateKeyFile=/etc/mahan-router/secrets/wg-hq.key", "RouteTable=main", "Endpoint=hq.example.com:51820"},
		"/etc/systemd/network/30-mr-wg-hq.network":      {"Destination=10.0.0.0/16", "Gateway=10.255.0.1"},
		"/etc/systemd/network/30-mr-ether2.network":     {"DHCP=ipv4", "RouteMetric=200", "UseDNS=no"},
		"/etc/systemd/network/30-mr-pppoe-out1.network": {"[CAKE]", "Bandwidth=95M"},
		"/etc/systemd/network/30-mr-lo-routes.network":  {"Type=blackhole"},
		"/etc/ppp/peers/mr-pppoe-out1":                  {"nic-ether1", "ifname pppoe-out1", "defaultroute"},
	}
	for path, subs := range want {
		f, ok := b[path]
		if !ok {
			t.Errorf("missing %s", path)
			continue
		}
		for _, s := range subs {
			if !strings.Contains(f.Content, s) {
				t.Errorf("%s lacks %q:\n%s", path, s, f.Content)
			}
		}
	}
	if b[WGKeyPath("wg-hq")].Mode != 0o640 {
		t.Error("wireguard key must not be world readable")
	}
}
