// Package apply writes a rendered bundle to disk and reloads the services
// whose files changed. It checks every file with the service's own
// validator before anything is replaced, and can put the previous bundle
// back if a reload fails.
package apply

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ashayesteh86/MahanRouter/internal/config"
	"github.com/ashayesteh86/MahanRouter/internal/render"
)

// Applier owns the managed files under Root.
type Applier struct {
	// Root is prepended to every path ("/" on a device, a temp dir in tests).
	Root string
	// StateDir holds the manifest of files we own.
	StateDir string
	// Reload runs service reload hooks. Off in lab/offline mode.
	Reload bool
	// Precheck runs nft -c / kea -t / unbound-checkconf before writing.
	Precheck bool
	// Run executes a command; replaceable in tests.
	Run func(name string, args ...string) error
	Log *slog.Logger
}

// Result describes what an apply changed.
type Result struct {
	Changed    []string `json:"changed"`    // paths written
	Removed    []string `json:"removed"`    // stale paths deleted
	Components []string `json:"components"` // components reloaded
	Warnings   []string `json:"warnings,omitempty"`
}

type manifest map[string]string // path -> sha256

func (a *Applier) manifestPath() string { return filepath.Join(a.StateDir, "manifest.json") }

func (a *Applier) loadManifest() manifest {
	m := manifest{}
	data, err := os.ReadFile(a.manifestPath())
	if err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

func (a *Applier) saveManifest(m manifest) error {
	data, _ := json.MarshalIndent(m, "", "  ")
	return writeAtomic(a.manifestPath(), data, 0o600)
}

func (a *Applier) full(p string) string { return filepath.Join(a.Root, p) }

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (a *Applier) run(name string, args ...string) error {
	if a.Run != nil {
		return a.Run(name, args...)
	}
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

// Precheck validates rendered files with each service's own checker.
// Missing tools are reported as warnings, not errors.
func (a *Applier) precheck(b render.Bundle) (warnings []string, err error) {
	tmp, err := os.MkdirTemp("", "mahan-precheck-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	checks := []struct {
		path, tool string
		args       func(string) []string
	}{
		{render.NftablesFile, "nft", func(f string) []string { return []string{"-c", "-f", f} }},
		{render.KeaFile, "kea-dhcp4", func(f string) []string { return []string{"-t", f} }},
		{render.UnboundFile, "unbound-checkconf", func(f string) []string { return []string{f} }},
		{render.FRRConf, "vtysh", func(f string) []string { return []string{"-C", "-f", f} }},
	}
	var errs []error
	if _, err := exec.LookPath("sing-box"); err == nil {
		for _, p := range b.Paths() {
			if !strings.HasPrefix(p, render.V2RayDir+"/") {
				continue
			}
			f := filepath.Join(tmp, filepath.Base(p))
			if err := os.WriteFile(f, []byte(b[p].Content), 0o600); err != nil {
				return nil, err
			}
			if out, err := exec.Command("sing-box", "check", "-c", f).CombinedOutput(); err != nil {
				errs = append(errs, fmt.Errorf("sing-box rejected %s: %s", p, bytes.TrimSpace(out)))
			}
		}
	}
	for _, c := range checks {
		f, ok := b[c.path]
		if !ok {
			continue
		}
		if _, err := exec.LookPath(c.tool); err != nil {
			warnings = append(warnings, c.tool+" not installed, "+c.path+" not prechecked")
			continue
		}
		p := filepath.Join(tmp, filepath.Base(c.path))
		if c.tool == "kea-dhcp4" {
			// Kea's AppArmor profile only lets it read /etc/kea.
			if st, err := os.Stat("/etc/kea"); err == nil && st.IsDir() {
				p = fmt.Sprintf("/etc/kea/.mr-precheck-%d.conf", os.Getpid())
				defer os.Remove(p)
			}
		}
		content := f.Content
		if c.tool == "kea-dhcp4" {
			content = render.KeaCheckVariant(content)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			return nil, err
		}
		out, err := exec.Command(c.tool, c.args(p)...).CombinedOutput()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s rejected %s: %s", c.tool, c.path, bytes.TrimSpace(out)))
		}
	}
	return warnings, errors.Join(errs...)
}

// Apply writes the bundle and reloads changed components.
func (a *Applier) Apply(c *config.Config, b render.Bundle) (*Result, error) {
	res := &Result{}
	if a.Precheck {
		w, err := a.precheck(b)
		res.Warnings = append(res.Warnings, w...)
		if err != nil {
			return res, err
		}
	}
	old := a.loadManifest()
	changedComp := map[string]bool{}
	var changedNetdevs []string
	// oldNetdev keeps a replaced or removed netdev file's previous content:
	// an L2TP tunnel is deleted by its tunnel ID, not by a link name.
	oldNetdev := map[string]string{}
	newM := manifest{}
	for _, p := range b.Paths() {
		f := b[p]
		h := sum(f.Content)
		newM[p] = h
		cur, err := os.ReadFile(a.full(p))
		if err == nil && sum(string(cur)) == h {
			continue
		}
		if err == nil && strings.HasSuffix(p, ".netdev") {
			oldNetdev[p] = string(cur)
		}
		if err := writeAtomic(a.full(p), []byte(f.Content), os.FileMode(f.Mode)); err != nil {
			return res, fmt.Errorf("write %s: %w", p, err)
		}
		if f.Group != "" {
			// e.g. WireGuard keys root:systemd-network, frr.conf root:frr.
			if g, err := user.LookupGroup(f.Group); err == nil {
				gid, _ := strconv.Atoi(g.Gid)
				_ = os.Chown(a.full(p), 0, gid)
			}
		}
		res.Changed = append(res.Changed, p)
		changedComp[f.Component] = true
		if strings.HasSuffix(p, ".netdev") {
			changedNetdevs = append(changedNetdevs, p)
		}
	}
	for p := range old {
		if _, still := newM[p]; still {
			continue
		}
		if cur, err := os.ReadFile(a.full(p)); err == nil && strings.HasSuffix(p, ".netdev") {
			oldNetdev[p] = string(cur)
		}
		if err := os.Remove(a.full(p)); err != nil && !os.IsNotExist(err) {
			return res, fmt.Errorf("remove %s: %w", p, err)
		}
		res.Removed = append(res.Removed, p)
		changedComp[componentOf(p)] = true
		if strings.HasSuffix(p, ".netdev") {
			changedNetdevs = append(changedNetdevs, p)
		}
	}
	sort.Strings(res.Removed)
	if err := a.saveManifest(newM); err != nil {
		return res, err
	}
	for _, comp := range render.Order {
		if changedComp[comp] {
			res.Components = append(res.Components, comp)
		}
	}
	if !a.Reload {
		return res, nil
	}
	var errs []error
	touched := map[string]bool{}
	for _, p := range append(append([]string{}, res.Changed...), res.Removed...) {
		touched[p] = true
	}
	for _, comp := range res.Components {
		var err error
		switch comp {
		case render.CompVPN:
			err = a.reloadVPN(c, touched)
		case render.CompPPP:
			err = a.reloadPPP(c, touched)
		default:
			err = a.reload(c, comp, changedNetdevs, oldNetdev)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", comp, err))
		}
	}
	return res, errors.Join(errs...)
}

func componentOf(p string) string {
	switch {
	case strings.HasPrefix(p, render.NetworkDir), strings.HasPrefix(p, render.SecretsDir):
		return render.CompNetwork
	case strings.HasPrefix(p, render.RozanehDir), strings.HasPrefix(p, render.V2RayDir):
		return render.CompVPN
	case strings.HasPrefix(p, "/etc/ppp"), strings.HasPrefix(p, "/etc/xl2tpd"):
		return render.CompPPP
	case strings.HasPrefix(p, "/etc/swanctl"):
		return render.CompIPsec
	case strings.HasPrefix(p, render.AccelDir):
		return render.CompPPPServer
	case strings.HasPrefix(p, "/etc/nftables"):
		return render.CompFirewall
	case strings.HasPrefix(p, "/etc/frr"):
		return render.CompRouting
	case strings.HasPrefix(p, "/etc/kea"):
		return render.CompDHCP
	case strings.HasPrefix(p, "/etc/unbound"):
		return render.CompDNS
	case strings.HasPrefix(p, "/etc/chrony"):
		return render.CompNTP
	}
	return render.CompSystem
}

func (a *Applier) svc(enable bool, unit string) error {
	if enable {
		if err := a.run("systemctl", "enable", "--quiet", unit); err != nil {
			return err
		}
		return a.run("systemctl", "restart", unit)
	}
	_ = a.run("systemctl", "disable", "--quiet", "--now", unit)
	return nil
}

func (a *Applier) reload(c *config.Config, comp string, netdevs []string, oldNetdev map[string]string) error {
	switch comp {
	case render.CompSystem:
		if err := a.run("hostname", c.System.Hostname); err != nil {
			return err
		}
		if c.System.Timezone != "" {
			if err := a.run("timedatectl", "set-timezone", c.System.Timezone); err != nil {
				return err
			}
		}
		return a.run("sysctl", "-q", "-p", a.full(render.SysctlFile))
	case render.CompNetwork:
		// networkd does not change an existing netdev when its file
		// changes; delete it so the reload recreates it.
		restart := false
		for _, p := range netdevs {
			if id := l2tpTunnelID(oldNetdev[p]); id != "" {
				// Deleting the tunnel deletes its session interface too.
				// networkd does not notice a deleted L2TP tunnel, so it
				// only creates it again after a restart.
				_ = a.run("ip", "l2tp", "del", "tunnel", "tunnel_id", id)
				restart = true
				continue
			}
			name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), "20-mr-"), ".netdev")
			_ = a.run("ip", "link", "delete", name)
		}
		_ = a.run("udevadm", "control", "--reload")
		a.EnsureLinkNames(c)
		if restart {
			return a.run("systemctl", "restart", "systemd-networkd")
		}
		return a.run("networkctl", "reload")
	case render.CompFirewall:
		return a.run("nft", "-f", a.full(render.NftablesFile))
	case render.CompIPsec:
		on := false
		for _, ifc := range c.Interfaces {
			on = on || (ifc.Type == config.IfL2TP && ifc.PPP != nil && ifc.PPP.IPsecSecret != "" && !ifc.Disabled)
		}
		on = on || (c.PPPServer.L2TPOn() && c.PPPServer.L2TP.IPsecSecret != "")
		// A restart, not swanctl --load-all: loading leaves the SAs of
		// removed or changed connections up, and a new connection to the
		// same peer then reuses the stale IKE SA.
		return a.svc(on, render.IPsecUnit)
	case render.CompPPPServer:
		return a.svc(c.PPPServer.Running(), render.PPPServerUnit)
	case render.CompRouting:
		return a.svc(render.RoutingEnabled(c), "frr.service")
	case render.CompDHCP:
		on := false
		for _, d := range c.DHCPServers {
			on = on || !d.Disabled
		}
		return a.svc(on, "kea-dhcp4-server.service")
	case render.CompDNS:
		return a.svc(c.DNS.Enabled, "unbound.service")
	case render.CompNTP:
		return a.svc(true, "chrony.service")
	}
	return nil
}

// l2tpTunnelID returns TunnelId= of an L2TP netdev file, or "".
func l2tpTunnelID(netdev string) string {
	if !strings.Contains(netdev, "Kind=l2tp") {
		return ""
	}
	for _, l := range strings.Split(netdev, "\n") {
		if v, ok := strings.CutPrefix(l, "TunnelId="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// reloadPPP restarts the pppd units (PPPoE, PPTP, SSTP) and xl2tpd (L2TP)
// whose files or secrets changed, and stops those of removed interfaces.
func (a *Applier) reloadPPP(c *config.Config, touched map[string]bool) error {
	var errs []error
	secrets := touched["/etc/ppp/chap-secrets"]
	l2tpOn, l2tpChanged := false, secrets || touched[render.XL2TPDConf]
	want := map[string]bool{}
	for _, ifc := range c.Interfaces {
		var unit string
		switch {
		case ifc.Type == config.IfPPPoE:
			unit = render.PPPoEUnit(ifc.Name)
		case ifc.Type == config.IfPPTP || ifc.Type == config.IfSSTP:
			unit = render.PPPClientUnit(ifc.Name)
		case ifc.Type == config.IfL2TP:
			l2tpOn = l2tpOn || !ifc.Disabled
			l2tpChanged = l2tpChanged || touched[render.L2TPOptionsFile(ifc.Name)]
			continue
		default:
			continue
		}
		if ifc.Disabled {
			_ = a.svc(false, unit)
			continue
		}
		want[unit] = true
		if secrets || touched[render.PPPPeerFile(ifc.Name)] {
			errs = append(errs, a.svc(true, unit))
		}
	}
	for p := range touched {
		if strings.HasSuffix(p, ".l2tp") {
			l2tpChanged = true
		}
		if name, ok := strings.CutPrefix(p, render.PPPPeerFile("")); ok {
			for _, unit := range []string{render.PPPoEUnit(name), render.PPPClientUnit(name)} {
				if !want[unit] {
					_ = a.svc(false, unit)
				}
			}
		}
	}
	if l2tpChanged {
		errs = append(errs, a.svc(l2tpOn, render.XL2TPDUnit))
	}
	return errors.Join(errs...)
}

// reloadVPN restarts the Rozaneh units whose files changed and stops those
// whose interface is gone or disabled.
func (a *Applier) reloadVPN(c *config.Config, touched map[string]bool) error {
	var errs []error
	want := map[string]bool{}
	for i := range c.Interfaces {
		ifc := &c.Interfaces[i]
		var unit, prefix string
		switch ifc.Type {
		case config.IfRozaneh, config.IfRozanehServer:
			unit, prefix = render.RozanehUnit(ifc), render.RozanehDir+"/"+ifc.Name+"."
		case config.IfV2Ray:
			unit, prefix = render.V2RayClientUnit(ifc.Name), render.V2RayDir+"/"+ifc.Name+"."
		default:
			continue
		}
		if ifc.Disabled {
			_ = a.svc(false, unit)
			continue
		}
		want[unit] = true
		changed := false
		for p := range touched {
			if strings.HasPrefix(p, prefix) {
				changed = true
			}
		}
		if changed {
			errs = append(errs, a.svc(true, unit))
		}
	}
	srv := c.V2RayServer != nil && !c.V2RayServer.Disabled
	if touched[render.V2RayServerConf] {
		errs = append(errs, a.svc(srv, render.V2RayServerUnit))
	}
	want[render.V2RayServerUnit] = srv
	// Units of interfaces that no longer exist (or changed type).
	for p := range touched {
		if !strings.HasSuffix(p, ".json") || p == render.V2RayServerConf {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(p), ".json")
		var units []string
		switch {
		case strings.HasPrefix(p, render.RozanehDir+"/"):
			units = []string{render.RozanehClientUnit(name), render.RozanehServerUnit(name)}
		case strings.HasPrefix(p, render.V2RayDir+"/"):
			units = []string{render.V2RayClientUnit(name)}
		}
		for _, unit := range units {
			if !want[unit] {
				_ = a.svc(false, unit)
			}
		}
	}
	return errors.Join(errs...)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mr-tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
