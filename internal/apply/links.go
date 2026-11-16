package apply

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ashayesteh86/MahanRouter/internal/config"
)

// sysNet is the sysfs directory of network interfaces (replaced in tests).
var sysNet = "/sys/class/net"

func readSys(dev, attr string) string {
	b, err := os.ReadFile(filepath.Join(sysNet, dev, attr))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// permAddr returns the permanent MAC of a device. Bond/bridge members can
// have their current MAC changed, so prefer the permanent one.
func (a *Applier) permAddr(dev string) string {
	// addr_assign_type 0 = permanent address in use.
	if readSys(dev, "addr_assign_type") == "0" || readSys(dev, "addr_assign_type") == "" {
		return strings.ToLower(readSys(dev, "address"))
	}
	if out, err := runOut("ethtool", "-P", dev); err == nil {
		if f := strings.Fields(out); len(f) > 0 {
			return strings.ToLower(f[len(f)-1])
		}
	}
	return strings.ToLower(readSys(dev, "address"))
}

// EnsureLinkNames renames physical ports to their configured names now,
// instead of waiting for the .link files to apply on the next boot.
// A port being renamed is taken down briefly (the kernel requires it).
func (a *Applier) EnsureLinkNames(c *config.Config) []string {
	entries, err := os.ReadDir(sysNet)
	if err != nil {
		return nil
	}
	byMAC := map[string]string{}
	exists := map[string]bool{}
	for _, e := range entries {
		dev := e.Name()
		exists[dev] = true
		if _, err := os.Stat(filepath.Join(sysNet, dev, "device")); err != nil {
			continue // virtual
		}
		byMAC[a.permAddr(dev)] = dev
	}
	var renamed []string
	for _, ifc := range c.Interfaces {
		if ifc.Type != config.IfEthernet || exists[ifc.Name] {
			continue
		}
		cur := ""
		if ifc.MAC != "" {
			cur = byMAC[strings.ToLower(ifc.MAC)]
		} else if exists[ifc.MatchDevice] {
			cur = ifc.MatchDevice
		}
		if cur == "" || cur == ifc.Name {
			continue
		}
		_ = a.run("ip", "link", "set", "dev", cur, "down")
		if err := a.run("ip", "link", "set", "dev", cur, "name", ifc.Name); err != nil {
			if a.Log != nil {
				a.Log.Warn("rename failed", "from", cur, "to", ifc.Name, "err", err)
			}
			continue
		}
		_ = a.run("ip", "link", "set", "dev", ifc.Name, "up")
		renamed = append(renamed, cur+"->"+ifc.Name)
		exists[ifc.Name] = true
	}
	return renamed
}

func runOut(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

// BootLinks is called once at agent start: rename ports and, if any were
// renamed, let networkd pick up the new names.
func (a *Applier) BootLinks(c *config.Config) []string {
	if !a.Reload {
		return nil
	}
	r := a.EnsureLinkNames(c)
	if len(r) > 0 {
		_ = a.run("networkctl", "reload")
	}
	return r
}
