package config

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"

	"gopkg.in/yaml.v3"
)

// Parse decodes a YAML document strictly (unknown keys are errors, so a
// typo never silently disables a firewall rule).
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}

// Load reads and parses a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Marshal encodes a config as YAML.
func Marshal(c *Config) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Forwarding reports whether IP forwarding is on (default true).
func (s System) Forwarding() bool { return s.IPForwarding == nil || *s.IPForwarding }

// Interface returns the interface with the given name.
func (c *Config) Interface(name string) *Interface {
	for i := range c.Interfaces {
		if c.Interfaces[i].Name == name {
			return &c.Interfaces[i]
		}
	}
	return nil
}

// DynamicLists returns address lists that rules add entries to at runtime.
func (f Firewall) DynamicLists() map[string]bool {
	out := map[string]bool{}
	for _, r := range f.Filter {
		if (r.Action == ActAddSrcList || r.Action == ActAddDstList) && r.AddressList != "" {
			out[r.AddressList] = true
		}
	}
	return out
}

// HasAddressList reports whether a list is declared or filled by a rule.
func (f Firewall) HasAddressList(name string) bool {
	if _, ok := f.AddressLists[name]; ok {
		return true
	}
	return f.DynamicLists()[name]
}

// RouteInterface returns the interface a static route is attached to:
// the explicit one, or the interface whose static subnet holds the gateway.
func (c *Config) RouteInterface(r StaticRoute) string {
	if r.Interface != "" {
		return r.Interface
	}
	gw, err := netip.ParseAddr(r.Gateway)
	if err != nil {
		return ""
	}
	for _, ifc := range c.Interfaces {
		for _, a := range ifc.Addresses {
			if pf, err := netip.ParsePrefix(a); err == nil && pf.Masked().Contains(gw) {
				return ifc.Name
			}
		}
	}
	return ""
}
