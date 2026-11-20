package api

import "testing"

func TestParseKeyscan(t *testing.T) {
	out := "# vps.example.com:22 SSH-2.0-OpenSSH_9.2\n" +
		"vps.example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7m0000000000000000000000000000000\n" +
		"vps.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx5bm90dGhlcmlnaHRrZXlub3R0aGVyaWdodGtleW5v\n" +
		"garbage line\n"
	got := parseKeyscan(out)
	if len(got) != 2 || got[0] != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx5bm90dGhlcmlnaHRrZXlub3R0aGVyaWdodGtleW5v" {
		t.Errorf("%q", got)
	}
}
