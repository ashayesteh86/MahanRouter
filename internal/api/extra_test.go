package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadLeases(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "kea-leases4.csv")
	now := time.Unix(1_800_000_000, 0)
	future, past := "1800003600", "1799990000"
	csv := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\n" +
		"192.168.88.10,aa:bb:cc:00:00:01,,3600," + future + ",1,0,0,laptop,0,\n" +
		"192.168.88.11,aa:bb:cc:00:00:02,,3600," + past + ",1,0,0,old,0,\n" +
		"192.168.88.12,aa:bb:cc:00:00:03,,3600," + future + ",1,0,0,phone,0,\n" +
		"192.168.88.12,aa:bb:cc:00:00:03,,0," + future + ",1,0,0,phone,0,\n" + // released
		"192.168.88.13,aa:bb:cc:00:00:04,,3600," + future + ",1,0,0,,0,\n"
	if err := os.WriteFile(p, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	ls, err := ReadLeases(p, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 2 || ls[0].Address != "192.168.88.10" || ls[0].Hostname != "laptop" || ls[1].Address != "192.168.88.13" {
		t.Fatalf("leases: %+v", ls)
	}
}
