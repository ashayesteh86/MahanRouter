package api

import "testing"

func TestWGKeys(t *testing.T) {
	kp, err := NewWGKeypair(true)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := WGPublicKey(kp.PrivateKey)
	if err != nil || pub != kp.PublicKey {
		t.Fatalf("derived %q, want %q (%v)", pub, kp.PublicKey, err)
	}
	if len(kp.PresharedKey) != 44 {
		t.Fatalf("psk %q", kp.PresharedKey)
	}
	// RFC 7748 test vector (Alice).
	pub, _ = WGPublicKey("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=")
	if pub != "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=" {
		t.Fatalf("rfc7748 vector: %s", pub)
	}
}

func TestParseWGDump(t *testing.T) {
	dump := "wg0\tPRIV\tPUBSRV\t51820\toff\n" +
		"wg0\tPEER1\t(none)\t5.6.7.8:41000\t10.10.0.2/32\t1700000000\t1200\t3400\t25\n" +
		"wg0\tPEER2\t(none)\t(none)\t10.10.0.3/32,192.168.5.0/24\t0\t0\t0\toff\n"
	st := ParseWGDump([]byte(dump))
	if len(st) != 1 || st[0].ListenPort != 51820 || len(st[0].Peers) != 2 {
		t.Fatalf("%+v", st)
	}
	p := st[0].Peers
	if p[0].Endpoint != "5.6.7.8:41000" || p[0].LastHandshake != 1700000000 || p[0].RxBytes != 1200 || p[0].TxBytes != 3400 {
		t.Fatalf("%+v", p[0])
	}
	if p[1].Endpoint != "" || len(p[1].AllowedIPs) != 2 {
		t.Fatalf("%+v", p[1])
	}
}
