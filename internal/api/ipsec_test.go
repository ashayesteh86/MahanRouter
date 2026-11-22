package api

import "testing"

func TestIPsecStates(t *testing.T) {
	raw := `list-sa event {mr-s2s-hq {uniqueid=3 version=2 state=ESTABLISHED local-host=198.51.100.7 local-port=4500 local-id=198.51.100.7 remote-host=203.0.113.10 remote-port=4500 remote-id=203.0.113.10 initiator=yes nat-local=yes encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 prf-alg=PRF_HMAC_SHA2_256 dh-group=MODP_2048 established=75 rekey-time=13000 child-sas {mr-s2s-hq-1-5 {name=mr-s2s-hq-1 uniqueid=5 reqid=1 state=INSTALLED mode=TUNNEL protocol=ESP encap=yes encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 bytes-in=840 packets-in=10 bytes-out=1680 packets-out=20 local-ts=[192.168.88.0/24] remote-ts=[10.10.0.0/16]} mr-s2s-hq-2-6 {name=mr-s2s-hq-2 state=REKEYING bytes-in=0 bytes-out=0 local-ts=[192.168.88.0/24 192.168.89.0/24] remote-ts [10.20.0.0/24]}}}}
list-sa event {mr-s2s-branch {uniqueid=4 version=1 state=CONNECTING remote-host=192.0.2.9 child-sas {}}}
list-sa event {mr-l2tp-server {uniqueid=9 state=ESTABLISHED child-sas {}}}
`
	st := ipsecStates(raw, []string{"hq", "branch", "idle"})
	if len(st) != 3 {
		t.Fatalf("%+v", st)
	}
	hq := st[0]
	if hq.State != "up" || hq.RemoteHost != "203.0.113.10" || hq.Established != 75 || !hq.NAT || len(hq.Children) != 2 {
		t.Fatalf("hq: %+v", hq)
	}
	c := hq.Children[0]
	if c.Name != "mr-s2s-hq-1" || c.LocalTS != "192.168.88.0/24" || c.RemoteTS != "10.10.0.0/16" || c.BytesIn != 840 || c.BytesOut != 1680 {
		t.Fatalf("child: %+v", c)
	}
	if hq.IKE != "aes_cbc-256 / hmac_sha2_256_128 / prf_hmac_sha2_256 / modp_2048" {
		t.Fatalf("ike: %q", hq.IKE)
	}
	if st[1].State != "connecting" || st[1].IKEState != "CONNECTING" {
		t.Fatalf("branch: %+v", st[1])
	}
	if st[2].State != "down" || st[2].Children == nil {
		t.Fatalf("idle: %+v", st[2])
	}
}
