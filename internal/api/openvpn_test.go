package api

import (
	"testing"
	"time"
)

func TestParseOpenVPNStatus(t *testing.T) {
	s := "TITLE,OpenVPN 2.6.3\nTIME,2026-11-20 06:00:00,1795154400\n" +
		"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher\n" +
		"CLIENT_LIST,phone,198.51.100.7:51000,10.81.0.2,,1234,5678,2026-11-20 05:59:00,1795154340,phone,0,0,AES-256-GCM\n" +
		"HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t)\nEND\n"
	got := parseOpenVPNStatus(s, time.Unix(1795154400, 0))
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	g := got[0]
	if g.Username != "phone" || g.IP != "10.81.0.2" || g.From != "198.51.100.7" || g.Uptime != 60 || g.RxBytes != 1234 || g.TxBytes != 5678 || g.Ifname != "ovpn:198.51.100.7:51000" || g.Type != "openvpn" {
		t.Errorf("%+v", g)
	}
}
