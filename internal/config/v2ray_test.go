package config

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const testUUID = "bf000d23-0752-40b4-affe-68f7707a9661"

func TestParseV2RayLinks(t *testing.T) {
	pbk := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "x", "add": "vm.example.com", "port": "443", "id": testUUID, "aid": "0",
		"net": "ws", "path": "/ws?ed=2048", "host": "cdn.example.com", "tls": "tls", "sni": "cdn.example.com"})
	ss2022 := "ss://2022-blake3-aes-128-gcm:" + "c2VydmVyc2VydmVyMTIzNA%3D%3D:dXNlcnVzZXJ1c2VyMTIzNA%3D%3D@1.2.3.4:8388#x"
	cases := []struct {
		link string
		want []string
	}{
		{"vless://" + testUUID + "@203.0.113.5:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=" + pbk + "&sid=ab12&type=tcp&flow=xtls-rprx-vision#home",
			[]string{`"type":"vless"`, `"flow":"xtls-rprx-vision"`, `"public_key":"` + pbk, `"short_id":"ab12"`, `"server_name":"www.microsoft.com"`, `"fingerprint":"chrome"`}},
		{"vless://" + testUUID + "@h.example.com:2053?security=tls&type=grpc&serviceName=svc", []string{`"service_name":"svc"`, `"server_port":2053`}},
		{"vmess://" + base64.StdEncoding.EncodeToString(vm), []string{`"type":"vmess"`, `"max_early_data":2048`, `"path":"/ws"`, `"Host":"cdn.example.com"`}},
		{"trojan://p%40ss@t.example.com:443?sni=t.example.com#t", []string{`"type":"trojan"`, `"password":"p@ss"`, `"enabled":true`}},
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret")) + "@5.6.7.8:8388#n", []string{`"method":"aes-256-gcm"`, `"password":"secret"`}},
		{ss2022, []string{`"method":"2022-blake3-aes-128-gcm"`, `"password":"c2VydmVyc2VydmVyMTIzNA==:dXNlcnVzZXJ1c2VyMTIzNA=="`}},
		{"hysteria2://pw@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=o&insecure=1", []string{`"type":"hysteria2"`, `"salamander"`, `"insecure":true`}},
	}
	for _, c := range cases {
		out, err := ParseV2RayLink(c.link)
		if err != nil {
			t.Errorf("%s: %v", c.link[:20], err)
			continue
		}
		data, _ := json.Marshal(out)
		for _, w := range c.want {
			if !strings.Contains(string(data), w) {
				t.Errorf("%s: missing %s in %s", c.link[:20], w, data)
			}
		}
	}
	for _, bad := range []string{"http://x", "vless://not-a-uuid@h:1", "vless://" + testUUID + "@h:443?security=reality", "vless://" + testUUID + "@h:443?type=xhttp"} {
		if _, err := ParseV2RayLink(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}
