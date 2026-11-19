package eoip

import (
	"bytes"
	"testing"
)

func TestEoIPHeader(t *testing.T) {
	frame := []byte("0123456789abcdefghij")
	pkt := make([]byte, HeaderLen+len(frame))
	Encap(pkt, 1234, len(frame))
	copy(pkt[HeaderLen:], frame)
	// Tunnel 1234 (0x4d2) goes out as d2 04; the length is big endian.
	want := []byte{0x20, 0x01, 0x64, 0x00, 0x00, 0x14, 0xd2, 0x04}
	if !bytes.Equal(pkt[:8], want) {
		t.Fatalf("header % x, want % x", pkt[:8], want)
	}
	id, got, err := Decap(append(pkt, 0, 0)) // padding after the frame
	if err != nil || id != 1234 || !bytes.Equal(got, frame) {
		t.Fatalf("decap: %d %q %v", id, got, err)
	}
	if _, _, err := Decap([]byte{0x00, 0x00, 0x08, 0x00, 0, 0, 0, 0}); err != ErrNotEoIP {
		t.Error("plain GRE accepted")
	}
	ka := make([]byte, HeaderLen)
	Encap(ka, 7, 0)
	if _, f, err := Decap(ka); err != nil || len(f) != 0 {
		t.Error("keepalive")
	}
	Encap(ka, 7, 50)
	if _, _, err := Decap(ka); err == nil {
		t.Error("truncated frame accepted")
	}
}

func TestEoIPv6Header(t *testing.T) {
	h := make([]byte, 2)
	Encap6(h, 0xABC)
	if h[0] != 0xA3 || h[1] != 0xBC {
		t.Fatalf("header % x", h)
	}
	id, f, err := Decap6(append(h, 'x'))
	if err != nil || id != 0xABC || string(f) != "x" {
		t.Fatalf("decap6: %x %q %v", id, f, err)
	}
	if _, _, err := Decap6([]byte{0x04, 0}); err == nil {
		t.Error("wrong version accepted")
	}
}

func TestIPv4Offset(t *testing.T) {
	p := make([]byte, 24)
	p[0] = 0x46
	if n, err := IPv4PayloadOffset(p); err != nil || n != 24 {
		t.Fatal(n, err)
	}
	if _, err := IPv4PayloadOffset([]byte{0x60}); err == nil {
		t.Error("ipv6 accepted")
	}
}
