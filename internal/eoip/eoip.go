// Package eoip speaks MikroTik's EoIP and EoIPv6 tunnel protocols.
//
// EoIP is Ethernet in GRE over IPv4 (IP protocol 47) with a non-standard
// 8-byte header:
//
//	20 01 64 00 | frame length (big endian) | tunnel ID (little endian)
//
// EoIPv6 is Ethernet over IPv6 protocol 97 with a 2-byte header: the low
// nibble of the first byte is 3, the high nibble and the second byte are
// the 12-bit tunnel ID.
//
// A zero-length frame is a keepalive. The formats follow the public
// bbonev/eoip project, which was written from packet captures.
package eoip

import (
	"encoding/binary"
	"errors"
)

// IP protocol numbers.
const (
	ProtoGRE     = 47
	ProtoEtherIP = 97
)

// Header sizes.
const (
	HeaderLen   = 8
	Header6Len  = 2
	MaxTunnelID = 65535
	MaxTunnel6  = 4095
)

var magic = [4]byte{0x20, 0x01, 0x64, 0x00}

// Encap writes the EoIP header for frame into dst[:HeaderLen].
func Encap(dst []byte, tunnelID uint16, frameLen int) {
	copy(dst[:4], magic[:])
	binary.BigEndian.PutUint16(dst[4:6], uint16(frameLen))
	binary.LittleEndian.PutUint16(dst[6:8], tunnelID)
}

// ErrNotEoIP is returned for GRE packets that are not EoIP (plain GRE,
// PPTP).
var ErrNotEoIP = errors.New("not an EoIP packet")

// Decap parses an EoIP packet (the GRE header onwards) and returns the
// tunnel ID and the Ethernet frame (empty for a keepalive).
func Decap(p []byte) (uint16, []byte, error) {
	if len(p) < HeaderLen || [4]byte(p[:4]) != magic {
		return 0, nil, ErrNotEoIP
	}
	n := int(binary.BigEndian.Uint16(p[4:6]))
	id := binary.LittleEndian.Uint16(p[6:8])
	body := p[HeaderLen:]
	if n > len(body) {
		return 0, nil, errors.New("truncated EoIP frame")
	}
	return id, body[:n], nil
}

// Encap6 writes the EoIPv6 header into dst[:Header6Len].
func Encap6(dst []byte, tunnelID uint16) {
	dst[0] = byte((tunnelID>>8)&0xF)<<4 | 3
	dst[1] = byte(tunnelID)
}

// Decap6 parses an EoIPv6 payload and returns the tunnel ID and frame.
func Decap6(p []byte) (uint16, []byte, error) {
	if len(p) < Header6Len || p[0]&0x0F != 3 {
		return 0, nil, ErrNotEoIP
	}
	return uint16(p[0]>>4)<<8 | uint16(p[1]), p[Header6Len:], nil
}

// IPv4PayloadOffset returns where the payload starts in an IPv4 packet
// read from a raw socket (which includes the IP header).
func IPv4PayloadOffset(p []byte) (int, error) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return 0, errors.New("not IPv4")
	}
	ihl := int(p[0]&0x0F) * 4
	if ihl < 20 || ihl > len(p) {
		return 0, errors.New("bad IPv4 header length")
	}
	return ihl, nil
}
