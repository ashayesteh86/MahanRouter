// mahan-eoip runs one MikroTik-compatible EoIP or EoIPv6 tunnel: it
// creates a TAP interface and carries its Ethernet frames to the other end
// over a raw IP socket. systemd-networkd configures the TAP interface like
// any other (addresses, bridge membership, VLANs).
//
// Usage: mahan-eoip -c /etc/mahan-router/eoip/NAME.json
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/ashayesteh86/MahanRouter/internal/eoip"
)

// Config is the file written by the agent (render.EoIPConfPath).
type Config struct {
	Name      string `json:"name"`
	IPv6      bool   `json:"ipv6"`
	Local     string `json:"local,omitempty"`
	Remote    string `json:"remote"`
	TunnelID  uint16 `json:"tunnel_id"`
	TTL       int    `json:"ttl,omitempty"`
	Keepalive int    `json:"keepalive"` // seconds, 0 = off
	MAC       string `json:"mac,omitempty"`
}

// keepaliveMisses is how many intervals pass without a packet before the
// link goes down (RouterOS keepalive=10s,10).
const keepaliveMisses = 10

func main() {
	conf := flag.String("c", "", "tunnel config file")
	flag.Parse()
	log.SetFlags(0)
	b, err := os.ReadFile(*conf)
	if err != nil {
		log.Fatal(err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		log.Fatalf("%s: %v", *conf, err)
	}
	t, err := open(&c)
	if err != nil {
		log.Fatal(err)
	}
	proto := "eoip"
	if c.IPv6 {
		proto = "eoipv6"
	}
	log.Printf("%s: %s tunnel %d to %s", c.Name, proto, c.TunnelID, c.Remote)
	go t.fromTap()
	go t.fromNet()
	if c.Keepalive > 0 {
		go t.keepalive(time.Duration(c.Keepalive) * time.Second)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case s := <-sig:
		log.Printf("%s: %v, stopping", c.Name, s)
	case err := <-t.fatal:
		log.Fatalf("%s: %v", c.Name, err)
	}
}

type tunnel struct {
	c      *Config
	tap    *os.File
	sock   int
	remote syscall.Sockaddr
	peer   netip.Addr
	lastRx atomic.Int64
	mu     sync.Mutex
	up     bool
	fatal  chan error
}

func open(c *Config) (*tunnel, error) {
	peer, err := netip.ParseAddr(c.Remote)
	if err != nil || peer.Is4() == c.IPv6 {
		return nil, fmt.Errorf("bad remote %q", c.Remote)
	}
	t := &tunnel{c: c, peer: peer, fatal: make(chan error, 2)}
	if t.sock, err = rawSocket(c, peer); err != nil {
		return nil, err
	}
	if c.IPv6 {
		t.remote = &syscall.SockaddrInet6{Addr: peer.As16()}
	} else {
		t.remote = &syscall.SockaddrInet4{Addr: peer.As4()}
	}
	mac, err := tunnelMAC(c)
	if err != nil {
		return nil, err
	}
	if t.tap, err = openTap(c.Name, mac); err != nil {
		return nil, err
	}
	// With keepalive the link is down until the other end is heard, like
	// RouterOS.
	t.setCarrier(c.Keepalive == 0)
	return t, nil
}

func rawSocket(c *Config, peer netip.Addr) (int, error) {
	fam, proto := syscall.AF_INET, eoip.ProtoGRE
	if c.IPv6 {
		fam, proto = syscall.AF_INET6, eoip.ProtoEtherIP
	}
	fd, err := syscall.Socket(fam, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return -1, fmt.Errorf("raw socket: %w", err)
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4<<20)
	// Let the kernel fragment: a full 1500-byte frame plus headers does
	// not fit a 1500 MTU path, and RouterOS reassembles.
	if c.IPv6 {
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, 0)
		if c.TTL > 0 {
			_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, c.TTL)
		}
	} else {
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT)
		if c.TTL > 0 {
			_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, c.TTL)
		}
	}
	if c.Local != "" {
		loc, err := netip.ParseAddr(c.Local)
		if err != nil {
			return -1, fmt.Errorf("bad local %q", c.Local)
		}
		var sa syscall.Sockaddr = &syscall.SockaddrInet4{Addr: loc.As4()}
		if c.IPv6 {
			sa = &syscall.SockaddrInet6{Addr: loc.As16()}
		}
		// IP_FREEBIND: the address may appear later (DHCP, PPPoE).
		if c.IPv6 {
			_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, 78 /* IPV6_FREEBIND */, 1)
		} else {
			_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_FREEBIND, 1)
		}
		if err := syscall.Bind(fd, sa); err != nil {
			return -1, fmt.Errorf("bind %s: %w", c.Local, err)
		}
	}
	return fd, nil
}

// tunnelMAC is the configured MAC, or a stable locally administered one
// derived from the machine ID and the interface name, so it survives
// restarts and differs between routers.
func tunnelMAC(c *Config) (net.HardwareAddr, error) {
	if c.MAC != "" {
		return net.ParseMAC(c.MAC)
	}
	id, _ := os.ReadFile("/etc/machine-id")
	h := sha256.Sum256([]byte("mahan-eoip/" + string(id) + "/" + c.Name))
	mac := net.HardwareAddr(h[:6])
	mac[0] = mac[0]&0xFC | 0x02
	return mac, nil
}

const (
	tunSetIff     = 0x400454ca
	tunSetCarrier = 0x400454e2
	iffTap        = 0x0002
	iffNoPI       = 0x1000
)

type ifreqFlags struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

type ifreqHW struct {
	Name   [16]byte
	Family uint16
	Data   [14]byte
	_      [8]byte
}

func openTap(name string, mac net.HardwareAddr) (*os.File, error) {
	if len(name) == 0 || len(name) > 15 {
		return nil, errors.New("bad interface name")
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("/dev/net/tun: %w", err)
	}
	var req ifreqFlags
	copy(req.Name[:], name)
	req.Flags = iffTap | iffNoPI
	if err := ioctl(fd, tunSetIff, unsafe.Pointer(&req)); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("create tap %s: %w", name, err)
	}
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err == nil {
		var hw ifreqHW
		copy(hw.Name[:], name)
		hw.Family = syscall.ARPHRD_ETHER
		copy(hw.Data[:], mac)
		if err := ioctl(s, syscall.SIOCSIFHWADDR, unsafe.Pointer(&hw)); err != nil {
			log.Printf("%s: set mac: %v", name, err)
		}
		syscall.Close(s)
	}
	return os.NewFile(uintptr(fd), "tap:"+name), nil
}

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

func (t *tunnel) setCarrier(on bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if on == t.up && t.lastRx.Load() != 0 {
		return
	}
	v := int32(0)
	if on {
		v = 1
	}
	raw, err := t.tap.SyscallConn()
	if err == nil {
		_ = raw.Control(func(fd uintptr) {
			err = ioctl(int(fd), tunSetCarrier, unsafe.Pointer(&v))
		})
	}
	if err != nil {
		log.Printf("%s: set carrier: %v", t.c.Name, err)
	}
	if on != t.up {
		log.Printf("%s: link %s", t.c.Name, map[bool]string{true: "up", false: "down"}[on])
	}
	t.up = on
}

func (t *tunnel) hdrLen() int {
	if t.c.IPv6 {
		return eoip.Header6Len
	}
	return eoip.HeaderLen
}

func (t *tunnel) send(pkt []byte, frameLen int) error {
	if t.c.IPv6 {
		eoip.Encap6(pkt, t.c.TunnelID)
	} else {
		eoip.Encap(pkt, t.c.TunnelID, frameLen)
	}
	return syscall.Sendto(t.sock, pkt[:t.hdrLen()+frameLen], 0, t.remote)
}

func (t *tunnel) fromTap() {
	h := t.hdrLen()
	buf := make([]byte, h+65536)
	for {
		n, err := t.tap.Read(buf[h:])
		if err != nil {
			t.fatal <- fmt.Errorf("read tap: %w", err)
			return
		}
		if err := t.send(buf, n); err != nil && !errors.Is(err, syscall.ENETUNREACH) && !errors.Is(err, syscall.EHOSTUNREACH) {
			log.Printf("%s: send: %v", t.c.Name, err)
		}
	}
}

func (t *tunnel) fromNet() {
	buf := make([]byte, 65536+60)
	for {
		n, from, err := syscall.Recvfrom(t.sock, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			t.fatal <- fmt.Errorf("receive: %w", err)
			return
		}
		if !t.fromPeer(from) {
			continue
		}
		var id uint16
		var frame []byte
		if t.c.IPv6 {
			// IPv6 raw sockets return the payload only.
			id, frame, err = eoip.Decap6(buf[:n])
		} else {
			off, e := eoip.IPv4PayloadOffset(buf[:n])
			if e != nil {
				continue
			}
			id, frame, err = eoip.Decap(buf[off:n])
		}
		if err != nil || id != t.c.TunnelID {
			continue // plain GRE, PPTP or another tunnel
		}
		t.lastRx.Store(time.Now().UnixNano())
		if t.c.Keepalive > 0 && !t.isUp() {
			t.setCarrier(true)
		}
		if len(frame) == 0 {
			continue // keepalive
		}
		if _, err := t.tap.Write(frame); err != nil && !errors.Is(err, syscall.EIO) {
			log.Printf("%s: write tap: %v", t.c.Name, err)
		}
	}
}

func (t *tunnel) isUp() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.up
}

func (t *tunnel) fromPeer(sa syscall.Sockaddr) bool {
	switch a := sa.(type) {
	case *syscall.SockaddrInet4:
		return t.peer.Is4() && netip.AddrFrom4(a.Addr) == t.peer
	case *syscall.SockaddrInet6:
		return t.peer.Is6() && netip.AddrFrom16(a.Addr) == t.peer
	}
	return false
}

func (t *tunnel) keepalive(every time.Duration) {
	pkt := make([]byte, t.hdrLen())
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		_ = t.send(pkt, 0)
		<-tick.C
		last := t.lastRx.Load()
		if t.isUp() && (last == 0 || time.Since(time.Unix(0, last)) > every*keepaliveMisses) {
			t.setCarrier(false)
		}
	}
}
