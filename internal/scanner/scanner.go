// Package scanner discovers LAN hosts without privileges.
//
// Strategy: for each IP in the chosen /24, a short-timeout TCP dial is attempted
// in parallel. Whether the connection succeeds is irrelevant — the kernel has to
// resolve the MAC via ARP to even try, which populates /proc/net/arp. The ARP
// table is then read and normalized into Sighting records.
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type Sighting struct {
	MAC    string
	IP     string
	Vendor string
	TS     time.Time
}

type Scanner struct {
	iface   *net.Interface
	ipNet   *net.IPNet
	selfIP  string
	selfMAC string
	log     zerolog.Logger

	dialTimeout   time.Duration
	dialConcur    int
	settleDelay   time.Duration
	skipGatewayIP string // optional: router IP to skip (unused for now)
}

func New(ifaceName, subnet string, log zerolog.Logger) (*Scanner, error) {
	iface, ipNet, err := pickInterface(ifaceName, subnet)
	if err != nil {
		return nil, err
	}
	s := &Scanner{
		iface:       iface,
		ipNet:       ipNet,
		selfIP:      ipNet.IP.String(),
		selfMAC:     strings.ToLower(iface.HardwareAddr.String()),
		log:         log.With().Str("component", "scanner").Logger(),
		dialTimeout: 150 * time.Millisecond,
		dialConcur:  48,
		settleDelay: 400 * time.Millisecond,
	}
	return s, nil
}

func (s *Scanner) InterfaceName() string { return s.iface.Name }
func (s *Scanner) Subnet() string        { return s.ipNet.String() }

// Scan sweeps the subnet, waits briefly, reads /proc/net/arp, returns sightings.
func (s *Scanner) Scan(ctx context.Context) ([]Sighting, error) {
	s.sweep(ctx)
	// Give the kernel a moment for late ARP replies to land.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(s.settleDelay):
	}
	return s.readARP()
}

// sweep opens a short-timeout TCP dial to every host in the /24. The dials go to
// port 80, but every port works — we only care about the ARP side-effect.
func (s *Scanner) sweep(ctx context.Context) {
	ips := enumerate(s.ipNet)
	if len(ips) == 0 {
		return
	}
	sem := make(chan struct{}, s.dialConcur)
	var wg sync.WaitGroup
	for _, ip := range ips {
		if ip.String() == s.selfIP {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			d := net.Dialer{Timeout: s.dialTimeout}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "80"))
			if err == nil {
				_ = conn.Close()
			}
		}(ip)
	}
	wg.Wait()
}

func (s *Scanner) readARP() ([]Sighting, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/arp: %w", err)
	}
	defer f.Close()
	now := time.Now()

	var out []Sighting
	sc := bufio.NewScanner(f)
	sc.Scan() // header: "IP address  HW type  Flags  HW address  Mask  Device"
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		ip := fields[0]
		flags := fields[2]
		mac := strings.ToLower(fields[3])
		dev := fields[5]

		if dev != s.iface.Name {
			continue
		}
		if flags == "0x0" {
			continue // incomplete entry
		}
		if mac == "00:00:00:00:00:00" || mac == s.selfMAC {
			continue
		}
		out = append(out, Sighting{
			MAC:    mac,
			IP:     ip,
			Vendor: vendorFor(mac),
			TS:     now,
		})
	}
	return out, sc.Err()
}

// pickInterface resolves the user's choice of interface + subnet, or auto-detects.
func pickInterface(name, subnet string) (*net.Interface, *net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	// Explicit name requested.
	if name != "" && name != "auto" {
		for i := range ifaces {
			if ifaces[i].Name == name {
				ipn, err := interfaceSubnet(&ifaces[i], subnet)
				if err != nil {
					return nil, nil, err
				}
				return &ifaces[i], ipn, nil
			}
		}
		return nil, nil, fmt.Errorf("interface %q not found", name)
	}

	// Auto: first UP, non-loopback, non-tailscale, RFC1918 interface.
	for i := range ifaces {
		ifc := &ifaces[i]
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.HasPrefix(ifc.Name, "tailscale") || strings.HasPrefix(ifc.Name, "docker") ||
			strings.HasPrefix(ifc.Name, "br-") || strings.HasPrefix(ifc.Name, "veth") {
			continue
		}
		ipn, err := interfaceSubnet(ifc, subnet)
		if err != nil {
			continue
		}
		if !isPrivate(ipn.IP) {
			continue
		}
		return ifc, ipn, nil
	}
	return nil, nil, fmt.Errorf("no suitable interface found")
}

func interfaceSubnet(ifc *net.Interface, override string) (*net.IPNet, error) {
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipn.IP.To4()
		if v4 == nil {
			continue
		}
		if override != "" && override != "auto" {
			_, custom, err := net.ParseCIDR(override)
			if err != nil {
				return nil, fmt.Errorf("parse subnet override: %w", err)
			}
			return &net.IPNet{IP: v4, Mask: custom.Mask}, nil
		}
		// Clamp to /24 so a /22 or /16 doesn't make us sweep thousands of hosts.
		mask := ipn.Mask
		ones, _ := mask.Size()
		if ones < 24 {
			mask = net.CIDRMask(24, 32)
		}
		return &net.IPNet{IP: v4.Mask(mask), Mask: mask}, nil
	}
	return nil, fmt.Errorf("interface %s has no usable IPv4 address", ifc.Name)
}

func isPrivate(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return (v4[0] == 10) ||
		(v4[0] == 192 && v4[1] == 168) ||
		(v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31)
}

// enumerate returns every host IP in the subnet, excluding network and broadcast.
func enumerate(ipn *net.IPNet) []net.IP {
	ones, bits := ipn.Mask.Size()
	if bits-ones > 10 {
		// Guardrail: refuse to enumerate larger than /22 (1022 hosts).
		return nil
	}
	start := ipn.IP.Mask(ipn.Mask).To4()
	bcast := make(net.IP, 4)
	copy(bcast, start)
	for i := 0; i < 4; i++ {
		bcast[i] |= ^ipn.Mask[i]
	}
	var out []net.IP
	cur := make(net.IP, 4)
	copy(cur, start)
	incr(cur) // skip network address
	for cur[0] != bcast[0] || cur[1] != bcast[1] || cur[2] != bcast[2] || cur[3] != bcast[3] {
		ip := make(net.IP, 4)
		copy(ip, cur)
		out = append(out, ip)
		incr(cur)
	}
	return out
}

func incr(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}
