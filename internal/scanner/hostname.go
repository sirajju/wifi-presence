package scanner

import (
	"context"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Hostname sources, in priority order:
//
//  1. Router DHCP-lease scrape (PRESENCE_ROUTER_LEASES_URL).
//     On the Genexis P4410 the endpoint is http://192.168.1.1/captcha/leases
//     and returns plain-text "MAC IP ttl hostname" rows. Works unauthenticated.
//     This is the primary source because phones send a hostname in DHCP
//     option 12 that the router happily stores; mDNS/NetBIOS miss most of them.
//
//  2. NetBIOS NBSTAT (UDP:137) — covers Windows / Samba and some Android.
//
//  3. Reverse DNS via the system resolver — anything the LAN DNS knows.
//
// Values are sticky in the store: once a non-empty hostname is written for a
// MAC, a later blank reading won't clobber it. That's what makes "router reboot
// wipes the lease table" a non-event once the DB has seen a device.

const defaultRouterLeasesURL = "http://192.168.1.1/captcha/leases"

var httpClient = &http.Client{Timeout: 2 * time.Second}

func routerLeasesURL() string {
	if v := strings.TrimSpace(os.Getenv("PRESENCE_ROUTER_LEASES_URL")); v != "" {
		return v
	}
	return defaultRouterLeasesURL
}

// resolveHostnames fills in sightings[i].Hostname in place.
//
// It fetches the router's DHCP lease table once and consults it for every
// sighting; sightings not in the lease table get a cheap NBNS + reverse-DNS
// probe as a fallback (short timeouts, high parallelism).
func resolveHostnames(ctx context.Context, sightings []Sighting) {
	byMAC := fetchRouterLeases(ctx)

	const workers = 24
	const perIPTimeout = 400 * time.Millisecond

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range sightings {
		if sightings[i].IP == "" {
			continue
		}
		// 1. Router lease table — authoritative.
		if h := byMAC[strings.ToLower(sightings[i].MAC)]; h != "" {
			sightings[i].Hostname = h
			continue
		}
		// 2 + 3. Fall back to active probing.
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			ip := sightings[idx].IP
			ctx2, cancel := context.WithTimeout(ctx, perIPTimeout)
			defer cancel()
			if name := netbiosName(ctx2, ip); name != "" {
				sightings[idx].Hostname = name
				return
			}
			if name := reverseDNS(ctx2, ip); name != "" {
				sightings[idx].Hostname = name
				return
			}
		}(i)
	}
	wg.Wait()
}

// fetchRouterLeases GETs the router's lease table and returns a lowercase-MAC
// → hostname map. Returns an empty map on any error — callers fall through to
// per-IP probes.
//
// Expected body is plain text, one row per line:
//
//	MAC IP ttl hostname
//
// Lines without a hostname are skipped. Leading/trailing whitespace is tolerated.
func fetchRouterLeases(ctx context.Context) map[string]string {
	url := routerLeasesURL()
	if url == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}
	out := make(map[string]string, 32)
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mac := strings.ToLower(fields[0])
		name := cleanHostname(fields[3])
		if mac == "" || name == "" {
			continue
		}
		out[mac] = name
	}
	return out
}

// reverseDNS returns the first PTR result from the system resolver,
// stripped of trailing dot. Empty on failure or NXDOMAIN.
func reverseDNS(ctx context.Context, ip string) string {
	r := net.Resolver{PreferGo: true}
	names, err := r.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := strings.TrimSuffix(names[0], ".")
	name = strings.TrimSuffix(name, ".lan")
	name = strings.TrimSuffix(name, ".local")
	return cleanHostname(name)
}

// netbiosName sends an NBSTAT query to ip:137 and returns the ComputerName
// (suffix 0x00, unique). Empty on timeout — common for phones and most IoT.
func netbiosName(ctx context.Context, ip string) string {
	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: 137}
	if addr.IP == nil {
		return ""
	}
	dl, _ := ctx.Deadline()
	if dl.IsZero() {
		dl = time.Now().Add(400 * time.Millisecond)
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(dl)

	trid := uint16(rand.Uint32())
	pkt := make([]byte, 0, 50)
	pkt = binary.BigEndian.AppendUint16(pkt, trid)
	pkt = binary.BigEndian.AppendUint16(pkt, 0x0010)
	pkt = binary.BigEndian.AppendUint16(pkt, 1)
	pkt = binary.BigEndian.AppendUint16(pkt, 0)
	pkt = binary.BigEndian.AppendUint16(pkt, 0)
	pkt = binary.BigEndian.AppendUint16(pkt, 0)
	pkt = append(pkt, 0x20)
	pkt = append(pkt, []byte("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")...)
	pkt = append(pkt, 0x00)
	pkt = binary.BigEndian.AppendUint16(pkt, 0x0021)
	pkt = binary.BigEndian.AppendUint16(pkt, 0x0001)

	if _, err := conn.Write(pkt); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return ""
	}
	return parseNBSTAT(buf[:n])
}

func parseNBSTAT(buf []byte) string {
	off := 12 + 34 + 4
	if len(buf) < off+12 {
		return ""
	}
	off += 34 + 2 + 2 + 4
	if len(buf) < off+3 {
		return ""
	}
	off += 2
	nameCount := int(buf[off])
	off++
	for i := 0; i < nameCount; i++ {
		if len(buf) < off+18 {
			return ""
		}
		name := string(buf[off : off+15])
		suffix := buf[off+15]
		flags := binary.BigEndian.Uint16(buf[off+16 : off+18])
		off += 18
		if flags&0x8000 == 0 && suffix == 0x00 {
			return cleanHostname(strings.TrimRight(name, " \x00"))
		}
	}
	return ""
}

func cleanHostname(s string) string {
	s = strings.TrimSpace(s)
	// Keep original case for the PRIMARY source since the router lease table
	// serves names like "Siru-s-A13" that are nicer than "siru-s-a13".
	// Still drop characters that have no business in a chat message.
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-' || r == '_' || r == '.':
			return r
		default:
			return -1
		}
	}, s)
	return s
}
