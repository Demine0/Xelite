package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// stats counts bridge traffic so the app's log can show where packets stop.
type stats struct {
	pktIn, pktOut     atomic.Uint64 // IP packets from / to the VPN plug-in
	bytesIn, bytesOut atomic.Uint64
	tcp, udp          atomic.Uint64 // flows handed to Xray
	dialErrors        atomic.Uint64
	ipv6Rejected      atomic.Uint64

	writeErrors    atomic.Uint64
	fileErr        atomic.Pointer[string]
	relayed        atomic.Uint64 // outbound connections opened through the plug-in relay
	dnsQueries     atomic.Uint64 // UDP datagrams to port 53 from apps
	dnsAnswers     atomic.Uint64 // UDP datagrams from port 53 back to apps
	dns6Redirected atomic.Uint64 // DNS flows to IPv6 servers answered via IPv4
	aaaaBlocked    atomic.Uint64 // AAAA queries answered locally with no records
	dohErrors      atomic.Uint64
	doorbells      atomic.Uint64
	lastDoH        atomic.Pointer[string]

	mu        sync.Mutex
	lastError string
	lastWrite string
	samples   []string // first packets from the plug-in, decoded
}

const maxSamples = 6

// sample records a short decode of the first few packets, to see in the log
// what Windows actually delivers (protocol, ports, TCP flags, checksum).
func (s *stats) sample(pkt []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.samples) >= maxSamples {
		return
	}
	s.samples = append(s.samples, describePacket(pkt))
}

func (s *stats) writeFailed(to fmt.Stringer, err error) {
	s.writeErrors.Add(1)
	s.mu.Lock()
	s.lastWrite = to.String() + ": " + err.Error()
	s.mu.Unlock()
}

func (s *stats) dialFailed(dst fmt.Stringer, err error) {
	s.dialErrors.Add(1)
	s.mu.Lock()
	s.lastError = dst.String() + ": " + err.Error()
	s.mu.Unlock()
}

func (s *stats) String() string {
	s.mu.Lock()
	last := s.lastError
	s.mu.Unlock()
	// Fixed "key=value" format: the app parses it for the home screen.
	line := fmt.Sprintf("t=%s godebug=%s pktIn=%d bytesIn=%d pktOut=%d bytesOut=%d tcp=%d udp=%d dialErrors=%d ipv6Rejected=%d writeErrors=%d relayed=%d",
		time.Now().Format("15:04:05"), os.Getenv("GODEBUG"), s.pktIn.Load(), s.bytesIn.Load(), s.pktOut.Load(), s.bytesOut.Load(),
		s.tcp.Load(), s.udp.Load(), s.dialErrors.Load(), s.ipv6Rejected.Load(), s.writeErrors.Load(), s.relayed.Load())
	if last != "" {
		line += "\nlast dial error: " + last
	}
	s.mu.Lock()
	if s.lastWrite != "" {
		line += "\nlast write error: " + s.lastWrite
	}
	for _, sm := range s.samples {
		line += "\nin: " + sm
	}
	s.mu.Unlock()
	return line
}

// writeLoop rewrites path with the current counters every second.
func (s *stats) writeLoop(path string, done <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if err := os.WriteFile(path, []byte(s.String()), 0o644); err != nil {
			s.setFileError(err.Error())
		} else {
			s.setFileError("none")
		}
		select {
		case <-t.C:
		case <-done:
			return
		}
	}
}

// describePacket decodes an IP packet header into one log line.
func describePacket(pkt []byte) string {
	switch header.IPVersion(pkt) {
	case header.IPv4Version:
		ip := header.IPv4(pkt)
		if !ip.IsValid(len(pkt)) {
			return fmt.Sprintf("invalid IPv4 packet, %d bytes", len(pkt))
		}
		return describeTransport("IPv4", ip.SourceAddress(), ip.DestinationAddress(),
			ip.TransportProtocol(), ip.Payload(), len(pkt))
	case header.IPv6Version:
		ip := header.IPv6(pkt)
		if !ip.IsValid(len(pkt)) {
			return fmt.Sprintf("invalid IPv6 packet, %d bytes", len(pkt))
		}
		return describeTransport("IPv6", ip.SourceAddress(), ip.DestinationAddress(),
			ip.TransportProtocol(), ip.Payload(), len(pkt))
	default:
		return fmt.Sprintf("not IP (version %d), %d bytes", header.IPVersion(pkt), len(pkt))
	}
}

func describeTransport(family string, src, dst tcpip.Address, proto tcpip.TransportProtocolNumber, payload []byte, size int) string {
	switch proto {
	case header.TCPProtocolNumber:
		if len(payload) < header.TCPMinimumSize {
			break
		}
		t := header.TCP(payload)
		ok := t.IsChecksumValid(src, dst, checksum.Checksum(t.Payload(), 0), uint16(len(t.Payload())))
		return fmt.Sprintf("%s TCP %s:%d -> %s:%d flags %s, %d bytes, checksum %s",
			family, src, t.SourcePort(), dst, t.DestinationPort(), t.Flags(), size, okText(ok))
	case header.UDPProtocolNumber:
		if len(payload) < header.UDPMinimumSize {
			break
		}
		u := header.UDP(payload)
		return fmt.Sprintf("%s UDP %s:%d -> %s:%d, %d bytes, checksum field %#04x",
			family, src, u.SourcePort(), dst, u.DestinationPort(), size, u.Checksum())
	}
	return fmt.Sprintf("%s proto %d %s -> %s, %d bytes", family, proto, src, dst, size)
}

func okText(ok bool) string {
	if ok {
		return "valid"
	}
	return "INVALID (offloaded)"
}

// heartbeatLoop sends "XELITE-HB <n> <stats>" to the plug-in's side socket
// every second. It proves from the outside that Go timers and the scheduler
// keep running, and carries the last stats-file error, without relying on
// file writes.
func (b *bridge) heartbeatLoop(statsErr func() string) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for n := 1; ; n++ {
		select {
		case <-t.C:
		case <-b.ctx.Done():
			return
		}
		to := b.control.Load()
		if to == nil {
			continue
		}
		msg := fmt.Sprintf("XELITE-HB %d pktIn=%d pktOut=%d tcp=%d udp=%d relayed=%d dnsQ=%d dnsA=%d dns6=%d aaaa=%d dohErr=%d lastDoH=%s bells=%d statsErr=%s",
			n, b.stats.pktIn.Load(), b.stats.pktOut.Load(), b.stats.tcp.Load(), b.stats.udp.Load(),
			b.stats.relayed.Load(), b.stats.dnsQueries.Load(), b.stats.dnsAnswers.Load(), b.stats.dns6Redirected.Load(), b.stats.aaaaBlocked.Load(), b.stats.dohErrors.Load(), b.stats.lastDoHError(), b.stats.doorbells.Load(), statsErr())
		_, _ = b.conn.WriteToUDP([]byte(msg), to)
	}
}

func (s *stats) setFileError(e string) { s.fileErr.Store(&e) }

func (s *stats) fileError() string {
	if e := s.fileErr.Load(); e != nil {
		return strings.ReplaceAll(*e, " ", "_")
	}
	return "not-yet"
}

func (s *stats) dohFailed(err error) {
	s.dohErrors.Add(1)
	e := strings.ReplaceAll(err.Error(), " ", "_")
	s.lastDoH.Store(&e)
}

func (s *stats) lastDoHError() string {
	if e := s.lastDoH.Load(); e != nil {
		return *e
	}
	return "none"
}
