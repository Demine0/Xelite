package main

import (
	"fmt"
	"os"
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

	writeErrors atomic.Uint64
	relayed     atomic.Uint64 // outbound connections opened through the plug-in relay

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
	line := fmt.Sprintf("pktIn=%d bytesIn=%d pktOut=%d bytesOut=%d tcp=%d udp=%d dialErrors=%d ipv6Rejected=%d writeErrors=%d relayed=%d",
		s.pktIn.Load(), s.bytesIn.Load(), s.pktOut.Load(), s.bytesOut.Load(),
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
		_ = os.WriteFile(path, []byte(s.String()), 0o644)
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
