package main

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// stats counts bridge traffic so the app's log can show where packets stop.
type stats struct {
	pktIn, pktOut     atomic.Uint64 // IP packets from / to the VPN plug-in
	bytesIn, bytesOut atomic.Uint64
	tcp, udp          atomic.Uint64 // flows handed to Xray
	dialErrors        atomic.Uint64

	mu        sync.Mutex
	lastError string
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
	line := fmt.Sprintf("packets in %d (%d B), out %d (%d B); flows tcp %d, udp %d; dial errors %d",
		s.pktIn.Load(), s.bytesIn.Load(), s.pktOut.Load(), s.bytesOut.Load(),
		s.tcp.Load(), s.udp.Load(), s.dialErrors.Load())
	if last != "" {
		line += "; last error " + last
	}
	return line
}

// writeLoop rewrites path with the current counters every few seconds.
func (s *stats) writeLoop(path string, done <-chan struct{}) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		_ = os.WriteFile(path, []byte(time.Now().Format("15:04:05 ")+s.String()), 0o644)
		select {
		case <-t.C:
		case <-done:
			return
		}
	}
}
