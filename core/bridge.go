package main

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	stdnet "net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1

	// InboundTag is visible to Xray routing rules ("inboundTag": ["tun"]).
	InboundTag = "tun"

	udpIdleTimeout = 60 * time.Second
	dnsIdleTimeout = 15 * time.Second

	// dns6Fallback answers DNS queries sent to IPv6 servers while IPv6 is rejected.
	dns6Fallback = "1.1.1.1"
)

var (
	pingMagic    = []byte("XELITE-PING")
	pongMagic    = []byte("XELITE-PONG")
	replyToMagic = []byte("XELITE-RT") // followed by the port to send replies to
	doorbellReq  = []byte("XELITE-DB")
	doorbellTag  = []byte("XLT0")

	// packetTag prefixes every IP packet sent to the reply-to transport.
	packetTag = []byte("XLT1")
)

// control handles the plug-in's short control datagrams.
func (b *bridge) handleControl(msg []byte, from *stdnet.UDPAddr) {
	switch {
	case bytes.HasPrefix(msg, pingMagic):
		// Loopback test: echo so the plug-in knows datagrams pass both ways.
		_, _ = b.conn.WriteToUDP(pongMagic, from)
		b.control.Store(from)
	case bytes.HasPrefix(msg, doorbellReq):
		// The plug-in has Xray upload queued and needs a Decapsulate call to send it.
		// Its optional transport is connected to our port and drops datagrams from
		// anywhere else, so the doorbell has to come from us.
		if peer := b.peer.Load(); peer != nil && b.fixedPeer.Load() {
			b.stats.doorbells.Add(1)
			_, _ = b.conn.WriteToUDP(doorbellTag, peer)
		}
	case bytes.HasPrefix(msg, replyToMagic):
		// The plug-in sends packets from its own socket, because Windows binds
		// the VPN transport socket to the physical interface, where loopback
		// datagrams never arrive. Replies still go to the transport socket so
		// the VPN platform hands them to Decapsulate.
		port, err := strconv.Atoi(string(msg[len(replyToMagic):]))
		if err != nil || port <= 0 || port > 65535 {
			return
		}
		b.peer.Store(&stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: port})
		b.fixedPeer.Store(true)
		_, _ = b.conn.WriteToUDP(append([]byte(nil), msg...), from) // ack
	}
}

// bridge moves raw IP packets between the VPN plug-in (over loopback UDP)
// and a gVisor stack whose TCP/UDP flows are dispatched into Xray.
type bridge struct {
	inst   *core.Instance
	conn   *stdnet.UDPConn
	peer   atomic.Pointer[stdnet.UDPAddr]
	ep     *channel.Endpoint
	stack  *stack.Stack
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	stats  *stats

	// rejectIPv6 refuses IPv6 flows captured by the tunnel (leak protection).
	rejectIPv6 bool

	// fixedPeer is set once the plug-in names its VPN transport socket as the
	// reply address (XELITE-RT); packets then arrive from a different socket.
	fixedPeer atomic.Bool

	// resolver answers apps' DNS queries with Xray's DNS (DoH through the proxy).
	resolver dns.Client

	// control is the plug-in's side socket, where heartbeats go.
	control atomic.Pointer[stdnet.UDPAddr]
}

func newBridge(inst *core.Instance, port int, mtu uint32, rejectIPv6 bool, st *stats) (*bridge, error) {
	conn, err := stdnet.ListenUDP("udp4", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)

	ep := channel.New(1024, mtu, "")
	// Windows' VPN interface hands over packets with TCP/UDP checksums left for
	// offload (not filled in). Don't verify them, or every SYN is dropped.
	ep.LinkEPCapabilities |= stack.CapabilityRXChecksumOffload
	s, err := createStack(ep)
	if err != nil {
		conn.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	b := &bridge{inst: inst, conn: conn, ep: ep, stack: s, ctx: ctx, cancel: cancel, rejectIPv6: rejectIPv6, stats: st}

	tcpForwarder := tcp.NewForwarder(s, 0, 2048, b.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := udp.NewForwarder(s, b.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	if c, ok := inst.GetFeature(dns.ClientType()).(dns.Client); ok && useXrayDNS {
		b.resolver = c
	}
	go b.readLoop()
	go b.writeLoop()
	return b, nil
}

func createStack(ep stack.LinkEndpoint) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, errors.New(err.String())
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	// Accept packets for any destination and answer from any address.
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, errors.New(err.String())
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, errors.New(err.String())
	}
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	cc := tcpip.CongestionControlOption("cubic")
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &cc)
	// Keep buffers modest: the VPN background task host has a small
	// memory budget on phones.
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultReceiveBufferSize, Max: 2 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultSendBufferSize, Max: 2 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)
	return s, nil
}

// readLoop takes packets from the VPN plug-in and injects them into the stack.
func (b *bridge) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			if b.ctx.Err() != nil {
				return
			}
			continue
		}
		if n < header.IPv4MinimumSize {
			b.handleControl(buf[:n], addr)
			continue
		}
		if !b.fixedPeer.Load() {
			b.peer.Store(addr)
		}
		b.stats.pktIn.Add(1)
		b.stats.bytesIn.Add(uint64(n))
		b.stats.sample(buf[:n])
		var proto tcpip.NetworkProtocolNumber
		switch header.IPVersion(buf[:n]) {
		case header.IPv4Version:
			proto = header.IPv4ProtocolNumber
		case header.IPv6Version:
			proto = header.IPv6ProtocolNumber
		default:
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), buf[:n]...)),
		})
		b.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

// writeLoop sends packets produced by the stack back to the VPN plug-in.
func (b *bridge) writeLoop() {
	for {
		pkt := b.ep.ReadContext(b.ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToBuffer()
		data := v.Flatten()
		v.Release()
		pkt.DecRef()
		if b.fixedPeer.Load() {
			// The reply-to socket is the VPN's optional transport, which also carries the
			// server's TCP stream on the main one: tag IP packets so the plug-in can tell
			// them from stream bytes in Decapsulate.
			data = append(append(make([]byte, 0, len(packetTag)+len(data)), packetTag...), data...)
		}
		if peer := b.peer.Load(); peer != nil {
			if _, err := b.conn.WriteToUDP(data, peer); err == nil {
				b.stats.pktOut.Add(1)
				b.stats.bytesOut.Add(uint64(len(data)))
			} else {
				b.stats.writeFailed(peer, err)
			}
		}
	}
}

func (b *bridge) flowContext(src xnet.Destination) context.Context {
	ctx := session.ContextWithInbound(b.ctx, &session.Inbound{Source: src, Tag: InboundTag, Name: "tun"})
	return session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled:                        true,
			OverrideDestinationForProtocol: []string{"http", "tls", "quic"},
			RouteOnly:                      true,
		},
	})
}

func (b *bridge) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	if b.rejectIPv6 && id.LocalAddress.Len() == 16 {
		// Reset at once so apps fall back to IPv4 (which goes through Xray)
		// instead of leaking over the Wi-Fi's IPv6 route.
		b.stats.ipv6Rejected.Add(1)
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	local := gonet.NewTCPConn(&wq, ep)

	src := xnet.TCPDestination(xnet.IPAddress(id.RemoteAddress.AsSlice()), xnet.Port(id.RemotePort))
	dst := xnet.TCPDestination(xnet.IPAddress(id.LocalAddress.AsSlice()), xnet.Port(id.LocalPort))
	go func() {
		defer local.Close()
		b.stats.tcp.Add(1)
		remote, err := core.Dial(b.flowContext(src), b.inst, dst)
		if err != nil {
			b.stats.dialFailed(dst, err)
			errors.LogInfo(b.ctx, "tun: dial ", dst, " failed: ", err)
			return
		}
		defer remote.Close()
		f := b.stats.flowOpened(dst.String())
		done := make(chan struct{}, 2)
		go func() {
			io.Copy(&countingWriter{remote, f, &f.up}, local)
			// Pass the app's half-close on, so servers that wait for EOF answer.
			if cw, ok := remote.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			done <- struct{}{}
		}()
		go func() {
			io.Copy(&countingWriter{local, f, &f.down}, remote)
			local.CloseWrite()
			done <- struct{}{}
		}()
		<-done
		<-done
		b.stats.flowEnded(f)
	}()
}

func (b *bridge) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dst := xnet.UDPDestination(xnet.IPAddress(id.LocalAddress.AsSlice()), xnet.Port(id.LocalPort))
	if b.rejectIPv6 && id.LocalAddress.Len() == 16 {
		if id.LocalPort != 53 {
			b.stats.ipv6Rejected.Add(1)
			return true // dropped
		}
		// Windows asks the Wi-Fi's IPv6 DNS server first. Dropping those queries
		// made every first lookup wait ~30 s for timeouts, so answer them through
		// an IPv4 resolver instead; the reply still comes from the IPv6 address.
		b.stats.dns6Redirected.Add(1)
		dst = xnet.UDPDestination(xnet.ParseAddress(dns6Fallback), 53)
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return true
	}
	local := gonet.NewUDPConn(&wq, ep)

	src := xnet.UDPDestination(xnet.IPAddress(id.RemoteAddress.AsSlice()), xnet.Port(id.RemotePort))
	if id.LocalPort == 53 && b.resolver != nil {
		go b.serveDNS(local)
		return true
	}
	timeout := udpIdleTimeout
	if id.LocalPort == 53 {
		timeout = dnsIdleTimeout
	}
	go func() {
		defer local.Close()
		ctx, cancel := context.WithCancel(b.flowContext(src))
		defer cancel()
		b.stats.udp.Add(1)
		remote, err := core.Dial(ctx, b.inst, dst)
		if err != nil {
			b.stats.dialFailed(dst, err)
			errors.LogInfo(b.ctx, "tun: dial ", dst, " failed: ", err)
			return
		}
		defer remote.Close()

		idle := time.AfterFunc(timeout, func() {
			local.Close()
			remote.Close()
		})
		defer idle.Stop()

		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := remote.Read(buf)
				if err != nil {
					local.Close()
					return
				}
				idle.Reset(timeout)
				if id.LocalPort == 53 {
					b.stats.dnsAnswers.Add(1)
				}
				if _, err := local.Write(buf[:n]); err != nil {
					return
				}
			}
		}()
		buf := make([]byte, 65535)
		for {
			n, err := local.Read(buf)
			if err != nil {
				return
			}
			idle.Reset(timeout)
			if id.LocalPort == 53 {
				b.stats.dnsQueries.Add(1)
				if b.rejectIPv6 {
					if resp, ok := aaaaNoData(buf[:n]); ok {
						b.stats.aaaaBlocked.Add(1)
						_, _ = local.Write(resp)
						continue
					}
				}
			}
			if _, err := remote.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	return true
}

func (b *bridge) Close() {
	b.once.Do(func() {
		b.cancel()
		b.conn.Close()
		b.ep.Close()
		b.stack.Close()
	})
}

// serveDNS answers the DNS queries of one app socket (a UDP flow to port 53)
// with DoH, each query in parallel; the flow ends after dnsIdleTimeout.
func (b *bridge) serveDNS(local *gonet.UDPConn) {
	defer local.Close()
	buf := make([]byte, 4096)
	for {
		_ = local.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
		n, err := local.Read(buf)
		if err != nil {
			return
		}
		b.stats.dnsQueries.Add(1)
		q := append([]byte(nil), buf[:n]...)
		if b.rejectIPv6 {
			if resp, ok := aaaaNoData(q); ok {
				b.stats.aaaaBlocked.Add(1)
				_, _ = local.Write(resp)
				continue
			}
		}
		go func() {
			resp, err := b.resolve(q)
			if err != nil {
				b.stats.dohFailed(err)
				return
			}
			b.stats.dnsAnswers.Add(1)
			_, _ = local.Write(resp)
		}()
	}
}

// resolve answers one DNS query with Xray's DNS client. Each query used to be
// its own UDP flow through the proxy (a new XHTTP request), which the
// event-driven VPN tunnel turned around too slowly: lookups timed out and Edge
// showed "can't reach this page". Xray's DoH client reuses one connection.
func (b *bridge) resolve(q []byte) ([]byte, error) {
	name, qtype, end, ok := dnsQuestion(q)
	if !ok {
		return nil, errors.New("unparsable DNS query")
	}
	if qtype != dnsTypeA && qtype != dnsTypeAAAA {
		return dnsResponse(q, end, qtype, nil, 0, 0), nil // NODATA for HTTPS/SVCB/MX/...
	}
	option := dns.IPOption{IPv4Enable: qtype == dnsTypeA, IPv6Enable: qtype == dnsTypeAAAA}
	ips, ttl, err := b.resolver.LookupIP(name, option)
	if err != nil {
		if stderrors.Is(err, dns.ErrEmptyResponse) {
			return dnsResponse(q, end, qtype, nil, 60, 0), nil
		}
		return dnsResponse(q, end, qtype, nil, 0, 3), err // NXDOMAIN-ish, but report the error
	}
	if ttl == 0 || ttl > 600 {
		ttl = 300
	}
	var raw [][]byte
	for _, ip := range ips {
		if v4 := ip.To4(); qtype == dnsTypeA && v4 != nil {
			raw = append(raw, v4)
		} else if qtype == dnsTypeAAAA && v4 == nil && len(ip) == 16 {
			raw = append(raw, ip)
		}
	}
	return dnsResponse(q, end, qtype, raw, ttl, 0), nil
}
