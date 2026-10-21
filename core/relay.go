package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	stdnet "net"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// relayDialer replaces Xray's system dialer. On Windows 10 Mobile a process
// started by the VPN plug-in may not open its own sockets to the internet
// (connect fails with WSAEACCES), so every outbound connection is handed to
// the plug-in, which opens it with a WinRT socket and pipes the bytes:
//
//	core -> plug-in (TCP, loopback): "TCP 1.2.3.4:443\n" or "UDP 1.2.3.4:443\n"
//	plug-in -> core:                 "OK\n" or "ERR <message>\n"
//
// After OK a TCP connection is a raw byte pipe; a UDP one carries datagrams
// framed as a 2-byte big-endian length followed by the payload.
type relayDialer struct {
	addr  string // plug-in relay listener, 127.0.0.1:port
	stats *stats
}

var _ internet.SystemDialer = (*relayDialer)(nil)

const relayHandshakeTimeout = 15 * time.Second

func (d *relayDialer) Dial(ctx context.Context, _ xnet.Address, dest xnet.Destination, _ *internet.SocketConfig) (stdnet.Conn, error) {
	network := "TCP"
	if dest.Network == xnet.Network_UDP {
		network = "UDP"
	}
	var nd stdnet.Dialer
	c, err := nd.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, errors.New("relay: cannot reach the VPN plug-in").Base(err)
	}
	_ = c.SetDeadline(time.Now().Add(relayHandshakeTimeout))
	if _, err := fmt.Fprintf(c, "%s %s\n", network, dest.NetAddr()); err != nil {
		c.Close()
		return nil, errors.New("relay: request failed").Base(err)
	}
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		c.Close()
		return nil, errors.New("relay: no answer from the VPN plug-in").Base(err)
	}
	line = strings.TrimSpace(line)
	if line != "OK" {
		c.Close()
		err := errors.New("relay: ", network, " ", dest.NetAddr(), ": ", strings.TrimPrefix(line, "ERR "))
		if d.stats != nil {
			d.stats.dialFailed(dest, err)
		}
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	if d.stats != nil {
		d.stats.relayed.Add(1)
	}
	bc := &bufferedConn{Conn: c, r: r}
	if network == "UDP" {
		return &frameConn{bufferedConn: bc}, nil
	}
	return bc, nil
}

func (d *relayDialer) DestIpAddress() stdnet.IP { return nil }

// bufferedConn keeps bytes that bufio read past the handshake line.
type bufferedConn struct {
	stdnet.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// CloseWrite lets Xray half-close relayed TCP connections.
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// frameConn carries one datagram per Read/Write over the relay stream.
type frameConn struct {
	*bufferedConn
	wmu sync.Mutex
}

func (c *frameConn) Read(b []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n <= len(b) {
		return io.ReadFull(c.r, b[:n])
	}
	// Datagram larger than the buffer: deliver what fits, drop the rest.
	if _, err := io.ReadFull(c.r, b); err != nil {
		return 0, err
	}
	_, err := c.r.Discard(n - len(b))
	return len(b), err
}

func (c *frameConn) Write(b []byte) (int, error) {
	if len(b) > 0xFFFF {
		return 0, errors.New("relay: datagram too large")
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.Conn.Write(buf); err != nil {
		return 0, err
	}
	return len(b), nil
}
