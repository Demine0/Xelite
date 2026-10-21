package main

import "encoding/binary"

const dnsTypeAAAA = 28

// aaaaNoData answers a DNS query for IPv6 addresses (AAAA) with "no such
// record" (NOERROR, no answers). While IPv6 is rejected, handing out AAAA
// records makes Windows try IPv6 first and wait ~21 s for the connect to time
// out before falling back to IPv4, so pages fail to load. Returns false for
// anything that is not a single-question AAAA query.
func aaaaNoData(q []byte) ([]byte, bool) {
	const header = 12
	if len(q) < header+5 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil, false // not a query, or not exactly one question
	}
	// Walk the question name (labels; compression pointers don't occur in queries).
	i := header
	for {
		if i >= len(q) {
			return nil, false
		}
		l := int(q[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 {
			return nil, false
		}
		i += 1 + l
	}
	if i+4 > len(q) || binary.BigEndian.Uint16(q[i:i+2]) != dnsTypeAAAA {
		return nil, false
	}
	end := i + 4 // header + question
	resp := make([]byte, end)
	copy(resp, q[:end])
	resp[2] = 0x80 | (q[2] & 0x79)             // QR=1, keep opcode and RD
	resp[3] = 0x80                             // RA=1, RCODE=NOERROR
	binary.BigEndian.PutUint16(resp[6:8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT
	return resp, true
}
