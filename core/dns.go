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

const (
	dnsTypeA     = 1
	dnsClassIN   = 1
	dnsMaxAnswer = 16
)

// dnsQuestion returns the queried name and type of a single-question query.
func dnsQuestion(q []byte) (name string, qtype uint16, end int, ok bool) {
	const header = 12
	if len(q) < header+5 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return "", 0, 0, false
	}
	var labels []byte
	i := header
	for {
		if i >= len(q) {
			return "", 0, 0, false
		}
		l := int(q[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 || i+1+l > len(q) {
			return "", 0, 0, false
		}
		if len(labels) > 0 {
			labels = append(labels, '.')
		}
		labels = append(labels, q[i+1:i+1+l]...)
		i += 1 + l
	}
	if i+4 > len(q) {
		return "", 0, 0, false
	}
	return string(labels), binary.BigEndian.Uint16(q[i : i+2]), i + 4, true
}

// dnsResponse builds an answer to query q (header + question up to end) with
// the given addresses as A or AAAA records; rcode 0 with no addresses is NODATA.
func dnsResponse(q []byte, end int, qtype uint16, ips [][]byte, ttl uint32, rcode byte) []byte {
	resp := make([]byte, end, end+len(ips)*28)
	copy(resp, q[:end])
	resp[2] = 0x80 | (q[2] & 0x79) // QR=1, keep opcode and RD
	resp[3] = 0x80 | rcode         // RA=1
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	n := 0
	for _, ip := range ips {
		if n == dnsMaxAnswer {
			break
		}
		resp = append(resp, 0xC0, 12) // name: pointer to the question
		resp = binary.BigEndian.AppendUint16(resp, qtype)
		resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
		resp = binary.BigEndian.AppendUint32(resp, ttl)
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(ip)))
		resp = append(resp, ip...)
		n++
	}
	binary.BigEndian.PutUint16(resp[6:8], uint16(n))
	return resp
}
