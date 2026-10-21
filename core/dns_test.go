package main

import (
	"encoding/binary"
	"testing"
)

func query(qtype uint16) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	q = append(q, 3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0)
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(q, qtype), 1)
}

func TestAAAANoData(t *testing.T) {
	resp, ok := aaaaNoData(query(dnsTypeAAAA))
	if !ok {
		t.Fatal("AAAA query not answered")
	}
	if resp[0] != 0x12 || resp[1] != 0x34 || resp[2]&0x80 == 0 || resp[3]&0x0F != 0 {
		t.Fatalf("bad header % x", resp[:4])
	}
	if binary.BigEndian.Uint16(resp[4:6]) != 1 || binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Fatalf("want 1 question 0 answers, got % x", resp[4:8])
	}
	if _, ok := aaaaNoData(query(1)); ok {
		t.Fatal("A query must be forwarded")
	}
	if _, ok := aaaaNoData([]byte{1, 2, 3}); ok {
		t.Fatal("garbage must be forwarded")
	}
}
