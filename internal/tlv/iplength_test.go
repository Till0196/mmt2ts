// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tlv

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func udpPacket(dstPort uint16, length int, payload string) []byte {
	b := make([]byte, udpHeader+len(payload))
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint16(b[4:6], uint16(length))
	copy(b[udpHeader:], payload)
	return b
}

func ipv4Packet(total int, body []byte) []byte {
	b := make([]byte, ipv4MinHeader)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[9] = protoUDP
	return append(b, body...)
}

func ipv6Packet(payloadLen int, body []byte) []byte {
	b := make([]byte, ipv6Header)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(payloadLen))
	b[6] = protoUDP
	return append(b, body...)
}

func firstDatagram(t *testing.T, typ byte, body []byte) (*Reader, Datagram, bool) {
	t.Helper()
	var in bytes.Buffer
	in.Write(packet(typ, body))
	r := NewReader(&in)
	p, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	d, ok := r.Datagram(p)
	return r, d, ok
}

func TestIPv4DeclaredLengthBoundsTheDatagram(t *testing.T) {
	udp := udpPacket(1234, udpHeader+3, "mmt")
	body := append(ipv4Packet(ipv4MinHeader+len(udp), udp), 0xde, 0xad, 0xbe, 0xef)
	r, d, ok := firstDatagram(t, TypeIPv4, body)
	if !ok {
		t.Fatalf("well-formed IPv4 packet was rejected, stats = %+v", r.Stats())
	}
	if d.DstPort != 1234 || string(d.Payload) != "mmt" {
		t.Fatalf("datagram = %+v", d)
	}
}

func TestIPv4RejectsImpossibleTotalLength(t *testing.T) {
	udp := udpPacket(1234, udpHeader+3, "mmt")
	cases := []struct {
		name  string
		total int
	}{
		{"shorter than the headers it claims", ipv4MinHeader + udpHeader - 1},
		{"shorter than a header at all", 0},
		{"longer than the bytes received", ipv4MinHeader + len(udp) + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _, ok := firstDatagram(t, TypeIPv4, ipv4Packet(tc.total, udp))
			if ok {
				t.Fatalf("total_length %d was accepted", tc.total)
			}
			if s := r.Stats(); s.MalformedIP != 1 {
				t.Fatalf("malformed IP count = %d", s.MalformedIP)
			}
		})
	}
}

func TestIPv6DeclaredLengthBoundsTheDatagram(t *testing.T) {
	udp := udpPacket(1234, udpHeader+3, "mmt")
	body := append(ipv6Packet(len(udp), udp), 0xde, 0xad)
	r, d, ok := firstDatagram(t, TypeIPv6, body)
	if !ok {
		t.Fatalf("well-formed IPv6 packet was rejected, stats = %+v", r.Stats())
	}
	if d.DstPort != 1234 || string(d.Payload) != "mmt" {
		t.Fatalf("datagram = %+v", d)
	}
}

func TestIPv6RejectsImpossiblePayloadLength(t *testing.T) {
	udp := udpPacket(1234, udpHeader+3, "mmt")
	cases := []struct {
		name       string
		payloadLen int
	}{
		{"shorter than a UDP header", udpHeader - 1},
		{"zero", 0},
		{"longer than the bytes received", len(udp) + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _, ok := firstDatagram(t, TypeIPv6, ipv6Packet(tc.payloadLen, udp))
			if ok {
				t.Fatalf("payload_length %d was accepted", tc.payloadLen)
			}
			if s := r.Stats(); s.MalformedIP != 1 {
				t.Fatalf("malformed IP count = %d", s.MalformedIP)
			}
		})
	}
}

func TestUDPLengthMustAgreeWithTheIPPayload(t *testing.T) {
	cases := []struct {
		name   string
		length int
	}{
		{"below the header size", udpHeader - 1},
		{"zero", 0},
		{"past the IP payload", udpHeader + 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			udp := udpPacket(1234, tc.length, "mmt")
			r, _, ok := firstDatagram(t, TypeIPv4, ipv4Packet(ipv4MinHeader+len(udp), udp))
			if ok {
				t.Fatalf("UDP length %d was accepted", tc.length)
			}
			if s := r.Stats(); s.MalformedIP != 1 {
				t.Fatalf("malformed IP count = %d", s.MalformedIP)
			}
		})
	}
}

func TestUDPLengthShorterThanTheIPPayloadTrimsIt(t *testing.T) {
	udp := udpPacket(1234, udpHeader+3, "mmt")
	udp = append(udp, 0, 0, 0, 0)
	r, d, ok := firstDatagram(t, TypeIPv4, ipv4Packet(ipv4MinHeader+len(udp), udp))
	if !ok {
		t.Fatalf("packet was rejected, stats = %+v", r.Stats())
	}
	if string(d.Payload) != "mmt" {
		t.Fatalf("payload = %q, want the UDP length to bound it", d.Payload)
	}
}

func TestIPv4WithOptionsUsesTheFullHeaderLength(t *testing.T) {
	udp := udpPacket(1234, udpHeader+3, "mmt")
	ip := make([]byte, 24)
	ip[0] = 0x46
	binary.BigEndian.PutUint16(ip[2:4], uint16(24+len(udp)))
	ip[9] = protoUDP
	r, d, ok := firstDatagram(t, TypeIPv4, append(ip, udp...))
	if !ok {
		t.Fatalf("packet with IP options was rejected, stats = %+v", r.Stats())
	}
	if string(d.Payload) != "mmt" {
		t.Fatalf("payload = %q", d.Payload)
	}
}

func fragmentedIPv4(id uint16, offset int, more bool, payload []byte) []byte {
	b := make([]byte, ipv4MinHeader)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)+len(payload)))
	binary.BigEndian.PutUint16(b[4:6], id)
	field := uint16(offset / 8)
	if more {
		field |= 0x2000
	}
	binary.BigEndian.PutUint16(b[6:8], field)
	b[9] = protoUDP
	copy(b[12:16], []byte{192, 0, 2, 1})
	copy(b[16:20], []byte{233, 0, 0, 1})
	return b
}

func TestIPv4FragmentsAreReassembledOutOfOrder(t *testing.T) {
	udp := udpPacket(1234, udpHeader+8, "abcdefgh")
	first, last := udp[:8], udp[8:]
	var in bytes.Buffer
	in.Write(packet(TypeIPv4, append(fragmentedIPv4(7, 8, false, last), last...)))
	in.Write(packet(TypeIPv4, append(fragmentedIPv4(7, 0, true, first), first...)))
	r := NewReader(&in)
	p, _ := r.Next()
	if _, ok := r.Datagram(p); ok {
		t.Fatal("an incomplete fragmented datagram was emitted")
	}
	p, _ = r.Next()
	d, ok := r.Datagram(p)
	if !ok || d.DstPort != 1234 || string(d.Payload) != "abcdefgh" {
		t.Fatalf("datagram = %+v, ok = %v", d, ok)
	}
	if s := r.Stats(); s.FragmentPackets != 2 || s.ReassembledIP != 1 || s.FragmentErrors != 0 {
		t.Fatalf("fragment stats = %+v", s)
	}
}

func TestConflictingIPv4FragmentOverlapIsRejected(t *testing.T) {
	first := []byte("12345678abcdefgh")
	conflict := []byte("Xbcdefgh")
	var in bytes.Buffer
	in.Write(packet(TypeIPv4, append(fragmentedIPv4(8, 0, true, first), first...)))
	in.Write(packet(TypeIPv4, append(fragmentedIPv4(8, 8, false, conflict), conflict...)))
	r := NewReader(&in)
	for range 2 {
		p, _ := r.Next()
		if _, ok := r.Datagram(p); ok {
			t.Fatal("overlapping fragments yielded a datagram")
		}
	}
	if got := r.Stats().FragmentErrors; got != 1 {
		t.Fatalf("FragmentErrors = %d, want 1", got)
	}
}

func fragmentedIPv6(id uint32, offset int, more bool, payload []byte) []byte {
	b := make([]byte, ipv6Header+8)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(8+len(payload)))
	b[6] = protoIPv6Fragment
	b[40] = protoUDP
	field := uint16(offset)
	if more {
		field |= 1
	}
	binary.BigEndian.PutUint16(b[42:44], field)
	binary.BigEndian.PutUint32(b[44:48], id)
	copy(b[8:24], testSrc)
	copy(b[24:40], testDst)
	return append(b, payload...)
}

func TestIPv6FragmentsAreReassembled(t *testing.T) {
	udp := udpPacket(1234, udpHeader+8, "abcdefgh")
	var in bytes.Buffer
	in.Write(packet(TypeIPv6, fragmentedIPv6(9, 0, true, udp[:8])))
	in.Write(packet(TypeIPv6, fragmentedIPv6(9, 8, false, udp[8:])))
	r := NewReader(&in)
	p, _ := r.Next()
	if _, ok := r.Datagram(p); ok {
		t.Fatal("an incomplete IPv6 datagram was emitted")
	}
	p, _ = r.Next()
	d, ok := r.Datagram(p)
	if !ok || d.DstPort != 1234 || string(d.Payload) != "abcdefgh" || !bytes.Equal(d.Dst, testDst) {
		t.Fatalf("datagram = %+v, ok = %v", d, ok)
	}
}
