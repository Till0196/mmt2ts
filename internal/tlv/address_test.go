// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tlv

import (
	"bytes"
	"encoding/binary"
	"testing"
)

var (
	testSrc = []byte{0x24, 0x01, 0xdb, 0xc0, 0x10, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	testDst = []byte{0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa0, 0x00, 0x10, 0x00}
)

func partialIPv6(cid uint16, src, dst []byte, srcPort, dstPort uint16, payload []byte) []byte {
	b := make([]byte, 45)
	binary.BigEndian.PutUint16(b[0:2], cid<<4)
	b[2] = cidIPv6Partial
	b[3] = 0x60
	b[7] = protoUDP
	b[8] = 32
	copy(b[9:25], src)
	copy(b[25:41], dst)
	binary.BigEndian.PutUint16(b[41:43], srcPort)
	binary.BigEndian.PutUint16(b[43:45], dstPort)
	return packet(TypeCompressedIP, append(b, payload...))
}

func partialIPv4(cid uint16, src, dst []byte, srcPort, dstPort uint16, payload []byte) []byte {
	b := make([]byte, 23)
	binary.BigEndian.PutUint16(b[0:2], cid<<4)
	b[2] = cidIPv4Partial
	b[3] = 0x45
	b[9] = 64
	b[10] = protoUDP
	copy(b[11:15], src)
	copy(b[15:19], dst)
	binary.BigEndian.PutUint16(b[19:21], srcPort)
	binary.BigEndian.PutUint16(b[21:23], dstPort)
	return packet(TypeCompressedIP, append(b, payload...))
}

func headerless(cid uint16, payload []byte) []byte {
	b := make([]byte, 3)
	binary.BigEndian.PutUint16(b[0:2], cid<<4)
	b[2] = cidIPv6None
	return packet(TypeCompressedIP, append(b, payload...))
}

func TestAPartialCompressedHeaderCarriesItsAddressesAndPorts(t *testing.T) {
	var in bytes.Buffer
	in.Write(partialIPv6(0x0001, testSrc, testDst, 50000, 51216, []byte("mmt")))
	r := NewReader(&in)
	p, _ := r.Next()
	d, ok := r.Datagram(p)
	if !ok {
		t.Fatal("the partial header was not decoded")
	}
	if !bytes.Equal(d.Src, testSrc) || !bytes.Equal(d.Dst, testDst) {
		t.Errorf("src = %x, dst = %x", d.Src, d.Dst)
	}
	if d.SrcPort != 50000 || d.DstPort != 51216 || !d.HasPort {
		t.Errorf("ports = %d, %d, hasPort = %v", d.SrcPort, d.DstPort, d.HasPort)
	}
	if d.CID != 0x0001 || !d.HasCID {
		t.Errorf("CID = %#04x, hasCID = %v", d.CID, d.HasCID)
	}
	if string(d.Payload) != "mmt" {
		t.Errorf("payload = %q", d.Payload)
	}
}

func TestAPartialCompressedIPv4HeaderCarriesItsContext(t *testing.T) {
	src := []byte{192, 0, 2, 1}
	dst := []byte{233, 0, 0, 1}
	var in bytes.Buffer
	in.Write(partialIPv4(0x0123, src, dst, 50000, 51216, []byte("first")))
	b := make([]byte, 3)
	binary.BigEndian.PutUint16(b[:2], 0x0123<<4)
	b[2] = cidIPv4None
	in.Write(packet(TypeCompressedIP, append(b, []byte("second")...)))
	r := NewReader(&in)

	for i, want := range []string{"first", "second"} {
		p, err := r.Next()
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		d, ok := r.Datagram(p)
		if !ok {
			t.Fatalf("packet %d was not decoded", i)
		}
		if !bytes.Equal(d.Src, src) || !bytes.Equal(d.Dst, dst) ||
			d.SrcPort != 50000 || d.DstPort != 51216 || !d.HasPort {
			t.Fatalf("packet %d context = %+v", i, d)
		}
		if string(d.Payload) != want {
			t.Errorf("packet %d payload = %q, want %q", i, d.Payload, want)
		}
	}
	if got := r.Stats().CompressedIPv4; got != 2 {
		t.Errorf("compressed IPv4 packets = %d, want 2", got)
	}
}

func TestMalformedPartialCompressedIPv4HeadersAreRejected(t *testing.T) {
	src := []byte{192, 0, 2, 1}
	dst := []byte{233, 0, 0, 1}
	valid := partialIPv4(1, src, dst, 1000, 2000, nil)[4:]
	cases := []struct {
		name string
		body []byte
	}{
		{"truncated", valid[:22]},
		{"wrong version", func() []byte { b := bytes.Clone(valid); b[3] = 0x65; return b }()},
		{"short IHL", func() []byte { b := bytes.Clone(valid); b[3] = 0x44; return b }()},
		{"not UDP", func() []byte { b := bytes.Clone(valid); b[10] = 6; return b }()},
		{"fragment", func() []byte { b := bytes.Clone(valid); b[8] = 1; return b }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var in bytes.Buffer
			in.Write(packet(TypeCompressedIP, tc.body))
			r := NewReader(&in)
			p, err := r.Next()
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			if _, ok := r.Datagram(p); ok {
				t.Fatal("malformed partial IPv4 header was accepted")
			}
			if got := r.Stats().MalformedIP; got != 1 {
				t.Errorf("MalformedIP = %d, want 1", got)
			}
		})
	}
}

func TestHeaderlessPacketsInheritTheirContext(t *testing.T) {
	var in bytes.Buffer
	in.Write(partialIPv6(0x0001, testSrc, testDst, 50000, 51216, []byte("first")))
	in.Write(headerless(0x0001, []byte("second")))
	in.Write(headerless(0x0001, []byte("third")))
	r := NewReader(&in)

	for i, want := range []string{"first", "second", "third"} {
		p, err := r.Next()
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		d, ok := r.Datagram(p)
		if !ok {
			t.Fatalf("packet %d was not decoded", i)
		}
		if string(d.Payload) != want {
			t.Errorf("packet %d payload = %q, want %q", i, d.Payload, want)
		}
		if !bytes.Equal(d.Src, testSrc) || !bytes.Equal(d.Dst, testDst) {
			t.Errorf("packet %d: src = %x, dst = %x", i, d.Src, d.Dst)
		}
		if d.SrcPort != 50000 || d.DstPort != 51216 || !d.HasPort {
			t.Errorf("packet %d: ports = %d, %d", i, d.SrcPort, d.DstPort)
		}
	}
	if got := r.Stats().CompressedNoContext; got != 0 {
		t.Errorf("CompressedNoContext = %d, want 0", got)
	}
}

func TestAContextIsOnlyUsedForItsOwnCID(t *testing.T) {
	var in bytes.Buffer
	in.Write(partialIPv6(0x0001, testSrc, testDst, 50000, 51216, []byte("a")))
	in.Write(headerless(0x0002, []byte("b")))
	r := NewReader(&in)
	first, err := r.Next()
	if err != nil {
		t.Fatalf("first packet: %v", err)
	}
	if _, ok := r.Datagram(first); !ok {
		t.Fatal("the context packet was not decoded")
	}

	p, err := r.Next()
	if err != nil {
		t.Fatalf("second packet: %v", err)
	}
	d, ok := r.Datagram(p)
	if !ok || string(d.Payload) != "b" {
		t.Fatalf("datagram = %+v, ok = %v", d, ok)
	}
	if d.Src != nil || d.Dst != nil {
		t.Errorf("an unknown context produced addresses %x and %x", d.Src, d.Dst)
	}
	if d.HasPort {
		t.Error("an unknown context produced a port")
	}
	if got := r.Stats().CompressedNoContext; got != 1 {
		t.Errorf("CompressedNoContext = %d, want 1", got)
	}
}

func TestARepeatedContextReplacesTheOldAddresses(t *testing.T) {
	other := bytes.Clone(testDst)
	other[15] = 0x99
	var in bytes.Buffer
	in.Write(partialIPv6(0x0001, testSrc, testDst, 50000, 51216, []byte("a")))
	in.Write(partialIPv6(0x0001, testSrc, other, 50000, 51217, []byte("b")))
	in.Write(headerless(0x0001, []byte("c")))
	r := NewReader(&in)
	for range 2 {
		p, _ := r.Next()
		r.Datagram(p)
	}
	p, _ := r.Next()
	d, _ := r.Datagram(p)
	if !bytes.Equal(d.Dst, other) {
		t.Errorf("dst = %x, want the address the newer header established", d.Dst)
	}
	if d.DstPort != 51217 {
		t.Errorf("dst port = %d, want 51217", d.DstPort)
	}
}

func TestUncompressedPacketsReportTheirAddresses(t *testing.T) {
	udp := make([]byte, 8+3)
	binary.BigEndian.PutUint16(udp[0:2], 4321)
	binary.BigEndian.PutUint16(udp[2:4], 1234)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], "mmt")

	t.Run("IPv6", func(t *testing.T) {
		ip := make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(udp)))
		ip[6] = protoUDP
		copy(ip[8:24], testSrc)
		copy(ip[24:40], testDst)
		var in bytes.Buffer
		in.Write(packet(TypeIPv6, append(ip, udp...)))
		r := NewReader(&in)
		p, _ := r.Next()
		d, ok := r.Datagram(p)
		if !ok || !bytes.Equal(d.Src, testSrc) || !bytes.Equal(d.Dst, testDst) {
			t.Fatalf("src = %x, dst = %x, ok = %v", d.Src, d.Dst, ok)
		}
		if d.SrcPort != 4321 || d.DstPort != 1234 {
			t.Errorf("ports = %d, %d", d.SrcPort, d.DstPort)
		}
	})

	t.Run("IPv4", func(t *testing.T) {
		src4 := []byte{192, 0, 2, 1}
		dst4 := []byte{233, 0, 0, 1}
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(udp)))
		ip[9] = protoUDP
		copy(ip[12:16], src4)
		copy(ip[16:20], dst4)
		var in bytes.Buffer
		in.Write(packet(TypeIPv4, append(ip, udp...)))
		r := NewReader(&in)
		p, _ := r.Next()
		d, ok := r.Datagram(p)
		if !ok || !bytes.Equal(d.Src, src4) || !bytes.Equal(d.Dst, dst4) {
			t.Fatalf("src = %x, dst = %x, ok = %v", d.Src, d.Dst, ok)
		}
	})
}
