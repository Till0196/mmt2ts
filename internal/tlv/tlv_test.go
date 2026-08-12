// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tlv

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func packet(typ byte, payload []byte) []byte {
	out := []byte{SyncByte, typ, 0, 0}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)))
	return append(out, payload...)
}

func TestReaderResyncAndNullPackets(t *testing.T) {
	var in bytes.Buffer
	in.Write([]byte{0x00, 0x11, 0x22})
	in.Write(packet(TypeNull, []byte{0xff, 0xff}))
	in.Write(packet(TypeCompressedIP, append([]byte{0x00, 0x00, 0x61}, 'a', 'b')))
	r := NewReader(&in)
	p, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	d, ok := r.Datagram(p)
	if !ok || string(d.Payload) != "ab" {
		t.Fatalf("payload = %q, ok = %v", d.Payload, ok)
	}
	if d.HasPort {
		t.Fatal("a compressed packet without a header cannot report a port")
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("err = %v, want EOF", err)
	}
	s := r.Stats()
	if s.Resyncs != 1 || s.NullPackets != 1 || s.Packets != 2 || s.CompressedIPv6 != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestDatagramFromCompressedIPv6(t *testing.T) {
	payload := make([]byte, 45+4)
	payload[2] = 0x60
	binary.BigEndian.PutUint16(payload[41:43], 5000)
	binary.BigEndian.PutUint16(payload[43:45], 123)
	copy(payload[45:], "ntp!")
	var in bytes.Buffer
	in.Write(packet(TypeCompressedIP, payload))
	r := NewReader(&in)
	p, _ := r.Next()
	d, ok := r.Datagram(p)
	if !ok || !d.HasPort || d.DstPort != 123 || !d.IsNTP() {
		t.Fatalf("datagram = %+v, ok = %v", d, ok)
	}
	if string(d.Payload) != "ntp!" {
		t.Fatalf("payload = %q", d.Payload)
	}
}

func TestDatagramFromIPv6UDP(t *testing.T) {
	udp := make([]byte, 8+3)
	binary.BigEndian.PutUint16(udp[2:4], 1234)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], "mmt")
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(udp)))
	ip[6] = protoUDP
	var in bytes.Buffer
	in.Write(packet(TypeIPv6, append(ip, udp...)))
	r := NewReader(&in)
	p, _ := r.Next()
	d, ok := r.Datagram(p)
	if !ok || d.DstPort != 1234 || string(d.Payload) != "mmt" {
		t.Fatalf("datagram = %+v, ok = %v", d, ok)
	}
}

func TestUnknownFramingIsCountedNotDropped(t *testing.T) {
	var in bytes.Buffer
	in.Write(packet(0x7e, []byte{1, 2, 3}))
	in.Write(packet(TypeCompressedIP, []byte{0x00, 0x00, 0x7f}))
	in.Write(packet(TypeControl, []byte{1}))
	r := NewReader(&in)
	for range 3 {
		p, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := r.Datagram(p); ok {
			t.Fatalf("type %#02x should not yield a datagram", p.Type)
		}
	}
	s := r.Stats()
	if s.UnknownType[0x7e] != 1 || s.UnknownCIDHeader[0x7f] != 1 || s.ControlPackets != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestNetworkIDFromActualNIT(t *testing.T) {
	section := []byte{0x40, 0xb0, 0x0d, 0x00, 0x0b, 0xc1, 0x00, 0x00, 0xf0, 0x00, 0xf0, 0x00, 0, 0, 0, 0}
	got, ok := NetworkID(section)
	if !ok || got != 0x000b {
		t.Fatalf("NetworkID() = %#04x, %v", got, ok)
	}
	section[0] = 0x41
	if _, ok := NetworkID(section); ok {
		t.Fatal("other-network NIT must not identify the input network")
	}
	section[0], section[5] = 0x40, 0xc0
	if _, ok := NetworkID(section); ok {
		t.Fatal("next NIT must not be used before it becomes current")
	}
}

func TestTruncatedPacketStopsCleanly(t *testing.T) {
	var in bytes.Buffer
	full := packet(TypeCompressedIP, append([]byte{0x00, 0x00, 0x61}, 'x'))
	in.Write(full)
	in.Write(full[:len(full)-2])
	r := NewReader(&in)
	if _, err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("err = %v, want EOF", err)
	}
	if s := r.Stats(); s.TruncatedPackets != 1 {
		t.Fatalf("truncated = %d", s.TruncatedPackets)
	}
}
