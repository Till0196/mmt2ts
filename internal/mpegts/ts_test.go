// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package mpegts

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func crcReference(b []byte) uint32 {
	crc := uint32(0xffffffff)
	for _, v := range b {
		for i := 7; i >= 0; i-- {
			bit := uint32((v >> uint(i)) & 1)
			top := crc >> 31
			crc <<= 1
			if top^bit != 0 {
				crc ^= 0x04c11db7
			}
		}
	}
	return crc
}

func TestCRC32MatchesBitwise(t *testing.T) {
	for _, sample := range [][]byte{
		{},
		{0x00},
		{0x47, 0x40, 0x00, 0x10},
		[]byte("mmt2ts section payload"),
	} {
		if got, want := CRC32(sample), crcReference(sample); got != want {
			t.Fatalf("CRC32(% x) = %08x, want %08x", sample, got, want)
		}
	}
}

func TestSectionsCarryValidCRC(t *testing.T) {
	pat := BuildPAT(0x0001, 3, []Program{{Number: 1, PID: 0x0100}}, PIDNIT)
	if got := CRC32(pat); got != 0 {
		t.Fatalf("PAT CRC residue = %08x", got)
	}
	if pat[0] != TableIDPAT {
		t.Fatalf("PAT table id = %#02x", pat[0])
	}
	if length := int(binary.BigEndian.Uint16(pat[1:3]) & 0x0fff); length != len(pat)-3 {
		t.Fatalf("PAT section_length = %d, want %d", length, len(pat)-3)
	}
	if v := (pat[5] >> 1) & 0x1f; v != 3 {
		t.Fatalf("PAT version = %d", v)
	}
	if binary.BigEndian.Uint16(pat[8:10]) != 0 || binary.BigEndian.Uint16(pat[10:12])&0x1fff != PIDNIT {
		t.Fatalf("PAT network entry = % x", pat[8:12])
	}
	if binary.BigEndian.Uint16(pat[12:14]) != 1 || binary.BigEndian.Uint16(pat[14:16])&0x1fff != 0x0100 {
		t.Fatalf("PAT program entry = % x", pat[12:16])
	}

	pmt := BuildPMT(1, 5, 0x1011, nil, []ElementaryStream{
		{StreamType: StreamTypeHEVC, PID: 0x1011, Descriptors: StreamIdentifierDescriptor(0)},
		{StreamType: StreamTypeADTSAAC, PID: 0x1100, Descriptors: StreamIdentifierDescriptor(0x10)},
	})
	if got := CRC32(pmt); got != 0 {
		t.Fatalf("PMT CRC residue = %08x", got)
	}
	if pcr := binary.BigEndian.Uint16(pmt[8:10]) & 0x1fff; pcr != 0x1011 {
		t.Fatalf("PCR PID = %#04x", pcr)
	}

}

func TestWriteUnitPacketisation(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	payload := bytes.Repeat([]byte{0xab}, 400)
	if err := w.WriteUnit(0x1011, payload, Adaptation{HasPCR: true, PCR: 27000000, RandomAccess: true}); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if len(out)%PacketSize != 0 || len(out) != 3*PacketSize {
		t.Fatalf("wrote %d bytes", len(out))
	}
	var recovered []byte
	for i := 0; i < len(out); i += PacketSize {
		p := out[i : i+PacketSize]
		if p[0] != SyncByte {
			t.Fatalf("packet %d has no sync byte", i/PacketSize)
		}
		if pid := binary.BigEndian.Uint16(p[1:3]) & 0x1fff; pid != 0x1011 {
			t.Fatalf("PID = %#04x", pid)
		}
		start := p[1]&0x40 != 0
		if start != (i == 0) {
			t.Fatalf("payload_unit_start_indicator on packet %d = %v", i/PacketSize, start)
		}
		if cc := p[3] & 0x0f; int(cc) != i/PacketSize {
			t.Fatalf("continuity counter = %d on packet %d", cc, i/PacketSize)
		}
		body := p[4:]
		if p[3]&0x20 != 0 {
			body = p[5+int(p[4]):]
		}
		recovered = append(recovered, body...)
	}
	if !bytes.Equal(recovered, payload) {
		t.Fatalf("payload round trip failed: %d bytes recovered", len(recovered))
	}
	if out[3]&0x20 == 0 || out[5]&0x10 == 0 || out[5]&0x40 == 0 {
		t.Fatalf("first packet adaptation flags = %#02x %#02x", out[3], out[5])
	}
	base := int64(out[6])<<25 | int64(out[7])<<17 | int64(out[8])<<9 | int64(out[9])<<1 | int64(out[10]>>7)
	if base != 90000 {
		t.Fatalf("PCR base = %d, want 90000", base)
	}
}

func TestWriteSectionAndNull(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	pat := BuildPAT(1, 0, []Program{{Number: 1, PID: 0x0100}}, 0)
	if err := w.WriteSection(PIDPAT, pat); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteNull(); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if len(out) != 2*PacketSize {
		t.Fatalf("wrote %d bytes", len(out))
	}
	if out[1]&0x40 == 0 || out[4] != 0x00 {
		t.Fatalf("section packet header = % x", out[:6])
	}
	if !bytes.Equal(out[5:5+len(pat)], pat) {
		t.Fatalf("section payload mismatch")
	}
	if out[5+len(pat)] != 0xff {
		t.Fatalf("section padding = %#02x", out[5+len(pat)])
	}
	if pid := binary.BigEndian.Uint16(out[PacketSize+1:PacketSize+3]) & 0x1fff; pid != PIDNull {
		t.Fatalf("null PID = %#04x", pid)
	}
}

func TestAdaptationOnlyKeepsContinuityCounter(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	_ = w.WriteUnit(0x1011, []byte{1, 2, 3}, Adaptation{})
	_ = w.WriteAdaptationOnly(0x1011, Adaptation{HasPCR: true, PCR: 0})
	_ = w.WriteUnit(0x1011, []byte{4, 5, 6}, Adaptation{})
	_ = w.Flush()
	out := buf.Bytes()
	got := []byte{out[3] & 0x0f, out[PacketSize+3] & 0x0f, out[2*PacketSize+3] & 0x0f}
	if want := []byte{0, 0, 1}; !bytes.Equal(got, want) {
		t.Fatalf("continuity counters = %v, want %v", got, want)
	}
	if afc := (out[PacketSize+3] >> 4) & 0x03; afc != afcAdaptation {
		t.Fatalf("adaptation-only packet afc = %d", afc)
	}
}

func TestCRC32MatchesBitwiseAtEveryLength(t *testing.T) {
	buf := make([]byte, 64)
	for i := range buf {
		buf[i] = byte(i*7 + 1)
	}
	for n := 0; n <= len(buf); n++ {
		if got, want := CRC32(buf[:n]), crcReference(buf[:n]); got != want {
			t.Errorf("CRC32(%d bytes) = %#08x, want %#08x", n, got, want)
		}
	}

	big := make([]byte, MaxSectionLength)
	for i := range big {
		big[i] = byte(i * 31)
	}
	if got, want := CRC32(big), crcReference(big); got != want {
		t.Errorf("CRC32(%d bytes) = %#08x, want %#08x", len(big), got, want)
	}
}

func BenchmarkCRC32(b *testing.B) {
	buf := make([]byte, MaxSectionLength)
	for i := range buf {
		buf[i] = byte(i)
	}
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		CRC32(buf)
	}
}
