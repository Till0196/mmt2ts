// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package mmtp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func header(counter, extension bool) []byte {
	h := make([]byte, 12)
	if counter {
		h[0] |= 0x20
	}
	if extension {
		h[0] |= 0x02
	}
	h[0] |= 0x01
	h[1] = PayloadTypeMPU
	binary.BigEndian.PutUint16(h[2:4], 0xf100)
	binary.BigEndian.PutUint32(h[4:8], 0x11223344)
	binary.BigEndian.PutUint32(h[8:12], 7)
	return h
}

func TestParseHeaderVariants(t *testing.T) {
	plain := append(header(false, false), 'p', 'a', 'y')
	p, err := Parse(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !p.RAP || p.PacketID != 0xf100 || p.SequenceNumber != 7 || p.Timestamp != 0x11223344 {
		t.Fatalf("packet = %+v", p)
	}
	if string(p.Payload) != "pay" {
		t.Fatalf("payload = %q", p.Payload)
	}

	withExt := header(true, true)
	withExt = binary.BigEndian.AppendUint32(withExt, 42)
	ext := []byte{0x80, 0x01, 0x00, 0x01, 0xe0}
	withExt = binary.BigEndian.AppendUint16(withExt, 0x0000)
	withExt = binary.BigEndian.AppendUint16(withExt, uint16(len(ext)))
	withExt = append(withExt, ext...)
	withExt = append(withExt, 'x')
	p, err = Parse(withExt)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasCounter || p.PacketCounter != 42 {
		t.Fatalf("counter = %d, has = %v", p.PacketCounter, p.HasCounter)
	}
	if p.Scrambled {
		t.Fatal("a clear scramble extension must not mark the packet scrambled")
	}
	if string(p.Payload) != "x" {
		t.Fatalf("payload = %q", p.Payload)
	}

	scrambled := bytes.Clone(withExt)
	scrambled[len(scrambled)-2] = 0xe8
	p, _ = Parse(scrambled)
	if !p.Scrambled {
		t.Fatal("scrambling control was ignored")
	}
}

func TestParseRejectsShortInput(t *testing.T) {
	if _, err := Parse(make([]byte, 11)); err != ErrShortPacket {
		t.Fatalf("err = %v", err)
	}
	h := header(false, true)
	h = binary.BigEndian.AppendUint16(h, 0)
	h = binary.BigEndian.AppendUint16(h, 8)
	if _, err := Parse(h); err != ErrBadExtension {
		t.Fatalf("err = %v", err)
	}
}

func TestParseValidatesALFECHeaderPair(t *testing.T) {
	repair := header(false, false)
	repair[0] = repair[0]&^0x18 | 2<<3
	repair[1] = PayloadTypeRepair
	if p, err := Parse(append(repair, "symbol"...)); err != nil || p.FECType != 2 {
		t.Fatalf("repair packet = %+v, err = %v", p, err)
	}
	bad := bytes.Clone(repair)
	bad[0] = bad[0]&^0x18 | 1<<3
	if _, err := Parse(bad); err != ErrBadFEC {
		t.Fatalf("source packet carrying repair payload: err = %v", err)
	}
	reserved := header(false, false)
	reserved[0] = reserved[0]&^0x18 | 3<<3
	if _, err := Parse(reserved); err != ErrBadFEC {
		t.Fatalf("reserved FEC type: err = %v", err)
	}
}

func mfu(sample, offset uint32, data []byte) []byte {
	u := make([]byte, 14)
	binary.BigEndian.PutUint32(u[4:8], sample)
	binary.BigEndian.PutUint32(u[8:12], offset)
	return append(u, data...)
}

func TestParseMPUSingleAndAggregated(t *testing.T) {
	body := mfu(3, 16, []byte("nal"))
	single := []byte{0, 0, 0x28, 0}
	single = binary.BigEndian.AppendUint32(single, 99)
	single = append(single, body...)
	binary.BigEndian.PutUint16(single[:2], uint16(len(single)-2))
	p, err := ParseMPU(single, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.FragmentType != FragmentTypeMFU || !p.Timed || p.Aggregation || p.MPUSequence != 99 {
		t.Fatalf("payload = %+v", p)
	}
	if len(p.Units) != 1 || p.Units[0].Sample != 3 || p.Units[0].Offset != 16 || string(p.Units[0].Data) != "nal" {
		t.Fatalf("units = %+v", p.Units)
	}

	first, second := mfu(1, 0, []byte("aa")), mfu(2, 0, []byte("bbbb"))
	agg := []byte{0, 0, 0x29, 0}
	agg = binary.BigEndian.AppendUint32(agg, 100)
	agg = binary.BigEndian.AppendUint16(agg, uint16(len(first)))
	agg = append(agg, first...)
	agg = binary.BigEndian.AppendUint16(agg, uint16(len(second)))
	agg = append(agg, second...)
	binary.BigEndian.PutUint16(agg[:2], uint16(len(agg)-2))
	p, err = ParseMPU(agg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Aggregation || len(p.Units) != 2 {
		t.Fatalf("aggregated payload = %+v", p)
	}
	if string(p.Units[0].Data) != "aa" || string(p.Units[1].Data) != "bbbb" {
		t.Fatalf("aggregated units = %q %q", p.Units[0].Data, p.Units[1].Data)
	}
}

func TestParseMPURejectsBadLengths(t *testing.T) {
	short := []byte{0, 0, 0x28, 0, 0, 0, 0, 1}
	if _, err := ParseMPU(short, nil); err != ErrShortPayload {
		t.Fatalf("zero payload_length err = %v", err)
	}
	oversize := []byte{0xff, 0xff, 0x28, 0, 0, 0, 0, 1}
	if _, err := ParseMPU(oversize, nil); err != ErrShortPayload {
		t.Fatalf("oversize err = %v", err)
	}
}
