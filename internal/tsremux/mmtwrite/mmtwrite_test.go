// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package mmtwrite

import (
	"bytes"
	"testing"
)

func TestBuildPacketSetsRequiredReservedBits(t *testing.T) {
	p := BuildPacket(Header{PayloadType: PayloadTypeSignaling, PacketID: 1}, nil)
	if p[0]&0x04 == 0 {
		t.Fatalf("MMTP byte 0 = %#02x: reserved bit is zero", p[0])
	}
	if p[1]&0xc0 != 0xc0 {
		t.Fatalf("MMTP byte 1 = %#02x: reserved bits are not 11", p[1])
	}
	if p[1]&0x3f != PayloadTypeSignaling {
		t.Fatalf("payload_type = %#02x", p[1]&0x3f)
	}
}

func TestBuildPacketClearScrambleExtension(t *testing.T) {
	p := BuildPacket(Header{PayloadType: PayloadTypeMPU, PacketID: 0xf110,
		Extension: ClearScrambleExtension}, []byte{0xaa})
	if p[0]&0x02 == 0 {
		t.Fatal("extension_flag is not set")
	}
	want := []byte{0, 0, 0, 5, 0x80, 1, 0, 1, 0xe0}
	if got := p[12:21]; !bytes.Equal(got, want) {
		t.Fatalf("extension = %x, want %x", got, want)
	}
}

func TestWrapSignallingSetsRequiredReservedBits(t *testing.T) {
	p := WrapSignalling([]byte{1, 2, 3})
	if p[0] != 0x3c || p[1] != 0 {
		t.Fatalf("signalling payload header = % x, want 3c 00", p[:2])
	}
}
