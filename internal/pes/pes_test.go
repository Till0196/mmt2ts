// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package pes

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func readTimestamp(b []byte) int64 {
	return int64(b[0]&0x0e)<<29 | int64(b[1])<<22 | int64(b[2]&0xfe)<<14 | int64(b[3])<<7 | int64(b[4])>>1
}

func TestBuildVideoWithPTSAndDTS(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 32)
	got := Build(Packet{
		StreamID: StreamIDVideo, PTS: 1 << 32, DTS: 90000, HasPTS: true, HasDTS: true,
		Aligned: true, Payload: payload,
	})
	if !bytes.Equal(got[:4], []byte{0, 0, 1, StreamIDVideo}) {
		t.Fatalf("start code = % x", got[:4])
	}
	length := int(binary.BigEndian.Uint16(got[4:6]))
	if length != len(got)-6 {
		t.Fatalf("PES_packet_length = %d, want %d", length, len(got)-6)
	}
	if got[6]&0xc0 != 0x80 || got[6]&0x04 == 0 {
		t.Fatalf("marker byte = %#02x", got[6])
	}
	if got[7]>>6 != 0x03 || got[8] != 10 {
		t.Fatalf("flags = %#02x, header length = %d", got[7], got[8])
	}
	if got[9]>>4 != 0x03 || got[14]>>4 != 0x01 {
		t.Fatalf("timestamp prefixes = %#02x %#02x", got[9], got[14])
	}
	if pts := readTimestamp(got[9:14]); pts != 1<<32 {
		t.Fatalf("PTS = %d", pts)
	}
	if dts := readTimestamp(got[14:19]); dts != 90000 {
		t.Fatalf("DTS = %d", dts)
	}
	for i := 9; i < 19; i++ {
		if got[i]&0x01 == 0 && (i-9)%5 != 1 && (i-9)%5 != 3 {
			t.Fatalf("marker bit missing at %d", i)
		}
	}
	if !bytes.Equal(got[19:], payload) {
		t.Fatal("payload changed")
	}
}

func TestBuildAudioWithPTSOnly(t *testing.T) {
	got := Build(Packet{StreamID: StreamIDAudio, PTS: 12345, HasPTS: true, Aligned: true, Payload: []byte{1, 2, 3}})
	if got[3] != StreamIDAudio || got[7]>>6 != 0x02 || got[8] != 5 {
		t.Fatalf("header = % x", got[:9])
	}
	if pts := readTimestamp(got[9:14]); pts != 12345 {
		t.Fatalf("PTS = %d", pts)
	}
	if int(binary.BigEndian.Uint16(got[4:6])) != len(got)-6 {
		t.Fatalf("length = %d", binary.BigEndian.Uint16(got[4:6]))
	}
}

func TestLargePayloadUsesZeroLength(t *testing.T) {
	got := Build(Packet{
		StreamID: StreamIDVideo, PTS: 1, DTS: 1, HasPTS: true, HasDTS: true,
		Payload: make([]byte, 70000),
	})
	if binary.BigEndian.Uint16(got[4:6]) != 0 {
		t.Fatalf("PES_packet_length = %d, want 0 for an oversize video access unit",
			binary.BigEndian.Uint16(got[4:6]))
	}
}

func TestTimestampWrapIsModulo(t *testing.T) {
	got := Build(Packet{StreamID: StreamIDAudio, PTS: 1<<33 + 7, HasPTS: true, Payload: []byte{0}})
	if pts := readTimestamp(got[9:14]); pts != 7 {
		t.Fatalf("wrapped PTS = %d, want 7", pts)
	}
}

func TestBuildCaptionWithPrivateData(t *testing.T) {
	private := []byte{'C', 'C', 'I', 'S', 1, 0x3f, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	payload := []byte{0x80, 0xff, 0xf0}
	got := Build(Packet{
		StreamID: StreamIDPrivate1, PTS: 90000, HasPTS: true, Aligned: true,
		PrivateData: private, Stuffing: 1, Payload: payload,
	})
	if got[7] != 0x81 || got[8] != 23 {
		t.Fatalf("flags = %#02x, header length = %d", got[7], got[8])
	}
	if got[14] != 0x8e || !bytes.Equal(got[15:31], private) || got[31] != 0xff {
		t.Fatalf("PES extension = % x", got[14:32])
	}
	if !bytes.Equal(got[32:], payload) {
		t.Fatalf("payload = % x", got[32:])
	}
	if int(binary.BigEndian.Uint16(got[4:6])) != len(got)-6 {
		t.Fatalf("length = %d", binary.BigEndian.Uint16(got[4:6]))
	}
}
