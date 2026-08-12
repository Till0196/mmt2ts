// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"testing"

	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/preservation"
)

const rawMediaTestNTP = uint64(0xebd83880) << 32

func rawMediaTestConverter(t *testing.T) (*converter, *stream, *preservation.Recorder) {
	t.Helper()
	rec, err := preservation.NewRecorder(preservation.Config{
		ServiceID: 0x66, TransportStreamID: 0x4010,
		RealtimePID: 0x1d00, ObjectPID: 0x1d01, RealtimeTag: 0xe0, ObjectTag: 0xe1,
	})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	rec.Observe(rawMediaTestNTP)
	c := &converter{currentNTP: rawMediaTestNTP, pres: &preserver{rec: rec}}
	s := &stream{assetType: "hev1", packetID: 0xf300, mmtTag: 0, hasMMTTag: true}
	return c, s, rec
}

func fragmentedMPU(fragment byte) []byte {
	p := mpuPayload(100, []byte{1, 2, 3, 4})
	p[2] = (p[2] &^ 0x06) | fragment<<1
	return p
}

func rawTestPacket(seq uint32, fragment byte, scrambled bool) mmtp.Packet {
	return mmtp.Packet{
		PacketID: 0xf300, SequenceNumber: seq,
		PayloadType: mmtp.PayloadTypeMPU, Payload: fragmentedMPU(fragment), Scrambled: scrambled,
	}
}

func TestRawMediaPreservesTheWholeMFUWithoutASpanID(t *testing.T) {
	c, s, rec := rawMediaTestConverter(t)

	c.preserveRawMedia(s, rawTestPacket(10, mmtp.FragmentIndicatorFirst, false), []byte("first"))
	if got := rec.Stats().Records; got != 0 {
		t.Fatalf("clear prefix produced %d records", got)
	}

	c.preserveRawMedia(s, rawTestPacket(11, mmtp.FragmentIndicatorMiddle, true), []byte("encrypted"))
	if got := rec.Stats().Records; got != 2 {
		t.Fatalf("prefix plus encrypted packet produced %d records, want 2", got)
	}
	if !s.rawMedia.poisoned || len(s.rawMedia.prefix) != 0 {
		t.Fatalf("state after encryption = %+v", s.rawMedia)
	}

	c.preserveRawMedia(s, rawTestPacket(12, mmtp.FragmentIndicatorMiddle, false), []byte("middle"))
	c.preserveRawMedia(s, rawTestPacket(13, mmtp.FragmentIndicatorLast, false), []byte("last"))
	if got := rec.Stats().Records; got != 4 {
		t.Fatalf("whole damaged MFU produced %d records, want 4", got)
	}
	if s.rawMedia.poisoned {
		t.Fatal("last fragment did not close the recovery run")
	}

	c.preserveRawMedia(s, rawTestPacket(14, mmtp.FragmentIndicatorComplete, false), []byte("next"))
	if got := rec.Stats().Records; got != 4 {
		t.Fatalf("next clear MFU changed record count to %d", got)
	}
}

func TestRawMediaDoesNotArchiveACompletelyClearFragmentedMFU(t *testing.T) {
	c, s, rec := rawMediaTestConverter(t)
	for seq, fragment := range []byte{
		mmtp.FragmentIndicatorFirst, mmtp.FragmentIndicatorMiddle, mmtp.FragmentIndicatorLast,
	} {
		c.preserveRawMedia(s, rawTestPacket(uint32(seq), fragment, false), []byte{byte(seq)})
	}
	if got := rec.Stats().Records; got != 0 {
		t.Fatalf("clear fragmented MFU produced %d raw records", got)
	}
	if len(s.rawMedia.prefix) != 0 || s.rawMedia.poisoned {
		t.Fatalf("clear MFU left recovery state %+v", s.rawMedia)
	}
}
