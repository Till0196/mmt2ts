// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package mpu

import (
	"encoding/binary"
	"testing"

	"mmt2ts/internal/mmtp"
)

func payload(mpuSeq uint32, fragmentation byte, aggregation bool, units ...[]byte) []byte {
	flags := byte(0x28) | fragmentation<<1
	if aggregation {
		flags |= 0x01
	}
	out := []byte{0, 0, flags, 0}
	out = binary.BigEndian.AppendUint32(out, mpuSeq)
	for _, u := range units {
		if aggregation {
			out = binary.BigEndian.AppendUint16(out, uint16(len(u)))
		}
		out = append(out, u...)
	}
	binary.BigEndian.PutUint16(out[:2], uint16(len(out)-2))
	return out
}

func unit(data []byte) []byte { return append(make([]byte, 14), data...) }

func packet(seq uint32, body []byte) mmtp.Packet {
	return mmtp.Packet{PacketID: 0xf100, PayloadType: mmtp.PayloadTypeMPU, SequenceNumber: seq, Payload: body}
}

func collect(r *Reassembler, p mmtp.Packet) []string {
	var out []string
	for _, u := range r.Push(p) {
		if u.Loss {
			out = append(out, "LOSS")
			continue
		}
		out = append(out, string(u.Data))
	}
	return out
}

func equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestReassembleCompleteAggregatedAndFragmented(t *testing.T) {
	r := New()
	if got := collect(r, packet(0, payload(1, 0, true, unit([]byte("one")), unit([]byte("two"))))); !equal(got, []string{"one", "two"}) {
		t.Fatalf("aggregated units = %v", got)
	}
	if got := collect(r, packet(1, payload(1, 1, false, unit([]byte("frag"))))); len(got) != 0 {
		t.Fatalf("first fragment emitted %v", got)
	}
	if got := collect(r, packet(2, payload(1, 2, false, unit([]byte("men"))))); len(got) != 0 {
		t.Fatalf("middle fragment emitted %v", got)
	}
	if got := collect(r, packet(3, payload(1, 3, false, unit([]byte("ted"))))); !equal(got, []string{"fragmented"}) {
		t.Fatalf("reassembled unit = %v", got)
	}
	if s := r.Stats(); s.Units != 3 || s.SequenceGaps != 0 || s.FragmentErrors != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestSequenceGapEmitsLossAndDropsPartialUnit(t *testing.T) {
	r := New()
	collect(r, packet(0, payload(1, 1, false, unit([]byte("head")))))
	got := collect(r, packet(5, payload(1, 0, false, unit([]byte("next")))))
	if !equal(got, []string{"LOSS", "next"}) {
		t.Fatalf("units after gap = %v", got)
	}
	s := r.Stats()
	if s.SequenceGaps != 1 || s.LostPackets != 4 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestUnexpectedFragmentOrderIsReported(t *testing.T) {
	r := New()
	if got := collect(r, packet(0, payload(1, 3, false, unit([]byte("tail"))))); !equal(got, []string{"LOSS"}) {
		t.Fatalf("orphan last fragment = %v", got)
	}
	if s := r.Stats(); s.FragmentErrors != 1 {
		t.Fatalf("fragment errors = %d", s.FragmentErrors)
	}
}

func TestOrphanFragmentRunEmitsOneLoss(t *testing.T) {
	r := New()
	if got := collect(r, packet(0, payload(1, 2, false, unit([]byte("middle1"))))); !equal(got, []string{"LOSS"}) {
		t.Fatalf("first orphan middle = %v", got)
	}
	if got := collect(r, packet(1, payload(1, 2, false, unit([]byte("middle2"))))); len(got) != 0 {
		t.Fatalf("second orphan middle = %v", got)
	}
	if got := collect(r, packet(2, payload(1, 3, false, unit([]byte("tail"))))); len(got) != 0 {
		t.Fatalf("orphan tail = %v", got)
	}
	if got := collect(r, packet(3, payload(2, 0, false, unit([]byte("next"))))); !equal(got, []string{"next"}) {
		t.Fatalf("complete unit after orphan = %v", got)
	}
	if s := r.Stats(); s.FragmentErrors != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestScrambledPacketIsNotParsed(t *testing.T) {
	r := New()
	p := packet(0, payload(1, 0, false, unit([]byte("secret"))))
	p.Scrambled = true
	if got := collect(r, p); !equal(got, []string{"LOSS"}) {
		t.Fatalf("scrambled packet produced %v", got)
	}
	if s := r.Stats(); s.ScrambledPackets != 1 || s.Units != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestNonMFUFragmentTypesAreCounted(t *testing.T) {
	r := New()
	metadata := payload(1, 0, false, unit(nil))
	metadata[2] = 0x08
	if got := collect(r, packet(0, metadata)); len(got) != 0 {
		t.Fatalf("metadata emitted %v", got)
	}
	if s := r.Stats(); s.MetadataFragments != 1 {
		t.Fatalf("metadata fragments = %d", s.MetadataFragments)
	}
}
