// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package mpu

import "testing"

func TestSequenceWrapIsNotAGap(t *testing.T) {
	r := New()
	for i, seq := range []uint32{0xfffffffe, 0xffffffff, 0} {
		if got := collect(r, packet(seq, payload(1, 0, false, unit([]byte("u"))))); !equal(got, []string{"u"}) {
			t.Fatalf("packet %d (seq %#x) = %v", i, seq, got)
		}
	}
	if s := r.Stats(); s.SequenceGaps != 0 || s.LostPackets != 0 || s.OutOfOrderPackets != 0 {
		t.Fatalf("the counter wrapping was reported as a discontinuity: %+v", s)
	}
}

func TestForwardGapIsOneLoss(t *testing.T) {
	r := New()
	if got := collect(r, packet(0, payload(1, 0, false, unit([]byte("a"))))); !equal(got, []string{"a"}) {
		t.Fatalf("first packet = %v", got)
	}
	if got := collect(r, packet(5, payload(1, 0, false, unit([]byte("b"))))); !equal(got, []string{"LOSS", "b"}) {
		t.Fatalf("packet after the gap = %v", got)
	}
	if got := collect(r, packet(6, payload(1, 0, false, unit([]byte("c"))))); !equal(got, []string{"c"}) {
		t.Fatalf("packet after resynchronising = %v", got)
	}
	if s := r.Stats(); s.SequenceGaps != 1 || s.LostPackets != 4 || s.OutOfOrderPackets != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestDuplicateAndLatePacketsAreNotLoss(t *testing.T) {
	r := New()
	for seq := range uint32(3) {
		if got := collect(r, packet(seq, payload(1, 0, false, unit([]byte("u"))))); !equal(got, []string{"u"}) {
			t.Fatalf("packet %d = %v", seq, got)
		}
	}
	for _, seq := range []uint32{2, 0} {
		if got := collect(r, packet(seq, payload(1, 0, false, unit([]byte("dup"))))); len(got) != 0 {
			t.Fatalf("late packet %d emitted %v", seq, got)
		}
	}
	if got := collect(r, packet(3, payload(1, 0, false, unit([]byte("next"))))); !equal(got, []string{"next"}) {
		t.Fatalf("packet after the duplicates = %v", got)
	}
	s := r.Stats()
	if s.OutOfOrderPackets != 2 {
		t.Fatalf("out of order packets = %d, want 2", s.OutOfOrderPackets)
	}
	if s.SequenceGaps != 0 || s.LostPackets != 0 {
		t.Fatalf("a duplicate was reported as loss: %+v", s)
	}
	if s.Units != 4 {
		t.Fatalf("units = %d, want only the four distinct packets", s.Units)
	}
}

func TestScrambledPacketAdvancesTheSequence(t *testing.T) {
	r := New()
	if got := collect(r, packet(0, payload(1, 0, false, unit([]byte("clear"))))); !equal(got, []string{"clear"}) {
		t.Fatalf("first packet = %v", got)
	}
	scrambled := packet(1, payload(1, 0, false, unit([]byte("secret"))))
	scrambled.Scrambled = true
	if got := collect(r, scrambled); !equal(got, []string{"LOSS"}) {
		t.Fatalf("scrambled packet = %v", got)
	}
	if got := collect(r, packet(2, payload(1, 0, false, unit([]byte("again"))))); !equal(got, []string{"again"}) {
		t.Fatalf("clear packet after the scrambled one = %v", got)
	}
	s := r.Stats()
	if s.ScrambledPackets != 1 {
		t.Fatalf("scrambled packets = %d", s.ScrambledPackets)
	}
	if s.SequenceGaps != 0 || s.LostPackets != 0 {
		t.Fatalf("the scrambled packet was counted as a gap as well: %+v", s)
	}
}

func TestGapEndingOnAScrambledPacketIsOneLoss(t *testing.T) {
	r := New()
	collect(r, packet(0, payload(1, 0, false, unit([]byte("clear")))))
	scrambled := packet(4, payload(1, 0, false, unit([]byte("secret"))))
	scrambled.Scrambled = true
	if got := collect(r, scrambled); !equal(got, []string{"LOSS"}) {
		t.Fatalf("scrambled packet after a gap = %v", got)
	}
	if got := collect(r, packet(5, payload(1, 0, false, unit([]byte("again"))))); !equal(got, []string{"again"}) {
		t.Fatalf("clear packet after the scrambled one = %v", got)
	}
	if s := r.Stats(); s.SequenceGaps != 1 || s.LostPackets != 3 || s.ScrambledPackets != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestFragmentBufferLimitDropsTheUnitOnce(t *testing.T) {
	r := newWithFragmentLimit(16)
	if got := collect(r, packet(0, payload(1, 1, false, unit([]byte("12345678"))))); len(got) != 0 {
		t.Fatalf("first fragment = %v", got)
	}
	if got := collect(r, packet(1, payload(1, 2, false, unit([]byte("12345678"))))); len(got) != 0 {
		t.Fatalf("fragment reaching the limit = %v", got)
	}
	if got := collect(r, packet(2, payload(1, 2, false, unit([]byte("9"))))); !equal(got, []string{"LOSS"}) {
		t.Fatalf("overflowing fragment = %v", got)
	}
	if got := collect(r, packet(3, payload(1, 2, false, unit([]byte("more"))))); len(got) != 0 {
		t.Fatalf("fragment after the overflow = %v", got)
	}
	if got := collect(r, packet(4, payload(1, 3, false, unit([]byte("tail"))))); len(got) != 0 {
		t.Fatalf("last fragment of the abandoned unit = %v", got)
	}
	if s := r.Stats(); s.FragmentErrors != 1 {
		t.Fatalf("fragment errors = %d, want one for the whole run", s.FragmentErrors)
	}
	collect(r, packet(5, payload(2, 1, false, unit([]byte("ab")))))
	if got := collect(r, packet(6, payload(2, 3, false, unit([]byte("cd"))))); !equal(got, []string{"abcd"}) {
		t.Fatalf("unit after the overflow = %v", got)
	}
	if s := r.Stats(); s.FragmentErrors != 1 || s.Units != 1 {
		t.Fatalf("stats after recovery = %+v", s)
	}
}

func TestFirstFragmentLargerThanTheLimitIsDropped(t *testing.T) {
	r := newWithFragmentLimit(4)
	if got := collect(r, packet(0, payload(1, 1, false, unit([]byte("toolong"))))); !equal(got, []string{"LOSS"}) {
		t.Fatalf("oversized first fragment = %v", got)
	}
	if got := collect(r, packet(1, payload(1, 3, false, unit([]byte("tail"))))); len(got) != 0 {
		t.Fatalf("tail of the dropped unit = %v", got)
	}
	if s := r.Stats(); s.FragmentErrors != 1 || s.Units != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestDefaultFragmentLimitLeavesRoomFor4K(t *testing.T) {
	if got := New().maxFragment; got != MaxFragmentBytes {
		t.Fatalf("default fragment limit = %d, want MaxFragmentBytes", got)
	}
	if MaxFragmentBytes < 32<<20 {
		t.Fatalf("MaxFragmentBytes = %d is too small for a 4K access unit", MaxFragmentBytes)
	}
}
