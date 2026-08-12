// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import "testing"

func TestModuleVersionAdvancesAndWrapsWithoutReusingALiveVersion(t *testing.T) {
	c := NewCarousel(RoleRealtime, testRealtime, 0xe0, 0x4d520066)
	now := int64(0)
	for i := range 300 {
		err := c.Set(Update{
			ID: ModuleIDCodecConfig, Kind: KindCodecConfig,
			Payload: []byte{byte(i), byte(i >> 8)}, Interval: DIIInterval,
		}, now)
		if err != nil {
			t.Fatalf("Set %d at t=%d: %v", i, now, err)
		}
		if got := c.modules[ModuleIDCodecConfig].version; got != byte(i) {
			t.Fatalf("set %d produced moduleVersion %d, want %d", i, got, byte(i))
		}
		now += staleGuard
	}
}

func TestReusingARetiredVersionInsideTheStaleGuardIsRefused(t *testing.T) {
	c := NewCarousel(RoleRealtime, testRealtime, 0xe0, 0x4d520066)
	var err error
	for i := range 300 {
		err = c.Set(Update{
			ID: ModuleIDCodecConfig, Kind: KindCodecConfig,
			Payload: []byte{byte(i), byte(i >> 8)}, Interval: DIIInterval,
		}, 0)
		if err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("the version wrapped onto a pair retired moments ago without complaint")
	}
}

func TestTheDIITransactionAdvancesOnlyWhenTheModuleSetChanges(t *testing.T) {
	c := NewCarousel(RoleRealtime, testRealtime, 0xe0, 0x4d520066)
	if err := c.Set(Update{ID: ModuleIDAVMap, Kind: KindAVMPUMap, Payload: []byte{1}, Interval: DIIInterval}, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	sink := func(uint16, []byte) error { return nil }
	if err := c.Emit(0, sink); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	first := c.transaction

	if err := c.Set(Update{ID: ModuleIDAVMap, Kind: KindAVMPUMap, Payload: []byte{1}, Interval: DIIInterval}, DIIInterval); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := c.Emit(DIIInterval, sink); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if c.transaction != first {
		t.Errorf("an unchanged module set advanced the transaction from %d to %d", first, c.transaction)
	}

	if err := c.Set(Update{ID: ModuleIDAVMap, Kind: KindAVMPUMap, Payload: []byte{2}, Interval: DIIInterval}, 2*DIIInterval); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := c.Emit(2*DIIInterval, sink); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if c.transaction == first {
		t.Errorf("a changed module did not advance the transaction from %d", first)
	}
}

func TestTimedModuleGetsOneFastRetryThenJoinsTheHistoryCycle(t *testing.T) {
	c := NewCarousel(RoleRealtime, testRealtime, 0xe0, 0x4d520066)
	const historyCycle = 3 * 90000
	if err := c.Set(Update{
		ID: TimedModuleID(0, 0), Kind: KindTimedSegment, Payload: []byte("segment"),
		Interval: historyCycle, RetryCount: 1, RetryInterval: SegmentInterval,
	}, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	sink := func(uint16, []byte) error { return nil }
	emit := func(now int64, want uint64) {
		t.Helper()
		if err := c.Emit(now, sink); err != nil {
			t.Fatalf("Emit(%d): %v", now, err)
		}
		if got := c.modules[TimedModuleID(0, 0)].sent; got != want {
			t.Errorf("after Emit(%d), segment sent %d times, want %d", now, got, want)
		}
	}

	emit(0, 1)
	emit(SegmentInterval-1, 1)
	emit(SegmentInterval, 2)
	emit(historyCycle-1, 2)
	emit(historyCycle, 3)
	emit(2*historyCycle-1, 3)
	emit(2*historyCycle, 4)
}
