// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package timeline

import "testing"

func TestNTPDeltaSeconds(t *testing.T) {
	a := uint64(12)<<32 | 0x40000000
	b := uint64(10)<<32 | 0xc0000000
	if got := NTPDeltaSeconds(a, b); got != 1.5 {
		t.Fatalf("delta = %v", got)
	}
	if got := NTPDeltaSeconds(b, a); got != -1.5 {
		t.Fatalf("reverse delta = %v", got)
	}
	beforeWrap := uint64(0xffffffff)<<32 | 0x80000000
	afterWrap := uint64(0x00000000) << 32
	if got := NTPDeltaSeconds(afterWrap, beforeWrap); got != 0.5 {
		t.Fatalf("era-wrap delta = %v", got)
	}
}
