// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"strings"
	"testing"
)

func TestItemDisplayNameStaysOnOneLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "(unnamed)"},
		{"plain", "app/index.html", "app/index.html"},
		{"tab", "a\tb", "a b"},
		{"newline", "a\nb", "a.b"},
		{"control", "a\x00\x1bb", "a..b"},
		{"multibyte kept", "番組/データ.html", "番組/データ.html"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := itemDisplayName(tc.in); got != tc.want {
				t.Errorf("itemDisplayName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestItemDisplayNameIsBounded(t *testing.T) {
	got := itemDisplayName(strings.Repeat("あ", 200))
	if n := len([]rune(got)); n != itemNameLimit {
		t.Errorf("length = %d runes, want %d", n, itemNameLimit)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("%q is not marked as shortened", got)
	}
}
