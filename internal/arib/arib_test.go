// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package arib

import (
	"strings"
	"testing"
)

func TestEncodeKanjiNeedsNoEscape(t *testing.T) {
	got := EncodeString("日本")
	want := []byte{0x46, 0x7c, 0x4b, 0x5c}
	if string(got.Bytes) != string(want) {
		t.Fatalf("bytes = % x, want % x", got.Bytes, want)
	}
	if !got.Lossless() || got.Count(ClassStandard) != 2 {
		t.Fatalf("counts = %v, lossless = %v", got.Counts, got.Lossless())
	}
}

func TestEncodeDesignatesOnSetChange(t *testing.T) {
	got := EncodeString("ABC放送")
	want := []byte{
		0x89, CodeESC, 0x28, 0x4a, 'A', 'B', 'C',
		0x8a, CodeESC, 0x24, 0x42, 0x4a, 0x7c, 0x41, 0x77,
	}
	if string(got.Bytes) != string(want) {
		t.Fatalf("bytes = % x, want % x", got.Bytes, want)
	}
	if n := strings.Count(string(got.Bytes), string([]byte{CodeESC})); n != 2 {
		t.Fatalf("escape sequences = %d, want 2", n)
	}
}

func TestEncodeKanaAndFullwidth(t *testing.T) {
	for _, s := range []string{"あいう", "アイウ", "ＡＢ１２"} {
		got := EncodeString(s)
		if !got.Lossless() {
			t.Errorf("%q: not lossless, counts %v", s, got.Counts)
		}
		if want := 2 * len([]rune(s)); len(got.Bytes) != want {
			t.Errorf("%q: %d bytes, want %d", s, len(got.Bytes), want)
		}
	}
}

func TestEncodeASCIIExceptionCells(t *testing.T) {
	for _, c := range []struct {
		r    rune
		cell byte
	}{{'¥', 0x5c}, {'‾', 0x7e}} {
		got := EncodeString(string(c.r))
		want := []byte{CodeMSZ, CodeESC, 0x28, 0x4a, c.cell}
		if string(got.Bytes) != string(want) || got.Count(ClassStandard) != 1 {
			t.Errorf("%U: bytes = % x, counts = %v, want % x", c.r, got.Bytes, got.Counts, want)
		}
	}
	for _, r := range []rune{'"', '\'', '`'} {
		got := EncodeString(string(r))
		want := []byte{CodeMSZ, CodeESC, 0x28, 0x4a, byte(r)}
		if string(got.Bytes) != string(want) || got.Count(ClassStandard) != 1 {
			t.Errorf("%U: bytes = % x, counts = %v, want % x", r, got.Bytes, got.Counts, want)
		}
	}
	for r, cell := range map[rune]uint16{
		'”': 0x2149, '’': 0x2147, '‘': 0x2146, '“': 0x2148, '￥': 0x216f,
	} {
		got := EncodeString(string(r))
		want := []byte{byte(cell >> 8), byte(cell)}
		if string(got.Bytes) != string(want) || got.Count(ClassStandard) != 1 {
			t.Errorf("%U: bytes = % x, counts = %v, want % x", r, got.Bytes, got.Counts, want)
		}
	}
}

func TestEncodeCombiningCells(t *testing.T) {
	for r, cell := range combiningRunes {
		got := EncodeString(string(r))
		want := []byte{byte(cell >> 8), byte(cell)}
		if string(got.Bytes) != string(want) || got.Count(ClassStandard) != 1 {
			t.Errorf("%U: bytes = % x, counts = %v, want % x", r, got.Bytes, got.Counts, want)
		}
	}
	got := EncodeString("￣")
	if got.Count(ClassNormalized) != 1 || got.Records[0].Via != '‾' {
		t.Fatalf("U+FFE3: counts = %v, records = %+v", got.Counts, got.Records)
	}
	e := NewEncoder()
	for _, r := range []rune{'￣', '｀', '＾', '＿', '´', '¨', '◯'} {
		if cell, ok := e.kanjiCell(r); ok {
			t.Errorf("%U reached the combining cell %#04x", r, cell)
		}
	}
}

func TestEncodeHalfWidthKatakana(t *testing.T) {
	got := EncodeString("ｱｲｳ")
	want := []byte{CodeMSZ, CodeESC, 0x28, 0x49, 0x31, 0x32, 0x33}
	if string(got.Bytes) != string(want) {
		t.Fatalf("bytes = % x, want % x", got.Bytes, want)
	}
	if !got.Lossless() || got.Count(ClassStandard) != 3 {
		t.Fatalf("counts = %v", got.Counts)
	}
}

func TestEncodeNormalizesCompatibleForms(t *testing.T) {
	got := EncodeString("〜")
	if got.Count(ClassNormalized) != 1 {
		t.Fatalf("counts = %v, records = %+v", got.Counts, got.Records)
	}
	if got.Records[0].Via != '～' {
		t.Fatalf("normalised via %q", got.Records[0].Via)
	}
	if len(got.Bytes) != 2 {
		t.Fatalf("bytes = % x", got.Bytes)
	}
}

func TestEncodeAdditionalSymbols(t *testing.T) {
	got := EncodeString("🅍🈑")
	want := []byte{CodeESC, 0x24, 0x3b, 0x7a, 0x5d, 0x7a, 0x56}
	if string(got.Bytes) != string(want) {
		t.Fatalf("bytes = % x, want % x", got.Bytes, want)
	}
	if !got.Lossless() || got.Count(ClassStandard) != 2 {
		t.Fatalf("counts = %v, records = %+v", got.Counts, got.Records)
	}
	if got.Records[0].Cell != 0x7a5d || got.Records[1].Cell != 0x7a56 {
		t.Fatalf("records = %+v", got.Records)
	}
}

func TestContinueKeepsTheDesignation(t *testing.T) {
	e := NewEncoder()
	e.SICharacterSize = false
	first := e.Continue("あ♬")
	want := []byte{0x24, 0x22, CodeESC, 0x24, 0x3b, 0x7d, 0x7a}
	if string(first.Bytes) != string(want) {
		t.Fatalf("first piece = % x, want % x", first.Bytes, want)
	}
	second := e.Continue("い")
	if string(second.Bytes) != string([]byte{CodeESC, 0x24, 0x42, 0x24, 0x24}) {
		t.Fatalf("continuation = % x, want the kanji set designated first", second.Bytes)
	}
	e2 := NewEncoder()
	e2.SICharacterSize = false
	e2.Encode("あ♬")
	if got := e2.Encode("い"); string(got.Bytes) != string([]byte{0x24, 0x24}) {
		t.Fatalf("Encode = % x, want a fresh string with kanji already in G0", got.Bytes)
	}
}

func TestAdditionalSymbolTableCoverage(t *testing.T) {
	if got := len(additionalSymbolCells); got != 476 {
		t.Fatalf("additional symbol entries = %d, want 476", got)
	}
	assigned, prevEnd := 0, -1
	for _, seg := range additionalSymbolSegments {
		if int(seg.first) <= prevEnd {
			t.Errorf("segment at %#04x overlaps the one before it", seg.first)
		}
		for _, r := range seg.runes {
			if r != 0 {
				assigned++
			}
		}
		prevEnd = int(seg.first) + len([]rune(seg.runes)) - 1
		if row := seg.first >> 8; row < 0x75 || row > 0x7e || prevEnd>>8 != int(row) {
			t.Errorf("segment %#04x-%#04x is not inside one additional symbol row", seg.first, prevEnd)
		}
	}
	if assigned != len(additionalSymbolCells) {
		t.Fatalf("%d cells assigned but %d scalars mapped (duplicate rune)", assigned, len(additionalSymbolCells))
	}
	for r, cell := range map[rune]uint16{
		'㈱': 0x7c4d, '℡': 0x7d2e, '№': 0x7d2d,
		'㎝': 0x7c2d, '㍾': 0x7d29, '髙': 0x7647,
	} {
		got := EncodeString(string(r))
		want := []byte{CodeESC, 0x24, 0x3b, byte(cell >> 8), byte(cell)}
		if string(got.Bytes) != string(want) || got.Count(ClassStandard) != 1 {
			t.Errorf("%U: bytes = % x, counts = %v, want % x", r, got.Bytes, got.Counts, want)
		}
	}
}

func TestKanjiCellRejectsEUCJPVendorRows(t *testing.T) {
	e := NewEncoder()
	for _, r := range "①㈱℡№髙" {
		if cell, ok := e.kanjiCell(r); ok {
			t.Errorf("%U accepted as Kanji cell %#04x", r, cell)
		}
	}
}

func TestAdditionalSymbolsAreNotSubstitutes(t *testing.T) {
	for r := range additionalSymbolCells {
		if replacement, ok := substitutes[r]; ok {
			t.Errorf("%U is both a standard additional symbol and substitute %q", r, replacement)
		}
	}
}

func TestSecondGenerationSymbolIsNotAssignedToB24Cell(t *testing.T) {
	got := EncodeString("🆞")
	if got.Count(ClassSubstituted) != 1 || got.Records[0].Substitute != "[4K]" {
		t.Fatalf("records = %+v, counts = %v", got.Records, got.Counts)
	}
}

func TestEncodeReportsUnconvertible(t *testing.T) {
	got := EncodeString("a\U0001F600b")
	if got.Count(ClassUnconvertible) != 1 {
		t.Fatalf("counts = %v", got.Counts)
	}
	if u := got.Unconvertible(); len(u) != 1 || u[0] != '\U0001F600' {
		t.Fatalf("unconvertible = %q", u)
	}
	if string(got.Bytes) != string([]byte{0x89, CodeESC, 0x28, 0x4a, 'a', 'b'}) {
		t.Fatalf("bytes = % x", got.Bytes)
	}
}

func TestSIASCIIUsesMediumSizeAndRestoresNormalSize(t *testing.T) {
	got := EncodeString("AB・CD 「＆EF」　テスト")
	if !strings.Contains(string(got.Bytes), string([]byte{0x89, CodeESC, 0x28, 0x4a, 'A', 'B'})) {
		t.Fatalf("ASCII run has no MSZ: % x", got.Bytes)
	}
	if !strings.Contains(string(got.Bytes), string([]byte{0x8a, CodeESC, 0x24, 0x42})) {
		t.Fatalf("full-width run has no NSZ: % x", got.Bytes)
	}
}

type fixedDRCS struct{ next uint16 }

func (f *fixedDRCS) AllocateDRCS(rune) (uint16, bool) {
	f.next++
	return 0x2100 | f.next, true
}

func TestEncodeUsesDRCSWhenAvailable(t *testing.T) {
	e := NewEncoder()
	e.DRCS = &fixedDRCS{}
	got := e.Encode("\U0001F600")
	if got.Count(ClassDRCS) != 1 {
		t.Fatalf("counts = %v", got.Counts)
	}
	want := []byte{CodeESC, 0x24, 0x28, 0x20, 0x40, 0x21, 0x01}
	if string(got.Bytes) != string(want) {
		t.Fatalf("bytes = % x, want % x", got.Bytes, want)
	}
}

func TestEncodeAccountsForEveryScalar(t *testing.T) {
	const s = "字幕 [Test] 〜🈑\U0001F600"
	got := EncodeString(s)
	if len(got.Records) != len([]rune(s)) {
		t.Fatalf("%d records for %d scalars", len(got.Records), len([]rune(s)))
	}
	var total uint64
	for _, n := range got.Counts {
		total += n
	}
	if total != uint64(len([]rune(s))) {
		t.Fatalf("counts %v sum to %d", got.Counts, total)
	}
}
