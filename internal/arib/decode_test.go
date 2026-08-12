// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package arib

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, s := range []string{
		"日本",
		"ABC放送",
		"あいうえお",
		"アイウエオ",
		"ＡＢ１２",
		"ｱｲｳ",
		"字幕 [Test] 番組",
		`"quoted" 'single' ` + "`grave`",
		"¥100 ‾ ￥１００",
		"🅍🈑㈱℡№㎝㍾髙",
		"、。「」・ーゝゞヽヾ",
		"第1話「はじまり」／全12回",
		"ア́テ̈ス⃝",
	} {
		enc := EncodeString(s)
		if enc.Count(ClassStandard) != uint64(len([]rune(s))) {
			t.Errorf("%q: not encoded from standard sets: %v %s", s, enc.Counts, enc.Describe())
			continue
		}
		got := DecodeString(enc.Bytes)
		if got.Text != s {
			t.Errorf("%q: round trip = %q (bytes % x)", s, got.Text, enc.Bytes)
		}
		if !got.Lossless() {
			t.Errorf("%q: undecodable %+v", s, got.Undecodable)
		}
	}
}

func TestDecodeUsesTheWholeCode(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []byte
		want string
	}{
		{"GR holds hiragana initially", []byte{0xa2, 0xa4, 0xa6}, "あいう"},
		{"SS2 is a single shift", []byte{CodeSS2, 0x22, 0x46, 0x7c}, "あ日"},
		{"SS3 reaches katakana", []byte{CodeSS3, 0x22}, "ア"},
		{"LS3R invokes G3 into GR", []byte{CodeESC, ls3REsc, 0xa2}, "ア"},
		{"LS1 invokes G1", []byte{CodeESC, 0x29, 0x49, CodeLS1, 0x31, 0x32}, "ｱｲ"},
		{"LS0 restores G0", []byte{CodeLS1, CodeLS0, 0x46, 0x7c}, "日"},
		{"additional symbols", []byte{CodeESC, 0x24, 0x3b, 0x7a, 0x5d, 0x7a, 0x56}, "🅍🈑"},
		{"additional cells under kanji", []byte{0x7a, 0x5d}, "🅍"},
		{"combining enclosing circle", []byte{0x22, 0x7e}, "⃝"},
	} {
		got := DecodeString(c.in)
		if got.Text != c.want {
			t.Errorf("%s: % x -> %q, want %q", c.name, c.in, got.Text, c.want)
		}
		if !got.Lossless() {
			t.Errorf("%s: undecodable %+v", c.name, got.Undecodable)
		}
	}
}

func TestDecodeControlCodes(t *testing.T) {
	in := []byte{
		0x0c,
		0x1c, 0x40, 0x41,
		0x9b, '3', '0', ';', '3', '0', 0x53,
		0x90, 0x20, 0x40,
		0x89,
		0x46, 0x7c,
	}
	got := DecodeString(in)
	if got.Text != "日" {
		t.Fatalf("text = %q, want %q (controls miscounted)", got.Text, "日")
	}
	want := []struct {
		code   byte
		params string
	}{
		{0x0c, ""},
		{0x1c, "\x40\x41"},
		{0x9b, "30;30\x53"},
		{0x90, "\x20\x40"},
		{0x89, ""},
	}
	if len(got.Controls) != len(want) {
		t.Fatalf("controls = %+v, want %d", got.Controls, len(want))
	}
	for i, w := range want {
		if got.Controls[i].Code != w.code || string(got.Controls[i].Params) != w.params {
			t.Errorf("control %d = %#02x %q, want %#02x %q",
				i, got.Controls[i].Code, got.Controls[i].Params, w.code, w.params)
		}
	}
}

func TestDecodeCSIFinals(t *testing.T) {
	for _, final := range []byte{0x53, 0x56, 0x57, 0x58, 0x59, 0x5f, 0x63} {
		in := append([]byte{0x9b, '1', ';', '2', final}, 0x46, 0x7c)
		got := DecodeString(in)
		if got.Text != "日" {
			t.Errorf("final %#02x: text = %q, want the character after the CSI", final, got.Text)
		}
		if len(got.Controls) != 1 || got.Controls[0].Code != 0x9b {
			t.Errorf("final %#02x: controls = %+v", final, got.Controls)
		}
	}
}

func TestDecodeReportsUndecodable(t *testing.T) {
	in := []byte{CodeESC, 0x28, 0x32, 0x21, CodeESC, 0x28, 0x4a, 'a'}
	got := DecodeString(in)
	if got.Text != "a" {
		t.Fatalf("text = %q, want the characters around the failure", got.Text)
	}
	if len(got.Undecodable) != 1 || got.Undecodable[0].Set != 0x32 {
		t.Fatalf("undecodable = %+v", got.Undecodable)
	}

	drcs := []byte{CodeESC, 0x24, 0x28, 0x20, 0x40, 0x21, 0x01}
	if got := DecodeString(drcs); got.Lossless() || got.Undecodable[0].Bytes != 0x2101 {
		t.Fatalf("DRCS without a resolver: %+v", got.Undecodable)
	}
	d := NewDecoder()
	d.DRCS = fixedResolver{}
	if got := d.Decode(drcs); got.Text != "★" || !got.Lossless() {
		t.Fatalf("DRCS with a resolver: %q %+v", got.Text, got.Undecodable)
	}
}

type fixedResolver struct{}

func (fixedResolver) DecodeDRCS(byte, uint16) (rune, bool) { return '★', true }

func TestDecodeContinueKeepsTheDesignation(t *testing.T) {
	e := NewEncoder()
	e.SICharacterSize = false
	first := e.Continue("ｱｲ")
	second := e.Continue("ｳｴ")
	if len(second.Bytes) != 2 {
		t.Fatalf("continuation re-designated: % x", second.Bytes)
	}

	d := NewDecoder()
	if got := d.Continue(first.Bytes); got.Text != "ｱｲ" {
		t.Fatalf("first piece = %q", got.Text)
	}
	if got := d.Continue(second.Bytes); got.Text != "ｳｴ" {
		t.Fatalf("continuation = %q", got.Text)
	}
	if got := DecodeString(second.Bytes); got.Text == "ｳｴ" {
		t.Fatal("a fresh decoder should not reproduce a continuation")
	}
}

func TestDecodeTruncatedInput(t *testing.T) {
	for _, in := range [][]byte{
		{CodeESC},
		{CodeESC, 0x24},
		{CodeESC, 0x24, 0x28},
		{CodeESC, 0x24, 0x28, 0x20},
		{CodeESC, 0x28},
		{0x46},
		{0x9b, '1', ';'},
		{0x95, 0x40},
		{CodeSS2},
		{0x1c, 0x40},
	} {
		got := DecodeString(in)
		_ = got.Text
	}
}

func TestDecodeControlOffsets(t *testing.T) {
	in := []byte{0x46, 0x7c, 0x89, CodeESC, 0x28, 0x4a, 'a', 'b'}
	got := DecodeString(in)
	if got.Text != "日ab" {
		t.Fatalf("text = %q", got.Text)
	}
	if len(got.Controls) != 1 || got.Controls[0].At != 1 {
		t.Fatalf("controls = %+v, want MSZ after one rune", got.Controls)
	}
}

func TestDecodeSharesTheSymbolTable(t *testing.T) {
	if len(additionalSymbolRunes) != len(additionalSymbolCells) {
		t.Fatalf("%d cells map back from %d runes", len(additionalSymbolRunes), len(additionalSymbolCells))
	}
	d := NewDecoder()
	for r, cell := range additionalSymbolCells {
		got := d.Decode([]byte{CodeESC, 0x24, 0x3b, byte(cell >> 8), byte(cell)})
		if got.Text != string(r) {
			t.Errorf("cell %#04x -> %q, want %U", cell, got.Text, r)
		}
	}
}

func TestDecodeAdditionalAliases(t *testing.T) {
	if len(additionalDecodeAliases) != 55 {
		t.Fatalf("got %d compatibility cells, want 55", len(additionalDecodeAliases))
	}
	d := NewDecoder()
	for cell, want := range additionalDecodeAliases {
		got := d.Decode([]byte{CodeESC, 0x24, 0x3b, byte(cell >> 8), byte(cell)})
		if got.Text != string(want) || !got.Lossless() {
			t.Errorf("cell %#04x -> %q, want %U", cell, got.Text, want)
		}
	}
}

func TestDecodeRejectsVendorRows(t *testing.T) {
	d := NewDecoder()
	for _, cell := range []uint16{0x2d21, 0x7521} {
		if _, ok := d.jis.kanjiRune(cell); ok && cell == 0x2d21 {
			t.Errorf("NEC row 13 cell %#04x decoded as kanji", cell)
		}
	}
	got := d.Decode([]byte{0x75, 0x21})
	if got.Text != "㐂" {
		t.Errorf("cell 0x7521 -> %q, want the additional kanji", got.Text)
	}
}

func TestDecodeLineBreakRestartsDesignations(t *testing.T) {
	in := []byte{CodeESC, 0x28, 0x4a, 'a', '\n', 0x46, 0x7c}
	got := DecodeString(in)
	if got.Text != "a\n日" {
		t.Fatalf("text = %q", got.Text)
	}
	if !strings.Contains(got.Text, "\n") {
		t.Fatal("the line break itself must survive")
	}
}

func TestRoundTripSweep(t *testing.T) {
	enc, dec := NewEncoder(), NewDecoder()
	var encoded, failed int
	for r := rune(0x20); r < 0x30000; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue
		}
		e := enc.Encode(string(r))
		if e.Count(ClassStandard) != 1 {
			continue
		}
		encoded++
		if got := dec.Decode(e.Bytes); got.Text != string(r) {
			if failed < 20 {
				t.Errorf("%U %q -> % x -> %q", r, r, e.Bytes, got.Text)
			}
			failed++
		}
	}
	if encoded < 7000 {
		t.Fatalf("only %d scalars encoded from standard sets; the tables look truncated", encoded)
	}
	t.Logf("%d scalars round tripped", encoded)
}

func TestCellSweepIsUnambiguous(t *testing.T) {
	enc, dec := NewEncoder(), NewDecoder()
	var checked, failed int
	for row := 0x21; row <= 0x7e; row++ {
		for col := 0x21; col <= 0x7e; col++ {
			cell := uint16(row)<<8 | uint16(col)
			got := dec.Decode([]byte{CodeESC, 0x24, 0x42, byte(row), byte(col)})
			if got.Text == "" {
				continue
			}
			if _, ok := additionalDecodeAliases[cell]; ok {
				continue
			}
			checked++
			back := enc.Encode(got.Text)
			if back.Count(ClassStandard) != 1 || back.Records[0].Cell != cell {
				if failed < 20 {
					t.Errorf("cell %#04x -> %q -> cell %#04x", cell, got.Text, back.Records[0].Cell)
				}
				failed++
			}
		}
	}
	t.Logf("%d cells checked", checked)
}
