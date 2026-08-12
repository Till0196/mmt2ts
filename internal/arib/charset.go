// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package arib

import (
	"unicode/utf8"

	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"
)

type charset byte

const (
	csASCII        charset = 0x40
	csHiragana     charset = 0x30
	csKatakana     charset = 0x31
	csMosaicA      charset = 0x32
	csMosaicB      charset = 0x33
	csMosaicC      charset = 0x34
	csMosaicD      charset = 0x35
	csASCIIProp    charset = 0x36
	csHiraganaProp charset = 0x37
	csKatakanaProp charset = 0x38
	csJISX0201Kata charset = 0x49
	csASCIIx       charset = 0x4a

	csJISX0213_1 charset = 0x39
	csJISX0213_2 charset = 0x3a
	csAdditional charset = 0x3b
	csKanji      charset = 0x42

	csDRCS0  charset = 0xc0
	csDRCS15 charset = 0xcf
	csMacro  charset = 0xf0
)

func (c charset) twoByte() bool {
	switch c {
	case csKanji, csJISX0213_1, csJISX0213_2, csAdditional, csDRCS0:
		return true
	}
	return false
}

func (c charset) drcs() bool { return c >= csDRCS0 && c <= csDRCS15 }

var (
	kanaPunctuation = [8]rune{'ヽ', 'ヾ', 'ー', '。', '「', '」', '、', '・'}
	hiraPunctuation = [2]rune{'ゝ', 'ゞ'}
)

var combiningCells = map[uint16]rune{
	0x212d: '́',
	0x212e: '̀',
	0x212f: '̈',
	0x2130: '̂',
	0x2131: '̄',
	0x2132: '̲',
	0x227e: '⃝',
}

var combiningRunes = func() map[rune]uint16 {
	out := make(map[rune]uint16, len(combiningCells))
	for cell, r := range combiningCells {
		out[r] = cell
	}
	return out
}()

type jisCodec struct {
	enc   transform.Transformer
	dec   transform.Transformer
	in    [utf8.UTFMax]byte
	out   [8]byte
	cells map[rune]uint16
}

const noKanjiCell = 0xffff

func newJISCodec() jisCodec {
	return jisCodec{
		enc:   japanese.EUCJP.NewEncoder(),
		dec:   japanese.EUCJP.NewDecoder(),
		cells: make(map[rune]uint16, 1024),
	}
}

func (j *jisCodec) kanjiCell(r rune) (uint16, bool) {
	if r < 0x80 {
		return 0, false
	}
	if cell, ok := j.cells[r]; ok {
		return cell, cell != noKanjiCell
	}
	cell, ok := j.lookupKanjiCell(r)
	if ok {
		j.cells[r] = cell
	} else {
		j.cells[r] = noKanjiCell
	}
	return cell, ok
}

func (j *jisCodec) lookupKanjiCell(r rune) (uint16, bool) {
	n := utf8.EncodeRune(j.in[:], r)
	j.enc.Reset()
	written, read, err := j.enc.Transform(j.out[:], j.in[:n], true)
	if err != nil || read != n || written != 2 {
		return 0, false
	}
	hi, lo := j.out[0], j.out[1]
	if hi < 0xa1 || hi > 0xfe || lo < 0xa1 || lo > 0xfe {
		return 0, false
	}
	cell := uint16(hi-0x80)<<8 | uint16(lo-0x80)
	if !kanjiRow(byte(cell>>8)) || combiningCells[cell] != 0 {
		return 0, false
	}
	return cell, true
}

func (j *jisCodec) kanjiRune(cell uint16) (rune, bool) {
	if !kanjiRow(byte(cell >> 8)) {
		return 0, false
	}
	j.in[0] = byte(cell>>8) | 0x80
	j.in[1] = byte(cell) | 0x80
	j.dec.Reset()
	written, read, err := j.dec.Transform(j.out[:], j.in[:2], true)
	if err != nil || read != 2 || written == 0 {
		return 0, false
	}
	r, size := utf8.DecodeRune(j.out[:written])
	if r == utf8.RuneError || size != written {
		return 0, false
	}
	return r, true
}

func kanjiRow(row byte) bool {
	return (row >= 0x21 && row <= 0x28) || (row >= 0x30 && row <= 0x74)
}

func kanaCell(r rune) (byte, bool) {
	if r < 0xff61 || r > 0xff9f {
		return 0, false
	}
	return byte(r - 0xff40), true
}

func (c charset) decode(j *jisCodec, c1, c2 byte) (rune, bool) {
	switch c {
	case csASCII, csASCIIx, csASCIIProp:
		if alt, ok := alphanumericExceptions[c1]; ok {
			return alt, true
		}
		return rune(c1), true

	case csKatakana, csKatakanaProp:
		if c1 < 0x21 {
			return 0, false
		}
		if c1 <= 0x76 {
			return rune(0x3080 + int(c1)), true
		}
		return kanaPunctuation[c1-0x77], true

	case csHiragana, csHiraganaProp:
		switch {
		case c1 < 0x21:
			return 0, false
		case c1 <= 0x73:
			return rune(0x3020 + int(c1)), true
		case c1 == 0x77 || c1 == 0x78:
			return hiraPunctuation[c1-0x77], true
		case c1 >= 0x79:
			return kanaPunctuation[c1-0x77], true
		}
		return 0, false

	case csJISX0201Kata:
		if c1 < 0x21 || c1 > 0x5f {
			return 0, false
		}
		return rune(0xff40 + int(c1)), true

	case csKanji, csAdditional, csJISX0213_1, csJISX0213_2:
		return decodeTwoByte(j, c1, c2)
	}
	return 0, false
}

func decodeTwoByte(j *jisCodec, c1, c2 byte) (rune, bool) {
	if c1 < 0x21 || c1 > 0x7e || c2 < 0x21 || c2 > 0x7e {
		return 0, false
	}
	cell := uint16(c1)<<8 | uint16(c2)
	if r, ok := additionalSymbolRunes[cell]; ok {
		return r, true
	}
	if r, ok := additionalDecodeAliases[cell]; ok {
		return r, true
	}
	if r, ok := combiningCells[cell]; ok {
		return r, true
	}
	return j.kanjiRune(cell)
}

var additionalSymbolRunes = func() map[uint16]rune {
	out := make(map[uint16]rune, len(additionalSymbolCells))
	for r, cell := range additionalSymbolCells {
		out[cell] = r
	}
	return out
}()
