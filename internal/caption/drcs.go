// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package caption

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"mmt2ts/internal/arib"
)

type Glyph struct {
	Width, Height int
	Depth         byte
	Pattern       []byte
}

type GlyphSource interface {
	Glyph(r rune) (Glyph, bool)
}

type DRCS struct {
	Source GlyphSource

	codes  map[rune]uint16
	byHash map[[32]byte]uint16
	next   uint16
	glyphs map[uint16]Glyph
	// 文ごとに、使った字形を全部その文に載せる。途中から読み始めても届く。
	used []uint16

	Allocated uint64
	Reused    uint64
	Refused   uint64
}

func NewDRCS(source GlyphSource) *DRCS {
	return &DRCS{
		Source: source,
		codes:  make(map[rune]uint16),
		byHash: make(map[[32]byte]uint16),
		next:   0x2121,
		glyphs: make(map[uint16]Glyph),
	}
}

func (d *DRCS) AllocateDRCS(r rune) (uint16, bool) {
	if d == nil || d.Source == nil {
		return 0, false
	}
	if code, ok := d.codes[r]; ok {
		d.use(code)
		return code, true
	}
	glyph, ok := d.Source.Glyph(r)
	if !ok || len(glyph.Pattern) == 0 {
		d.Refused++
		return 0, false
	}
	sum := sha256.Sum256(append([]byte{byte(glyph.Width), byte(glyph.Height), glyph.Depth}, glyph.Pattern...))
	if code, ok := d.byHash[sum]; ok {
		d.codes[r] = code
		d.Reused++
		d.use(code)
		return code, true
	}
	code, ok := d.allocate()
	if !ok {
		d.Refused++
		return 0, false
	}
	d.codes[r] = code
	d.byHash[sum] = code
	d.glyphs[code] = glyph
	d.Allocated++
	d.use(code)
	return code, true
}

func (d *DRCS) use(code uint16) {
	if !slices.Contains(d.used, code) {
		d.used = append(d.used, code)
	}
}

func (d *DRCS) allocate() (uint16, bool) {
	hi, lo := byte(d.next>>8), byte(d.next)
	if hi > 0x7e {
		return 0, false
	}
	code := uint16(hi)<<8 | uint16(lo)
	lo++
	if lo > 0x7e {
		lo = 0x21
		hi++
	}
	d.next = uint16(hi)<<8 | uint16(lo)
	return code, true
}

func (d *DRCS) Definitions() []byte {
	if d == nil || len(d.used) == 0 {
		return nil
	}
	body := []byte{byte(len(d.used))}
	for _, code := range d.used {
		g := d.glyphs[code]
		body = binary.BigEndian.AppendUint16(body, code)
		body = append(body, 1)
		body = append(body, 0x01, g.Depth, byte(g.Width), byte(g.Height))
		body = append(body, g.Pattern...)
	}
	d.used = d.used[:0]
	return arib.DataUnit(arib.UnitDRCS2Byte, body)
}
