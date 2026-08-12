// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package caption

import (
	"crypto/sha256"
	"encoding/binary"

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

	codes   map[rune]uint16
	byHash  map[[32]byte]uint16
	next    uint16
	pending []definition

	Allocated uint64
	Reused    uint64
	Refused   uint64
}

type definition struct {
	code  uint16
	glyph Glyph
}

func NewDRCS(source GlyphSource) *DRCS {
	return &DRCS{
		Source: source,
		codes:  make(map[rune]uint16),
		byHash: make(map[[32]byte]uint16),
		next:   0x2121,
	}
}

func (d *DRCS) AllocateDRCS(r rune) (uint16, bool) {
	if d == nil || d.Source == nil {
		return 0, false
	}
	if code, ok := d.codes[r]; ok {
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
		return code, true
	}
	code, ok := d.allocate()
	if !ok {
		d.Refused++
		return 0, false
	}
	d.codes[r] = code
	d.byHash[sum] = code
	d.pending = append(d.pending, definition{code: code, glyph: glyph})
	d.Allocated++
	return code, true
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
	if d == nil || len(d.pending) == 0 {
		return nil
	}
	body := []byte{byte(len(d.pending))}
	for _, def := range d.pending {
		body = binary.BigEndian.AppendUint16(body, def.code)
		body = append(body, 1)
		body = append(body, 0x01, def.glyph.Depth, byte(def.glyph.Width), byte(def.glyph.Height))
		body = append(body, def.glyph.Pattern...)
	}
	d.pending = nil
	return arib.DataUnit(arib.UnitDRCS2Byte, body)
}
