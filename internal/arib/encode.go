// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package arib

type DRCSAllocator interface {
	AllocateDRCS(r rune) (cell uint16, ok bool)
}

type Encoder struct {
	DRCS            DRCSAllocator
	SICharacterSize bool

	jis    jisCodec
	cur    charset
	medium bool
	dst    []byte
	recs   []Record
	offs   []int32
}

func NewEncoder() *Encoder {
	return &Encoder{jis: newJISCodec(), SICharacterSize: true, cur: csKanji}
}

func (e *Encoder) Encode(s string) Result { return e.encode(s, true) }

func (e *Encoder) Continue(s string) Result { return e.encode(s, false) }

func (e *Encoder) encode(s string, reset bool) Result {
	e.dst = make([]byte, 0, len(s)+8)
	e.recs = e.recs[:0]
	e.offs = e.offs[:0]
	if reset {
		e.cur = csKanji
		e.medium = false
	}
	var counts [5]uint64
	for _, r := range s {
		rec := e.encodeRune(r)
		counts[rec.Class]++
		e.recs = append(e.recs, rec)
		e.offs = append(e.offs, int32(len(e.dst)))
	}
	return Result{
		Bytes:   e.dst,
		Records: append([]Record(nil), e.recs...),
		Counts:  counts,
		Offsets: append([]int32(nil), e.offs...),
	}
}

func (e *Encoder) encodeRune(r rune) Record {
	if cell, ok := e.emitStandard(r); ok {
		return Record{Rune: r, Class: ClassStandard, Cell: cell}
	}
	if isVariationSelector(r) {
		return Record{Rune: r, Class: ClassNormalized}
	}
	if alt, ok := compatible[r]; ok {
		if cell, ok := e.emitStandard(alt); ok {
			return Record{Rune: r, Class: ClassNormalized, Via: alt, Cell: cell}
		}
	}
	if sub, ok := substitutes[r]; ok {
		if e.emitString(sub) {
			return Record{Rune: r, Class: ClassSubstituted, Substitute: sub}
		}
	}
	if e.DRCS != nil {
		if cell, ok := e.DRCS.AllocateDRCS(r); ok {
			e.setMedium(false)
			e.designate(csDRCS0)
			e.dst = append(e.dst, byte(cell>>8), byte(cell))
			return Record{Rune: r, Class: ClassDRCS, Cell: cell}
		}
	}
	return Record{Rune: r, Class: ClassUnconvertible}
}

func isVariationSelector(r rune) bool {
	return (r >= 0xfe00 && r <= 0xfe0f) || (r >= 0xe0100 && r <= 0xe01ef)
}

func (e *Encoder) emitString(s string) bool {
	mark, set, medium := len(e.dst), e.cur, e.medium
	for _, r := range s {
		if _, ok := e.emitStandard(r); !ok {
			e.dst, e.cur, e.medium = e.dst[:mark], set, medium
			return false
		}
	}
	return true
}

func (e *Encoder) emitStandard(r rune) (uint16, bool) {
	if r < 0x80 {
		switch {
		case r == '\n' || r == '\r':
			e.dst = append(e.dst, byte(r))
			return 0, true
		case r >= 0x20 && r < 0x7f && !alphanumericTaken[r]:
			e.setMedium(true)
			e.designate(csASCIIx)
			e.dst = append(e.dst, byte(r))
			return 0, true
		}
		return 0, false
	}
	if cell, ok := additionalSymbolCells[r]; ok {
		e.setMedium(false)
		e.designate(csAdditional)
		e.dst = append(e.dst, byte(cell>>8), byte(cell))
		return cell, true
	}
	if b, ok := alphanumericExceptionCells[r]; ok {
		e.setMedium(true)
		e.designate(csASCIIx)
		e.dst = append(e.dst, b)
		return 0, true
	}
	if cell, ok := combiningRunes[r]; ok {
		e.setMedium(false)
		e.designate(csKanji)
		e.dst = append(e.dst, byte(cell>>8), byte(cell))
		return cell, true
	}
	if cell, ok := kanaCell(r); ok {
		e.setMedium(true)
		e.designate(csJISX0201Kata)
		e.dst = append(e.dst, cell)
		return 0, true
	}
	cell, ok := e.jis.kanjiCell(r)
	if !ok {
		return 0, false
	}
	e.setMedium(false)
	e.designate(csKanji)
	e.dst = append(e.dst, byte(cell>>8), byte(cell))
	return cell, true
}

func (e *Encoder) kanjiCell(r rune) (uint16, bool) { return e.jis.kanjiCell(r) }

func (e *Encoder) setMedium(medium bool) {
	if !e.SICharacterSize || e.medium == medium {
		return
	}
	if medium {
		e.dst = append(e.dst, CodeMSZ)
	} else {
		e.dst = append(e.dst, CodeNSZ)
	}
	e.medium = medium
}

func (e *Encoder) designate(s charset) {
	if e.cur == s {
		return
	}
	switch {
	case s == csDRCS0:
		e.dst = append(e.dst, CodeESC, 0x24, 0x28, 0x20, 0x40)
	case s.twoByte():
		e.dst = append(e.dst, CodeESC, 0x24, byte(s))
	default:
		e.dst = append(e.dst, CodeESC, 0x28, byte(s))
	}
	e.cur = s
}

func EncodeString(s string) Result { return NewEncoder().Encode(s) }
