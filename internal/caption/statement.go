// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package caption

import (
	"fmt"
	"strconv"

	"mmt2ts/internal/arib"
)

const (
	planeWidth   = 960
	planeHeight  = 540
	writingFmt7  = 7
	defaultCellW = 36
	defaultCellH = 36
)

type WriterStats struct {
	Cues        uint64
	Spans       uint64
	Scaled      uint64
	Colours     uint64
	ColourExact uint64
	Unsupported map[string]uint64
	Text        arib.Result
	Characters  [5]uint64
	Samples     []rune
}

func (s *WriterStats) note(what string) {
	if s.Unsupported == nil {
		s.Unsupported = make(map[string]uint64)
	}
	s.Unsupported[what]++
}

type Writer struct {
	PlaneW, PlaneH int
	DRCS           *DRCS

	stats WriterStats
	enc   *arib.Encoder
}

func NewWriter(planeW, planeH int, drcs *DRCS) *Writer {
	if planeW <= 0 || planeH <= 0 {
		planeW, planeH = 1920, 1080
	}
	return &Writer{PlaneW: planeW, PlaneH: planeH, DRCS: drcs}
}

func (w *Writer) Stats() WriterStats { return w.stats }

func (w *Writer) scaleX(v int) int { return v * planeWidth / w.PlaneW }
func (w *Writer) scaleY(v int) int { return v * planeHeight / w.PlaneH }

func (w *Writer) Cue(c Cue) []byte {
	w.stats.Cues++
	w.enc = arib.NewEncoder()
	w.enc.DRCS = w.DRCS
	w.enc.SICharacterSize = false
	var b []byte
	b = append(b, arib.CodeCS)
	b = append(b, csi(writingFmt7, -1, arib.CSISWF)...)
	b = append(b, csi(planeWidth, planeHeight, arib.CSISDF)...)

	cell := w.cell(c)
	b = append(b, csi(cell.width, cell.height, arib.CSISSM)...)
	if cell.hasHorizontal {
		b = append(b, csi(cell.horizontal, -1, arib.CSISHS)...)
	}
	if cell.hasVertical {
		b = append(b, csi(cell.vertical, -1, arib.CSISVS)...)
	}

	var current Style
	first := true
	sizeW, sizeH, haveSize := 0, 0, false
	size := func(st Style) []byte {
		if haveSize && st.FontSizeW == sizeW && st.FontSizeH == sizeH {
			return nil
		}
		sizeW, sizeH, haveSize = st.FontSizeW, st.FontSizeH, true
		return w.size(st, cell)
	}
	for _, blk := range c.Blocks {
		if blk.HasRegion && blk.Region.HasExtent {
			b = append(b, csi(w.scaleX(blk.Region.ExtentW), w.scaleY(blk.Region.ExtentH), arib.CSISDF)...)
			w.stats.Scaled++
		}
		if len(blk.Spans) > 0 {
			b = append(b, size(blk.Spans[0].Style)...)
		}
		if blk.HasRegion && blk.Region.HasOrigin {
			b = append(b, csi(w.scaleX(blk.Region.OriginX), w.scaleY(blk.Region.OriginY), arib.CSISDP)...)
		}
		b = append(b, arib.CodeAPS, 0x40, 0x40)
		for _, span := range blk.Spans {
			w.stats.Spans++
			if span.NewLine {
				b = append(b, arib.CodeAPD, arib.CodeAPR)
			}
			b = append(b, size(span.Style)...)
			if first || span.Style.Color != current.Color {
				b = append(b, w.colour(span.Style.Color, false)...)
			}
			if first || span.Style.Background != current.Background {
				b = append(b, w.colour(span.Style.Background, true)...)
			}
			switch changed := span.Style.HasOutline != current.HasOutline ||
				span.Style.Outline != current.Outline; {
			case span.Style.HasOutline && (first || changed):
				b = append(b, w.ornament(w.outlineColour(span.Style))...)
			case changed && !first:
				b = append(b, w.ornamentOff()...)
			}
			if span.Style.Bold {
				w.stats.note("tts:fontWeight bold has no B24 control")
			}
			if span.Style.Italic {
				w.stats.note("tts:fontStyle italic has no B24 control")
			}
			b = append(b, w.text(span.Text)...)
			current, first = span.Style, false
		}
	}
	return arib.DataUnit(arib.UnitStatementBody, b)
}

func (w *Writer) Clear() []byte { return arib.DataUnit(arib.UnitStatementBody, []byte{arib.CodeCS}) }

func (w *Writer) text(s string) []byte {
	res := w.enc.Continue(s)
	for class, count := range res.Counts {
		w.stats.Characters[class] += count
		w.stats.Text.Counts[class] += count
	}
	w.stats.Text.Records = append(w.stats.Text.Records, res.Records...)
	for _, r := range res.Unconvertible() {
		if len(w.stats.Samples) < 16 {
			w.stats.Samples = append(w.stats.Samples, r)
		}
	}
	return res.Bytes
}

type cellGeometry struct {
	width, height        int
	horizontal, vertical int
	hasHorizontal        bool
	hasVertical          bool
	full                 int
}

func (w *Writer) cell(c Cue) cellGeometry {
	g := cellGeometry{
		width: defaultCellW, height: defaultCellH, full: defaultCellH,
	}
	var ref Style
	for _, blk := range c.Blocks {
		for _, span := range blk.Spans {
			if span.Style.FontSizeH > ref.FontSizeH {
				ref = span.Style
			}
			if span.Style.FontSizeH == ref.FontSizeH && span.Style.FontSizeW > ref.FontSizeW {
				ref = span.Style
			}
		}
	}
	if ref.FontSizeH == 0 {
		return g
	}
	g.width, g.height = w.scaleX(ref.FontSizeW), w.scaleY(ref.FontSizeH)
	g.full = g.height
	if g.width <= 0 || g.height <= 0 {
		return cellGeometry{width: defaultCellW, height: defaultCellH, full: defaultCellH}
	}
	if ref.HasLetterSpacing {
		g.horizontal, g.hasHorizontal = w.scaleX(ref.LetterSpacing), true
	}
	if ref.HasLineHeight {
		if gap := w.scaleY(ref.LineHeight) - g.height; gap >= 0 {
			g.vertical, g.hasVertical = gap, true
		} else {
			w.stats.note(fmt.Sprintf("tts:lineHeight %d dots is shorter than the %d-dot character",
				w.scaleY(ref.LineHeight), g.height))
		}
	}
	return g
}

func (w *Writer) size(s Style, cell cellGeometry) []byte {
	if s.FontSizeH == 0 {
		return c1(arib.CodeNSZ)
	}
	width, height := w.scaleX(s.FontSizeW), w.scaleY(s.FontSizeH)
	code, name := byte(arib.CodeNSZ), "normal size"
	wantW, wantH := cell.width, cell.height
	switch {
	case half(width, cell.width) && half(height, cell.height):
		code, name = arib.CodeSSZ, "small size"
		wantW, wantH = cell.width/2, cell.height/2
	case half(width, cell.width):
		code, name = arib.CodeMSZ, "middle size"
		wantW = cell.width / 2
	case half(height, cell.height):
		w.stats.note("tts:fontSize is half height at full width, which has no B24 character size")
	}
	if width != wantW || height != wantH {
		w.stats.note(fmt.Sprintf("tts:fontSize %dx%d approximated by the %s of a %dx%d cell",
			width, height, name, cell.width, cell.height))
	}
	return c1(code)
}

func half(v, cell int) bool { return v*4 < cell*3 }

func (w *Writer) colour(css string, background bool) []byte {
	if css == "" {
		return nil
	}
	palette, index := w.resolve(css)
	b := []byte{arib.CodeCOL, 0x20, 0x40 | palette}
	if !background && palette == 0 && index <= 7 {
		return append(b, arib.CodeBKF+index)
	}
	base := byte(0x40)
	if background {
		base = 0x50
	}
	return append(b, arib.CodeCOL, base|index)
}

func (w *Writer) resolve(css string) (palette, index byte) {
	w.stats.Colours++
	palette, index, exact := nearestColour(css)
	if exact {
		w.stats.ColourExact++
	} else {
		w.stats.note("colour " + css + " approximated by the B24 default CLUT")
	}
	return palette, index
}

func (w *Writer) ornament(css string) []byte {
	palette, index := w.resolve(css)
	b := []byte{arib.CodeCSI, arib.ORNHemming, 0x3b}
	b = append(b, '0'+palette/10, '0'+palette%10, '0'+index/10, '0'+index%10)
	return append(b, 0x20, arib.CSIORN)
}

func (w *Writer) ornamentOff() []byte {
	return []byte{arib.CodeCSI, arib.ORNNone, 0x20, arib.CSIORN}
}

func (w *Writer) outlineColour(s Style) string {
	if s.Outline != "" {
		return s.Outline
	}
	if s.Color != "" {
		return s.Color
	}
	return "white"
}

func c1(code byte) []byte { return []byte{code} }

func csi(p1, p2 int, final byte) []byte {
	b := c1(arib.CodeCSI)
	b = append(b, strconv.Itoa(p1)...)
	if p2 >= 0 {
		b = append(b, 0x3b)
		b = append(b, strconv.Itoa(p2)...)
	}
	return append(b, 0x20, final)
}

func Wait(tenths int) []byte {
	var b []byte
	for tenths > 0 {
		step := min(tenths, 0x3f)
		b = append(b, c1(arib.CodeTIME)...)
		b = append(b, 0x20, byte(0x40+step))
		tenths -= step
	}
	return b
}

func (s WriterStats) String() string {
	return fmt.Sprintf("cues %d, spans %d, colours %d (%d exact)", s.Cues, s.Spans, s.Colours, s.ColourExact)
}
