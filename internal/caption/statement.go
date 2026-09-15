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
	area, hasArea := w.area(c, cell)
	if hasArea {
		b = append(b, csi(area.w, area.h, arib.CSISDF)...)
		b = append(b, csi(area.x, area.y, arib.CSISDP)...)
		w.stats.Scaled++
	}
	for _, blk := range c.Blocks {
		if len(blk.Spans) > 0 {
			b = append(b, size(blk.Spans[0].Style)...)
		}
		// 字を置いたあとの SDP/SDF は無視されるので、二つ目からの
		// block は ACPS で置く。
		if ox, oy := w.scaleX(blk.Region.OriginX), w.scaleY(blk.Region.OriginY); blk.HasRegion &&
			blk.Region.HasOrigin && (ox != area.x || oy != area.y) {
			var st Style
			if len(blk.Spans) > 0 {
				st = blk.Spans[0].Style
			}
			b = append(b, csi(ox, oy+w.linePitch(st, cell), arib.CSIACPS)...)
		} else {
			b = append(b, arib.CodeAPS, 0x40, 0x40)
		}
		for _, span := range blk.Spans {
			w.stats.Spans++
			if span.NewLine {
				b = append(b, arib.CodeAPR)
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

type displayArea struct{ x, y, w, h int }

// area は全 block の region を包む表示領域。TTML は region からはみ出た行も
// そのまま出すが、表示領域の下端で一番上の行へ戻されるので、行が収まる
// まで伸ばす。
func (w *Writer) area(c Cue, cell cellGeometry) (displayArea, bool) {
	var a displayArea
	has := false
	for _, blk := range c.Blocks {
		if !blk.HasRegion || !blk.Region.HasOrigin {
			continue
		}
		x, y := w.scaleX(blk.Region.OriginX), w.scaleY(blk.Region.OriginY)
		bw, bh := 0, w.blockHeight(blk, cell)
		if blk.Region.HasExtent {
			bw, bh = w.scaleX(blk.Region.ExtentW), max(bh, w.scaleY(blk.Region.ExtentH))
		}
		if !has {
			a, has = displayArea{x, y, bw, bh}, true
			continue
		}
		right, bottom := max(a.x+a.w, x+bw), max(a.y+a.h, y+bh)
		a.x, a.y = min(a.x, x), min(a.y, y)
		a.w, a.h = right-a.x, bottom-a.y
	}
	if has {
		a.w, a.h = min(a.w, planeWidth-a.x), min(a.h, planeHeight-a.y)
	}
	return a, has
}

func (w *Writer) blockHeight(blk Block, cell cellGeometry) int {
	h, pitch := 0, 0
	for i, span := range blk.Spans {
		if span.NewLine || i == 0 {
			h += pitch
			pitch = 0
		}
		pitch = max(pitch, w.linePitch(span.Style, cell))
	}
	return h + pitch
}

func (w *Writer) linePitch(s Style, cell cellGeometry) int {
	if w.sizeCode(s, cell) == arib.CodeSSZ {
		return (cell.height + cell.vertical) / 2
	}
	return cell.height + cell.vertical
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

func (w *Writer) sizeCode(s Style, cell cellGeometry) byte {
	if s.FontSizeH == 0 {
		return arib.CodeNSZ
	}
	width, height := w.scaleX(s.FontSizeW), w.scaleY(s.FontSizeH)
	switch {
	case half(width, cell.width) && half(height, cell.height):
		return arib.CodeSSZ
	case half(width, cell.width):
		return arib.CodeMSZ
	}
	return arib.CodeNSZ
}

func (w *Writer) size(s Style, cell cellGeometry) []byte {
	code := w.sizeCode(s, cell)
	if s.FontSizeH == 0 {
		return c1(code)
	}
	width, height := w.scaleX(s.FontSizeW), w.scaleY(s.FontSizeH)
	name := "normal size"
	wantW, wantH := cell.width, cell.height
	switch code {
	case arib.CodeSSZ:
		name = "small size"
		wantW, wantH = cell.width/2, cell.height/2
	case arib.CodeMSZ:
		name = "middle size"
		wantW = cell.width / 2
	default:
		if half(height, cell.height) {
			w.stats.note("tts:fontSize is half height at full width, which has no B24 character size")
		}
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
