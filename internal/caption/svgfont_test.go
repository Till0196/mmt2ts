// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package caption

import (
	"bytes"
	"testing"

	"mmt2ts/internal/arib"
)

func pixel(g Glyph, x, y int) byte {
	bit := (y*g.Width + x) * 2
	return g.Pattern[bit>>3] >> (6 - bit&7) & 3
}

func TestSVGFontSquareGlyphFillsItsBox(t *testing.T) {
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><defs><font><font-face units-per-em="1024" ascent="880" descent="144"/><glyph unicode="&#xe054;" horiz-adv-x="1024" d="M0,-144 L1024,-144 L1024,880 L0,880 Z"/></font></defs></svg>`
	glyphs := SVGFontGlyphs([]byte(svg))
	g, ok := glyphs['']
	if !ok || len(glyphs) != 1 {
		t.Fatalf("glyphs = %v", glyphs)
	}
	if g.Width != drcsSide || g.Height != drcsSide || g.Depth != drcsLevels-2 || len(g.Pattern) != drcsSide*drcsSide*2/8 {
		t.Fatalf("glyph = %dx%d depth %d, %d bytes", g.Width, g.Height, g.Depth, len(g.Pattern))
	}
	for y := range drcsSide {
		for x := range drcsSide {
			if pixel(g, x, y) != drcsLevels-1 {
				t.Fatalf("pixel (%d,%d) = %d", x, y, pixel(g, x, y))
			}
		}
	}
}

// y は上向き。ascent に近いほど上の行。穴は逆向きの輪で透ける。
func TestSVGFontUpperHalfAndHoles(t *testing.T) {
	svg := `<svg><font><font-face units-per-em="1024" ascent="880" descent="144"/>
<glyph unicode="A" d="M0,368 Q512,368 1024,368 L1024,880 Q512,880 0,880 Z"/>
<glyph unicode="O" d="M0,-144 L1024,-144 L1024,880 L0,880 Z M256,112 L256,624 L768,624 L768,112 Z"/>
</font></svg>`
	glyphs := SVGFontGlyphs([]byte(svg))
	a := glyphs['A']
	if pixel(a, drcsSide/2, 4) != drcsLevels-1 || pixel(a, drcsSide/2, drcsSide-4) != 0 {
		t.Fatalf("A: top %d, bottom %d", pixel(a, drcsSide/2, 4), pixel(a, drcsSide/2, drcsSide-4))
	}
	o := glyphs['O']
	if pixel(o, drcsSide/2, drcsSide/2) != 0 || pixel(o, 2, 2) != drcsLevels-1 {
		t.Fatalf("O: hole %d, ring %d", pixel(o, drcsSide/2, drcsSide/2), pixel(o, 2, 2))
	}
}

func TestSVGPathRelativeAndShorthandSteps(t *testing.T) {
	steps := svgPath("m10,20 h30 v-5 l-10,10 q5,5 10,0 t10,0 c1,1 2,2 3,3 s1,1 2,2 z")
	if got := svgPath("M.5.5L1e2.5-1"); len(got) != 2 || got[0].p[0] != (point{0.5, 0.5}) || got[1].p[0] != (point{100, 0.5}) {
		t.Fatalf("adjacent decimals: %+v", got)
	}
	want := []step{
		{kind: stepMove, p: [3]point{{10, 20}}},
		{kind: stepLine, p: [3]point{{40, 20}}},
		{kind: stepLine, p: [3]point{{40, 15}}},
		{kind: stepLine, p: [3]point{{30, 25}}},
		{kind: stepQuad, p: [3]point{{35, 30}, {40, 25}}},
		{kind: stepQuad, p: [3]point{{45, 20}, {50, 25}}},
		{kind: stepCubic, p: [3]point{{51, 26}, {52, 27}, {53, 28}}},
		{kind: stepCubic, p: [3]point{{54, 29}, {54, 29}, {55, 30}}},
		{kind: stepClose},
	}
	if len(steps) != len(want) {
		t.Fatalf("steps = %+v", steps)
	}
	for i := range want {
		if steps[i] != want[i] {
			t.Errorf("step %d = %+v, want %+v", i, steps[i], want[i])
		}
	}
}

// 書体は文書と同じ MPU の subsample で届く。文書の私用面文字はその字形の DRCS になる。
func TestStreamCarriesSVGFontGlyphsAsDRCS(t *testing.T) {
	s := NewStream(AdditionalInfo{Language: "jpn", TMD: 0xf, DMF: 0x2}, NewDRCS(nil))
	ttml := `<tt xmlns="http://www.w3.org/ns/ttml"><body><div><p><span>&#xE054;字</span></p></div></body></tt>`
	svg := `<svg><font><font-face units-per-em="1024" ascent="880" descent="144"/><glyph unicode="&#xe054;" d="M0,-144 L1024,-144 L1024,880 L0,880 Z"/></font></svg>`
	s.Push(1, mfu(0x38, 1, 0, 1, DataTypeTTML, []byte(ttml)))
	mpu, ok := s.Push(1, mfu(0x38, 1, 1, 1, DataTypeSVGFont, []byte(svg)))
	if !ok {
		t.Fatal("the MPU did not complete")
	}
	out, err := s.Convert(mpu, Timing{})
	if err != nil {
		t.Fatal(err)
	}
	stats := s.Stats()
	if stats.FontGlyphs != 1 || stats.Writer.Characters[arib.ClassDRCS] != 1 || stats.Writer.Characters[arib.ClassUnconvertible] != 0 {
		t.Fatalf("font glyphs %d, characters %v", stats.FontGlyphs, stats.Writer.Characters)
	}
	if len(stats.Resources) != 0 {
		t.Fatalf("the font was reported as an unconverted resource: %v", stats.Resources)
	}
	var statement []byte
	for _, o := range out {
		if !o.Management {
			statement = o.Payload
		}
	}
	if !containsDRCSDefinition(statement) {
		t.Fatalf("no DRCS definition in the statement: % x", statement)
	}
}

func containsDRCSDefinition(b []byte) bool {
	for i := 0; i+7 < len(b); i++ {
		if b[i] == 0x1f && b[i+1] == arib.UnitDRCS2Byte && b[i+5] == 1 && b[i+6] == 0x21 && b[i+7] == 0x21 {
			return true
		}
	}
	return false
}

// TTML の region より行が多いとき、表示領域の下端で上へ戻されないよう領域を伸ばす。
func TestTwoLinesGetADisplayAreaTallEnough(t *testing.T) {
	w := NewWriter(3840, 2160, nil)
	st := Style{FontSizeW: 120, FontSizeH: 120, LineHeight: 160, HasLineHeight: true}
	body := w.Cue(Cue{Blocks: []Block{{
		HasRegion: true,
		Region:    Region{HasOrigin: true, OriginX: 800, OriginY: 160, HasExtent: true, ExtentW: 2376, ExtentH: 280},
		Spans: []Span{
			{Text: "一行目", Style: st},
			{Text: "二行目", Style: st, NewLine: true},
		},
	}}})[5:]
	area := append([]byte{arib.CodeCSI}, "594;80"...)
	area = append(area, 0x20, arib.CSISDF)
	if !bytes.Contains(body, area) {
		t.Fatalf("the area is not two 40-dot lines tall: % x", body)
	}
	if bytes.Contains(body, []byte{arib.CodeAPD, arib.CodeAPR}) {
		t.Fatalf("a new line is APR alone, not APD then APR: % x", body)
	}
}

// 同じ region に続く段落は、置き直さずに前の段落の下へ続ける。
func TestParagraphsInOneRegionStack(t *testing.T) {
	w := NewWriter(3840, 2160, nil)
	st := Style{FontSizeW: 120, FontSizeH: 120}
	region := Region{HasOrigin: true, OriginX: 800, OriginY: 160, HasExtent: true, ExtentW: 2376, ExtentH: 120}
	body := w.Cue(Cue{Blocks: []Block{
		{HasRegion: true, Region: region, Spans: []Span{{Text: "一", Style: st}}},
		{HasRegion: true, Region: region, Spans: []Span{{Text: "二", Style: st}}},
	}})[5:]
	if bytes.Contains(body, []byte{arib.CSIACPS}) || bytes.Count(body, []byte{arib.CodeAPR}) != 1 {
		t.Fatalf("the second paragraph is not a plain line feed: % x", body)
	}
	area := append([]byte{arib.CodeCSI}, "594;60"...)
	if !bytes.Contains(body, append(area, 0x20, arib.CSISDF)) {
		t.Fatalf("the area does not hold both paragraphs: % x", body)
	}
}
