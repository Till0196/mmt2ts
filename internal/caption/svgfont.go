// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package caption

import (
	"bytes"
	"encoding/xml"
	"math"
	"sort"
	"strconv"
	"strings"
)

// 4K の字幕は外字の書体を SVG フォント（STD-B62 第一編第三部 3.5.2）で送る。
// 読める描画器はもう無いので、輪郭を DRCS の字形に落とす。
const (
	drcsSide   = 36
	drcsLevels = 4
)

type fontGlyphs map[rune]Glyph

func (f fontGlyphs) Glyph(r rune) (Glyph, bool) {
	g, ok := f[r]
	return g, ok
}

func SVGFontGlyphs(svg []byte) map[rune]Glyph {
	out := make(map[rune]Glyph)
	dec := xml.NewDecoder(bytes.NewReader(svg))
	dec.Strict = false
	em, ascent, descent := 1000.0, 800.0, 200.0
	advance := math.NaN()
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		e, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch e.Name.Local {
		case "font":
			advance = number(attr(e, "", "horiz-adv-x"), math.NaN())
		case "font-face":
			em = math.Max(number(attr(e, "", "units-per-em"), 1000), 1)
			ascent = number(attr(e, "", "ascent"), em*0.8)
			descent = math.Abs(number(attr(e, "", "descent"), em-ascent))
		case "glyph":
			letters := []rune(attr(e, "", "unicode"))
			d := attr(e, "", "d")
			if len(letters) == 0 || d == "" {
				continue
			}
			width := number(attr(e, "", "horiz-adv-x"), advance)
			if math.IsNaN(width) {
				width = em
			}
			width = math.Max(width, 1)
			segments := flatten(svgPath(d))
			if len(segments) == 0 {
				continue
			}
			height := math.Max(ascent+descent, 1)
			// 輪郭は y が上向きで原点がベースライン。升を drcsSide の正方に。
			for i := range segments {
				for j := range segments[i] {
					p := segments[i][j]
					segments[i][j] = point{p.x / width * drcsSide, (ascent - p.y) / height * drcsSide}
				}
			}
			out[letters[0]] = Glyph{
				Width: drcsSide, Height: drcsSide, Depth: drcsLevels - 2,
				Pattern: pack(rasterise(segments, drcsSide, drcsSide), drcsLevels),
			}
		}
	}
	return out
}

func number(s string, or float64) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return or
	}
	return v
}

type point struct{ x, y float64 }

type segment [2]point

type stepKind byte

const (
	stepMove stepKind = iota
	stepLine
	stepQuad
	stepCubic
	stepClose
)

type step struct {
	kind stepKind
	p    [3]point
}

// svgPath は d を絶対座標の手に読む。M・L・H・V・Q・T・C・S・Z と相対形。
// A は書体には出ないので、端点までの直線にする。
func svgPath(d string) []step {
	var out []step
	var numbers []float64
	var current, start, lastQuad, lastCubic point
	haveQuad, haveCubic := false, false
	flush := func(command byte) {
		relative := command >= 'a'
		upper := command &^ 0x20
		at := 0
		take := func(n int) ([]float64, bool) {
			if at+n > len(numbers) {
				return nil, false
			}
			v := numbers[at : at+n]
			at += n
			return v, true
		}
		abs := func(x, y float64) point {
			if relative {
				return point{current.x + x, current.y + y}
			}
			return point{x, y}
		}
		first := true
		for {
			switch upper {
			case 'M':
				v, ok := take(2)
				if !ok {
					goto done
				}
				p := abs(v[0], v[1])
				if first {
					out = append(out, step{kind: stepMove, p: [3]point{p}})
					start = p
				} else {
					out = append(out, step{kind: stepLine, p: [3]point{p}})
				}
				current = p
				haveQuad, haveCubic = false, false
			case 'L':
				v, ok := take(2)
				if !ok {
					goto done
				}
				current = abs(v[0], v[1])
				out = append(out, step{kind: stepLine, p: [3]point{current}})
				haveQuad, haveCubic = false, false
			case 'H', 'V':
				v, ok := take(1)
				if !ok {
					goto done
				}
				switch {
				case upper == 'H' && relative:
					current.x += v[0]
				case upper == 'H':
					current.x = v[0]
				case relative:
					current.y += v[0]
				default:
					current.y = v[0]
				}
				out = append(out, step{kind: stepLine, p: [3]point{current}})
				haveQuad, haveCubic = false, false
			case 'Q', 'T':
				var c, p point
				if upper == 'Q' {
					v, ok := take(4)
					if !ok {
						goto done
					}
					c, p = abs(v[0], v[1]), abs(v[2], v[3])
				} else {
					v, ok := take(2)
					if !ok {
						goto done
					}
					c = current
					if haveQuad {
						c = point{2*current.x - lastQuad.x, 2*current.y - lastQuad.y}
					}
					p = abs(v[0], v[1])
				}
				out = append(out, step{kind: stepQuad, p: [3]point{c, p}})
				current, lastQuad, haveQuad, haveCubic = p, c, true, false
			case 'C', 'S':
				var c1, c2, p point
				if upper == 'C' {
					v, ok := take(6)
					if !ok {
						goto done
					}
					c1, c2, p = abs(v[0], v[1]), abs(v[2], v[3]), abs(v[4], v[5])
				} else {
					v, ok := take(4)
					if !ok {
						goto done
					}
					c1 = current
					if haveCubic {
						c1 = point{2*current.x - lastCubic.x, 2*current.y - lastCubic.y}
					}
					c2, p = abs(v[0], v[1]), abs(v[2], v[3])
				}
				out = append(out, step{kind: stepCubic, p: [3]point{c1, c2, p}})
				current, lastCubic, haveCubic, haveQuad = p, c2, true, false
			case 'A':
				v, ok := take(7)
				if !ok {
					goto done
				}
				current = abs(v[5], v[6])
				out = append(out, step{kind: stepLine, p: [3]point{current}})
				haveQuad, haveCubic = false, false
			case 'Z':
				out = append(out, step{kind: stepClose})
				current = start
				haveQuad, haveCubic = false, false
				goto done
			default:
				goto done
			}
			first = false
			if at >= len(numbers) {
				break
			}
		}
	done:
		numbers = numbers[:0]
	}
	var command byte
	var num strings.Builder
	pushNumber := func() {
		if num.Len() > 0 {
			if v, err := strconv.ParseFloat(num.String(), 64); err == nil {
				numbers = append(numbers, v)
			}
			num.Reset()
		}
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		switch {
		case (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') && c != 'e' && c != 'E':
			pushNumber()
			if command != 0 {
				flush(command)
			}
			command = c
			if c == 'Z' || c == 'z' {
				flush(c)
				command = 0
			}
		case c == '.':
			// 二つ目の小数点は次の数の頭（M.5.5）。
			if s := num.String(); strings.ContainsAny(s, ".eE") {
				pushNumber()
			}
			num.WriteByte(c)
		case c >= '0' && c <= '9' || c == 'e' || c == 'E':
			num.WriteByte(c)
		case c == '-' || c == '+':
			// 符号は数の頭。指数の符号は続きのまま。
			if s := num.String(); strings.HasSuffix(s, "e") || strings.HasSuffix(s, "E") {
				num.WriteByte(c)
			} else {
				pushNumber()
				num.WriteByte(c)
			}
		default:
			pushNumber()
		}
	}
	pushNumber()
	if command != 0 {
		flush(command)
	}
	return out
}

// flatten は曲線を十六分割の線分にし、開いた輪も閉じる。
func flatten(steps []step) []segment {
	const pieces = 16
	var out []segment
	var current, start point
	open := false
	closeRing := func() {
		if current != start {
			out = append(out, segment{current, start})
		}
	}
	for _, s := range steps {
		switch s.kind {
		case stepMove:
			if open {
				closeRing()
			}
			current, start, open = s.p[0], s.p[0], true
		case stepLine:
			out = append(out, segment{current, s.p[0]})
			current = s.p[0]
		case stepQuad, stepCubic:
			from := current
			for i := 1; i <= pieces; i++ {
				t := float64(i) / pieces
				u := 1 - t
				var p point
				if s.kind == stepQuad {
					c, e := s.p[0], s.p[1]
					p = point{u*u*from.x + 2*u*t*c.x + t*t*e.x, u*u*from.y + 2*u*t*c.y + t*t*e.y}
				} else {
					c1, c2, e := s.p[0], s.p[1], s.p[2]
					p = point{u*u*u*from.x + 3*u*u*t*c1.x + 3*u*t*t*c2.x + t*t*t*e.x,
						u*u*u*from.y + 3*u*u*t*c1.y + 3*u*t*t*c2.y + t*t*t*e.y}
				}
				out = append(out, segment{current, p})
				current = p
			}
		case stepClose:
			closeRing()
			current, open = start, false
		}
	}
	if open {
		closeRing()
	}
	return out
}

// rasterise は線分の輪を非零の巻き数で塗り、画素ごとの被覆（0〜1）を返す。
func rasterise(segments []segment, width, height int) []float64 {
	const sub = 4
	coverage := make([]float64, width*height)
	type crossing struct {
		x   float64
		dir int
	}
	var crossings []crossing
	for row := 0; row < height; row++ {
		for s := 0; s < sub; s++ {
			y := float64(row) + (float64(s)+0.5)/sub
			crossings = crossings[:0]
			for _, seg := range segments {
				top, bottom, dir := seg[0], seg[1], 1
				if bottom.y < top.y {
					top, bottom, dir = bottom, top, -1
				}
				// 上端は含み下端は含まない。頂点を二度数えない。
				if y < top.y || y >= bottom.y || top.y == bottom.y {
					continue
				}
				t := (y - top.y) / (bottom.y - top.y)
				crossings = append(crossings, crossing{top.x + (bottom.x-top.x)*t, dir})
			}
			sort.Slice(crossings, func(i, j int) bool { return crossings[i].x < crossings[j].x })
			winding, from := 0, 0.0
			for _, c := range crossings {
				was := winding
				winding += c.dir
				switch {
				case was == 0 && winding != 0:
					from = c.x
				case was != 0 && winding == 0:
					start := math.Min(math.Max(from, 0), float64(width))
					end := math.Min(math.Max(c.x, 0), float64(width))
					for col := int(start); col < width && float64(col) < end; col++ {
						left := math.Max(start, float64(col))
						right := math.Min(end, float64(col+1))
						if right > left {
							coverage[row*width+col] += (right - left) / sub
						}
					}
				}
			}
		}
	}
	return coverage
}

// pack は被覆を levels 階調にし、一画素を ceil(log2(levels)) bit で詰める。
func pack(coverage []float64, levels int) []byte {
	bits := 0
	for 1<<bits < levels {
		bits++
	}
	out := make([]byte, (len(coverage)*bits+7)/8)
	bit := 0
	for _, c := range coverage {
		v := int(math.Min(math.Max(c, 0), 1)*float64(levels-1) + 0.5)
		for i := bits - 1; i >= 0; i-- {
			if v>>i&1 != 0 {
				out[bit>>3] |= 0x80 >> (bit & 7)
			}
			bit++
		}
	}
	return out
}
