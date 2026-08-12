// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package caption

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

const (
	nsTT       = "http://www.w3.org/ns/ttml"
	nsTTStyle  = "http://www.w3.org/ns/ttml#styling"
	nsTTParam  = "http://www.w3.org/ns/ttml#parameter"
	nsXML      = "http://www.w3.org/XML/1998/namespace"
	nsARIBTTML = "http://www.arib.or.jp/ns/arib-ttml/v1_0"
	nsARIBTT   = "http://www.arib.or.jp/ns/arib-tt"
)

func aribExtension(space string) bool {
	return space == nsARIBTTML || space == nsARIBTT
}

type Ticks int64

const ticksPerSecond = 90000

type Time struct {
	Ticks Ticks
	Set   bool
}

type Style struct {
	Color                string
	Background           string
	FontSizeW, FontSizeH int
	Bold                 bool
	Italic               bool
	Outline              string
	HasOutline           bool
	LetterSpacing        int
	HasLetterSpacing     bool
	LineHeight           int
	HasLineHeight        bool
}

type Region struct {
	ID                   string
	OriginX, OriginY     int
	ExtentW, ExtentH     int
	HasOrigin, HasExtent bool
}

type Span struct {
	Text    string
	Style   Style
	NewLine bool
}

type Block struct {
	Region    Region
	HasRegion bool
	Spans     []Span
}

type Cue struct {
	Begin, End Time
	Blocks     []Block
}

type Document struct {
	Language    string
	Cues        []Cue
	Unsupported []string
	External    []string
	Rounded     int
}

type ttmlParser struct {
	doc       Document
	styles    map[string]Style
	regions   map[string]Region
	frameRate int
	seen      map[string]bool
	planeW    int
	planeH    int
}

func ParseTTML(data []byte, planeW, planeH int) (*Document, error) {
	p := &ttmlParser{
		styles:    make(map[string]Style),
		regions:   make(map[string]Region),
		frameRate: 30,
		seen:      make(map[string]bool),
		planeW:    planeW,
		planeH:    planeH,
	}
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return &p.doc, fmt.Errorf("caption: TTML parse: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch {
		case start.Name.Space == nsTT && start.Name.Local == "tt":
			p.root(start)
		case start.Name.Space == nsTT && start.Name.Local == "style":
			p.style(start)
		case start.Name.Space == nsTT && start.Name.Local == "region":
			p.region(start)
		case start.Name.Space == nsTT && start.Name.Local == "body":
			if err := p.body(dec, start); err != nil {
				return &p.doc, err
			}
		}
	}
	return &p.doc, nil
}

func (p *ttmlParser) unsupported(what string) {
	if p.seen[what] {
		return
	}
	p.seen[what] = true
	p.doc.Unsupported = append(p.doc.Unsupported, what)
}

func (p *ttmlParser) root(e xml.StartElement) {
	for _, a := range e.Attr {
		switch {
		case a.Name.Space == nsXML && a.Name.Local == "lang":
			p.doc.Language = a.Value
		case a.Name.Space == nsTTParam && a.Name.Local == "frameRate":
			if n, err := strconv.Atoi(a.Value); err == nil && n > 0 {
				p.frameRate = n
			}
		}
	}
}

func (p *ttmlParser) style(e xml.StartElement) {
	id, s := "", Style{}
	for _, a := range e.Attr {
		if a.Name.Space == nsXML && a.Name.Local == "id" {
			id = a.Value
			continue
		}
		p.applyStyleAttr(&s, a)
	}
	if id != "" {
		p.styles[id] = s
	}
}

func (p *ttmlParser) applyStyleAttr(s *Style, a xml.Attr) {
	if aribExtension(a.Name.Space) {
		p.applyARIBStyleAttr(s, a)
		return
	}
	if a.Name.Space != nsTTStyle {
		return
	}
	switch a.Name.Local {
	case "lineHeight":
		if v, ok := p.length(a.Value, p.planeH); ok {
			s.LineHeight, s.HasLineHeight = v, true
		}
	case "color":
		s.Color = a.Value
	case "backgroundColor":
		s.Background = a.Value
	case "fontSize":
		if x, y, ok := p.fontSize(a.Value); ok {
			s.FontSizeW, s.FontSizeH = x, y
		}
	case "fontWeight":
		s.Bold = a.Value == "bold"
	case "fontStyle":
		s.Italic = a.Value == "italic"
	case "textOutline":
		s.Outline, s.HasOutline = p.textOutline(a.Value)
	case "ruby", "rubyAlign", "textEmphasis", "textCombine":
		p.unsupported("tts:" + a.Name.Local)
	case "writingMode", "displayAlign", "textAlign", "direction", "unicodeBidi", "wrapOption":
		p.unsupported("tts:" + a.Name.Local)
	case "border", "borderTop", "borderBottom", "borderLeft", "borderRight",
		"textShadow", "opacity", "textDecoration":
		p.unsupported("tts:" + a.Name.Local)
	}
}

func (p *ttmlParser) applyARIBStyleAttr(s *Style, a xml.Attr) {
	switch a.Name.Local {
	case "letter-spacing":
		if v, ok := p.length(a.Value, p.planeW); ok {
			s.LetterSpacing, s.HasLetterSpacing = v, true
		}
	default:
		p.unsupported("arib-tt:" + a.Name.Local)
	}
}

func (p *ttmlParser) textOutline(v string) (colour string, has bool) {
	fields := strings.Fields(v)
	if len(fields) == 0 || fields[0] == "none" {
		return "", false
	}
	if !isLength(fields[0]) {
		colour, fields = fields[0], fields[1:]
	}
	if len(fields) > 0 {
		p.unsupported("tts:textOutline thickness and blur have no B24 ornament")
	}
	return colour, true
}

func isLength(v string) bool {
	if v == "" {
		return false
	}
	c := v[0]
	return c == '.' || c == '+' || c == '-' || (c >= '0' && c <= '9')
}

func (p *ttmlParser) length(v string, reference int) (int, bool) {
	v = strings.TrimSpace(v)
	switch {
	case strings.HasSuffix(v, "px"):
		n, err := strconv.ParseFloat(strings.TrimSuffix(v, "px"), 64)
		return int(n), err == nil
	case strings.HasSuffix(v, "%"):
		n, err := strconv.ParseFloat(strings.TrimSuffix(v, "%"), 64)
		return int(n * float64(reference) / 100), err == nil
	case strings.HasSuffix(v, "c"):
		p.unsupported("cell units in a length")
		return 0, false
	case strings.HasSuffix(v, "em") || strings.HasSuffix(v, "rem"):
		p.unsupported("em units in a length")
		return 0, false
	default:
		n, err := strconv.ParseFloat(v, 64)
		return int(n), err == nil
	}
}

func (p *ttmlParser) region(e xml.StartElement) {
	r := Region{}
	for _, a := range e.Attr {
		switch {
		case a.Name.Space == nsXML && a.Name.Local == "id":
			r.ID = a.Value
		case a.Name.Space == nsTTStyle && a.Name.Local == "origin":
			if x, y, ok := p.pair(a.Value); ok {
				r.OriginX, r.OriginY, r.HasOrigin = x, y, true
			}
		case a.Name.Space == nsTTStyle && a.Name.Local == "extent":
			if w, h, ok := p.pair(a.Value); ok {
				r.ExtentW, r.ExtentH, r.HasExtent = w, h, true
			}
		}
	}
	if r.ID != "" {
		p.regions[r.ID] = r
	}
}

func (p *ttmlParser) fontSize(v string) (int, int, bool) {
	if len(strings.Fields(v)) == 2 {
		return p.pair(v)
	}
	h, ok := p.length(v, p.planeH)
	return h, h, ok
}

func (p *ttmlParser) pair(v string) (int, int, bool) {
	parts := strings.Fields(v)
	if len(parts) != 2 {
		return 0, 0, false
	}
	x, okX := p.length(parts[0], p.planeW)
	y, okY := p.length(parts[1], p.planeH)
	return x, y, okX && okY
}

func (p *ttmlParser) finishCue(cue **Cue) {
	if *cue == nil {
		return
	}
	p.doc.Cues = append(p.doc.Cues, **cue)
	*cue = nil
}

func (p *ttmlParser) body(dec *xml.Decoder, body xml.StartElement) error {
	type frame struct {
		style   Style
		region  string
		begin   Time
		end     Time
		element string
	}
	stack := []frame{{style: p.inherited(body), region: attr(body, nsTT, "region")}}
	var cue *Cue
	var block *Block
	divDepth := 0
	pending := false
	for {
		tok, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			return fmt.Errorf("caption: TTML body: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			top := stack[len(stack)-1]
			f := frame{style: top.style, region: top.region, begin: top.begin, end: top.end, element: t.Name.Local}
			if r := attr(t, nsTT, "region"); r != "" {
				f.region = r
			}
			p.resolveStyle(&f.style, t)
			if b, ok := p.time(attr(t, "", "begin")); ok {
				f.begin = Time{Ticks: b, Set: true}
			}
			if e, ok := p.time(attr(t, "", "end")); ok {
				f.end = Time{Ticks: e, Set: true}
			}
			if d, ok := p.time(attr(t, "", "dur")); ok && f.begin.Set {
				f.end = Time{Ticks: f.begin.Ticks + d, Set: true}
			}
			switch {
			case t.Name.Space == nsTT && t.Name.Local == "div":
				divDepth++
				if cue == nil {
					cue = &Cue{Begin: f.begin, End: f.end}
				}
			case t.Name.Space == nsTT && t.Name.Local == "p":
				if cue == nil {
					cue = &Cue{Begin: f.begin, End: f.end}
				}
				if len(cue.Blocks) == 0 && !cue.Begin.Set {
					cue.Begin, cue.End = f.begin, f.end
				}
				if f.begin != cue.Begin || f.end != cue.End {
					p.unsupported("a paragraph timed apart from its division")
				}
				block = &Block{}
				if r, ok := p.regions[f.region]; ok {
					block.Region, block.HasRegion = r, true
				}
			case t.Name.Space == nsTT && t.Name.Local == "br":
				pending = true
			case t.Name.Space == nsTT && t.Name.Local == "image",
				t.Name.Space == nsARIBTTML && t.Name.Local == "image":
				p.doc.External = append(p.doc.External, "image reference in the document body")
			}
			stack = append(stack, f)
		case xml.CharData:
			text := string(t)
			if strings.TrimSpace(text) == "" {
				continue
			}
			if block == nil {
				continue
			}
			block.Spans = append(block.Spans, Span{
				Text:    collapse(text),
				Style:   stack[len(stack)-1].style,
				NewLine: pending,
			})
			pending = false
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			switch {
			case t.Name.Space == nsTT && t.Name.Local == "p":
				if block != nil && cue != nil {
					cue.Blocks = append(cue.Blocks, *block)
					block = nil
				}
				if divDepth == 0 {
					p.finishCue(&cue)
				}
			case t.Name.Space == nsTT && t.Name.Local == "div":
				if divDepth > 0 {
					divDepth--
				}
				if divDepth == 0 {
					p.finishCue(&cue)
				}
			case t.Name.Space == nsTT && t.Name.Local == "body":
				p.finishCue(&cue)
				return nil
			}
		}
	}
}

func (p *ttmlParser) inherited(e xml.StartElement) Style {
	var s Style
	p.resolveStyle(&s, e)
	return s
}

func (p *ttmlParser) resolveStyle(s *Style, e xml.StartElement) {
	for _, ref := range strings.Fields(attr(e, nsTT, "style")) {
		if st, ok := p.styles[ref]; ok {
			merge(s, st)
		}
	}
	for _, a := range e.Attr {
		p.applyStyleAttr(s, a)
	}
}

func merge(dst *Style, src Style) {
	if src.Color != "" {
		dst.Color = src.Color
	}
	if src.Background != "" {
		dst.Background = src.Background
	}
	if src.FontSizeH != 0 {
		dst.FontSizeW, dst.FontSizeH = src.FontSizeW, src.FontSizeH
	}
	if src.HasOutline {
		dst.Outline, dst.HasOutline = src.Outline, true
	}
	if src.HasLetterSpacing {
		dst.LetterSpacing, dst.HasLetterSpacing = src.LetterSpacing, true
	}
	if src.HasLineHeight {
		dst.LineHeight, dst.HasLineHeight = src.LineHeight, true
	}
	dst.Bold = dst.Bold || src.Bold
	dst.Italic = dst.Italic || src.Italic
}

func attr(e xml.StartElement, space, local string) string {
	for _, a := range e.Attr {
		if a.Name.Local != local {
			continue
		}
		if space == "" || a.Name.Space == space || a.Name.Space == "" {
			return a.Value
		}
	}
	return ""
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

func (p *ttmlParser) time(v string) (Ticks, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if strings.Contains(v, ":") {
		return p.clockTime(v)
	}
	return p.offsetTime(v)
}

func (p *ttmlParser) clockTime(v string) (Ticks, bool) {
	parts := strings.Split(v, ":")
	if len(parts) != 3 {
		p.unsupported("clock time with " + strconv.Itoa(len(parts)) + " fields")
		return 0, false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || m > 59 {
		return 0, false
	}
	secs := parts[2]
	frac := Ticks(0)
	if i := strings.IndexAny(secs, ".:"); i >= 0 {
		if secs[i] == ':' {
			frames, err := strconv.Atoi(secs[i+1:])
			if err != nil {
				return 0, false
			}
			frac = Ticks(frames) * ticksPerSecond / Ticks(p.frameRate)
			if frac*Ticks(p.frameRate) != Ticks(frames)*ticksPerSecond {
				p.doc.Rounded++
			}
		} else {
			f, ok := p.fraction(secs[i+1:])
			if !ok {
				return 0, false
			}
			frac = f
		}
		secs = secs[:i]
	}
	s, err := strconv.Atoi(secs)
	if err != nil || s > 59 {
		return 0, false
	}
	return Ticks((h*3600+m*60+s))*ticksPerSecond + frac, true
}

func (p *ttmlParser) fraction(digits string) (Ticks, bool) {
	scale := Ticks(1)
	value := Ticks(0)
	for _, d := range digits {
		if d < '0' || d > '9' {
			return 0, false
		}
		value = value*10 + Ticks(d-'0')
		scale *= 10
	}
	ticks := value * ticksPerSecond / scale
	if ticks*scale != value*ticksPerSecond {
		p.doc.Rounded++
	}
	return ticks, true
}

func (p *ttmlParser) offsetTime(v string) (Ticks, bool) {
	i := 0
	for i < len(v) && (v[i] == '.' || (v[i] >= '0' && v[i] <= '9')) {
		i++
	}
	number, unit := v[:i], v[i:]
	if number == "" {
		return 0, false
	}
	whole, frac := number, ""
	if dot := strings.Index(number, "."); dot >= 0 {
		whole, frac = number[:dot], number[dot+1:]
	}
	n, err := strconv.Atoi(whole)
	if err != nil {
		return 0, false
	}
	var perUnit Ticks
	switch unit {
	case "h":
		perUnit = 3600 * ticksPerSecond
	case "m":
		perUnit = 60 * ticksPerSecond
	case "s", "":
		perUnit = ticksPerSecond
	case "ms":
		perUnit = ticksPerSecond / 1000
	case "f":
		perUnit = ticksPerSecond / Ticks(p.frameRate)
	case "t":
		p.unsupported("tick offset times need ttp:tickRate")
		return 0, false
	default:
		p.unsupported("offset time unit " + unit)
		return 0, false
	}
	total := Ticks(n) * perUnit
	if frac != "" {
		f, ok := p.fraction(frac)
		if !ok {
			return 0, false
		}
		total += f * perUnit / ticksPerSecond
	}
	return total, true
}
