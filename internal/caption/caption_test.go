// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package caption

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"mmt2ts/internal/arib"
)

func mfu(tag, seq, number, last, dataType byte, data []byte) []byte {
	b := []byte{tag, seq, number, last, dataType << 4}
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func TestParseMFUReadsTheSampleHeader(t *testing.T) {
	m, err := ParseMFU(mfu(0x30, 7, 0, 2, DataTypeTTML, []byte("<tt/>")))
	if err != nil {
		t.Fatal(err)
	}
	if m.SubtitleTag != 0x30 || m.SequenceNumber != 7 || m.LastNumber != 2 {
		t.Fatalf("mfu = %+v", m)
	}
	if string(m.Data) != "<tt/>" || m.Trailing != 0 {
		t.Fatalf("data = %q, trailing %d", m.Data, m.Trailing)
	}
}

func TestParseMFUReadsTheHintList(t *testing.T) {
	b := []byte{0x30, 1, 0, 2, DataTypeTTML<<4 | 0x04}
	b = binary.BigEndian.AppendUint16(b, 3)
	b = append(b, DataTypePNG<<4)
	b = binary.BigEndian.AppendUint16(b, 100)
	b = append(b, DataTypeWOFFFont<<4)
	b = binary.BigEndian.AppendUint16(b, 200)
	b = append(b, "abc"...)
	m, err := ParseMFU(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Hints) != 2 || m.Hints[0].DataType != DataTypePNG || m.Hints[1].Size != 200 {
		t.Fatalf("hints = %+v", m.Hints)
	}
	if string(m.Data) != "abc" {
		t.Fatalf("data = %q", m.Data)
	}
}

func TestParseAdditionalInfoDecidesTypeAndTiming(t *testing.T) {
	b := []byte{0x38, 0x00}
	b = append(b, "jpn"...)
	b = append(b, TypeSuperimposition<<6|0x00, TMDMPUTime<<4|0x03, 0x10)
	info, ok := ParseAdditionalInfo(b)
	if !ok {
		t.Fatal("additional info did not parse")
	}
	if !info.Superimposition() || info.Language != "jpn" || info.TMD != TMDMPUTime || info.DMF != 3 {
		t.Fatalf("info = %+v", info)
	}
	w, h, ok := info.DisplaySize()
	if !ok || w != 3840 || h != 2160 {
		t.Fatalf("display = %dx%d", w, h)
	}
}

const sampleTTML = `<?xml version="1.0" encoding="UTF-8"?>
<tt xmlns="http://www.w3.org/ns/ttml"
    xmlns:tts="http://www.w3.org/ns/ttml#styling"
    xml:lang="jpn">
 <head>
  <styling>
   <style xml:id="s1" tts:color="yellow" tts:fontSize="72px"/>
  </styling>
  <layout>
   <region xml:id="r1" tts:origin="480px 1620px" tts:extent="2880px 360px"/>
  </layout>
 </head>
 <body>
  <div begin="00:00:01.500" end="00:00:04.000">
   <p region="r1" style="s1">こんにちは<br/>字幕です</p>
  </div>
 </body>
</tt>`

func TestParseTTMLResolvesStyleRegionAndTime(t *testing.T) {
	doc, err := ParseTTML([]byte(sampleTTML), 3840, 2160)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Language != "jpn" {
		t.Fatalf("language = %q", doc.Language)
	}
	if len(doc.Cues) != 1 {
		t.Fatalf("cues = %d", len(doc.Cues))
	}
	c := doc.Cues[0]
	if !c.Begin.Set || c.Begin.Ticks != 1500*90 {
		t.Fatalf("begin = %+v", c.Begin)
	}
	if !c.End.Set || c.End.Ticks != 4*90000 {
		t.Fatalf("end = %+v", c.End)
	}
	if len(c.Blocks) != 1 {
		t.Fatalf("blocks = %+v", c.Blocks)
	}
	blk := c.Blocks[0]
	if !blk.HasRegion || blk.Region.OriginX != 480 || blk.Region.ExtentH != 360 {
		t.Fatalf("region = %+v", blk.Region)
	}
	if len(blk.Spans) != 2 {
		t.Fatalf("spans = %+v", blk.Spans)
	}
	if blk.Spans[0].Style.Color != "yellow" || blk.Spans[0].Style.FontSizeW != 72 || blk.Spans[0].Style.FontSizeH != 72 {
		t.Fatalf("style = %+v", blk.Spans[0].Style)
	}
	if !blk.Spans[1].NewLine {
		t.Fatal("the line break between the spans was lost")
	}
}

func TestParseTTMLIgnoresPrefixAndReportsUnsupported(t *testing.T) {
	doc, err := ParseTTML([]byte(`<x:tt xmlns:x="http://www.w3.org/ns/ttml"
		xmlns:s="http://www.w3.org/ns/ttml#styling">
		<x:body><x:div><x:p s:writingMode="tblr">縦</x:p></x:div></x:body></x:tt>`), 1920, 1080)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Cues) != 1 || len(doc.Cues[0].Blocks[0].Spans) != 1 {
		t.Fatalf("cues = %+v", doc.Cues)
	}
	if len(doc.Unsupported) == 0 {
		t.Fatal("tts:writingMode was accepted silently")
	}
}

func TestParseTTMLRejectsBrokenDocuments(t *testing.T) {
	_, err := ParseTTML([]byte(`<tt xmlns="http://www.w3.org/ns/ttml"><body>`), 1920, 1080)
	if err == nil {
		t.Fatal("a truncated document parsed successfully")
	}
}

func TestOffsetTimesUseIntegerArithmetic(t *testing.T) {
	doc, err := ParseTTML([]byte(`<tt xmlns="http://www.w3.org/ns/ttml"><body><div>
		<p begin="1.5s" dur="500ms">a</p></div></body></tt>`), 1920, 1080)
	if err != nil {
		t.Fatal(err)
	}
	c := doc.Cues[0]
	if c.Begin.Ticks != 135000 || c.End.Ticks != 180000 {
		t.Fatalf("begin %d end %d", c.Begin.Ticks, c.End.Ticks)
	}
}

func captionStream() *Stream {
	return NewStream(AdditionalInfo{
		SubtitleTag: 0x30,
		Language:    "jpn",
		Type:        TypeClosedCaption,
		TMD:         TMDMPUTime,
		DMF:         0x3,
		Resolution:  0x1,
	}, NewDRCS(nil))
}

func TestSingleSubsampleMPUCompletesOnArrival(t *testing.T) {
	s := captionStream()
	done, ok := s.Push(10, mfu(0x30, 1, 0, 0, DataTypeTTML, []byte(sampleTTML)))
	if !ok {
		t.Fatal("a single-subsample MPU did not complete on arrival")
	}
	if done.Sequence != 10 || len(done.TTML) == 0 {
		t.Fatalf("mpu = %+v", done)
	}
	if _, ok := s.Flush(); ok {
		t.Fatal("the MPU was still pending after it completed")
	}
	next, ok := s.Push(4, mfu(0x30, 2, 0, 0, DataTypeTTML,
		[]byte(`<tt xmlns="http://www.w3.org/ns/ttml"><body><div><p>x</p></div></body></tt>`)))
	if !ok || next.Sequence != 4 {
		t.Fatalf("the following MPU did not complete on arrival: %+v, ok=%v", next, ok)
	}
}

func TestMultiSubsampleMPUWaitsForItsLastSubsample(t *testing.T) {
	s := captionStream()
	if _, ok := s.Push(10, mfu(0x30, 1, 0, 2, DataTypeTTML, []byte(sampleTTML))); ok {
		t.Fatal("an MPU completed before its last subsample arrived")
	}
	if _, ok := s.Push(10, mfu(0x30, 1, 1, 2, DataTypePNG, []byte{0x89, 'P'})); ok {
		t.Fatal("an MPU completed one subsample early")
	}
	done, ok := s.Push(10, mfu(0x30, 1, 2, 2, DataTypeWOFFFont, []byte{'w', 'O'}))
	if !ok {
		t.Fatal("the MPU did not complete when its last subsample arrived")
	}
	if len(done.Resources) != 2 {
		t.Fatalf("resources = %+v", done.Resources)
	}
}

func TestStreamConvertsOneMPU(t *testing.T) {
	s := captionStream()
	s.Push(10, mfu(0x30, 1, 0, 1, DataTypeTTML, []byte(sampleTTML)))
	done, ok := s.Push(10, mfu(0x30, 1, 1, 1, DataTypePNG, []byte{0x89, 'P', 'N', 'G'}))
	if !ok {
		t.Fatal("the MPU never completed")
	}
	if len(done.TTML) == 0 || len(done.Resources) != 1 {
		t.Fatalf("mpu = %+v", done)
	}
	out, err := s.Convert(done, Timing{MPUPresentation: 900000, HasMPU: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 2 {
		t.Fatalf("outputs = %d, want management plus statement", len(out))
	}
	if !out[0].Management {
		t.Fatal("the first output is not the caption management data group")
	}
	if tcs := out[0].Payload[14] >> 2 & 0x03; tcs != 0 {
		t.Fatalf("caption TCS = %d, want 8-unit code", tcs)
	}
	statement := out[1]
	if !statement.HasPTS {
		t.Fatal("a caption timed by the MPU timestamp has no PTS")
	}
	if want := int64(900000 + 135000); statement.PTS != want {
		t.Fatalf("PTS = %d, want %d", statement.PTS, want)
	}
	if statement.Payload[0] != arib.DataIdentifierSynchronised {
		t.Fatalf("data identifier = %#02x", statement.Payload[0])
	}
	st := s.Stats()
	if st.Documents != 1 || st.Statements != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if st.Resources["PNG"] != 1 {
		t.Fatalf("the image resource was not reported: %+v", st.Resources)
	}
	if st.Writer.Characters[0] == 0 {
		t.Fatal("no characters were encoded")
	}
	if st.Writer.Characters[4] != 0 {
		t.Fatalf("unconvertible characters: %q", string(st.Writer.Samples))
	}
}

func TestStreamKeepsSuperimpositionAsynchronous(t *testing.T) {
	s := NewStream(AdditionalInfo{
		Language:   "jpn",
		Type:       TypeSuperimposition,
		TMD:        TMDNone,
		Resolution: 0x1,
	}, nil)
	done, ok := s.Push(1, mfu(0x38, 1, 0, 0, DataTypeTTML, []byte(sampleTTML)))
	if !ok {
		t.Fatal("a single-subsample MPU did not complete on arrival")
	}
	out, err := s.Convert(done, Timing{MPUPresentation: 1000, HasMPU: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range out {
		if o.HasPTS {
			t.Fatal("a superimposition without time control was given a time stamp")
		}
		if o.Payload[0] != arib.DataIdentifierAsynchronous {
			t.Fatalf("data identifier = %#02x", o.Payload[0])
		}
	}
}

func TestCaptionWithoutDocumentTimeModeRemainsSynchronous(t *testing.T) {
	s := NewStream(AdditionalInfo{
		Language: "jpn", Type: TypeClosedCaption, TMD: TMDNone, Resolution: 0x1,
	}, nil)
	done, ok := s.Push(1, mfu(0x30, 1, 0, 0, DataTypeTTML, []byte(sampleTTML)))
	if !ok {
		t.Fatal("a single-subsample MPU did not complete on arrival")
	}
	out, err := s.Convert(done, Timing{MPUPresentation: 90000, HasMPU: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range out {
		if !o.HasPTS {
			t.Fatal("a caption service with TMD none lost its PES timestamp")
		}
		if o.Payload[0] != arib.DataIdentifierSynchronised {
			t.Fatalf("data identifier = %#02x", o.Payload[0])
		}
	}
}

func TestStreamReportsBrokenDocument(t *testing.T) {
	s := captionStream()
	done, _ := s.Push(1, mfu(0x30, 1, 0, 0, DataTypeTTML, []byte("<tt")))
	if _, err := s.Convert(done, Timing{MPUPresentation: 0, HasMPU: true}); err == nil {
		t.Fatal("a broken document was converted")
	}
	if s.Stats().ParseErrors != 1 {
		t.Fatalf("stats = %+v", s.Stats())
	}
}

type squareGlyphs struct{}

func (squareGlyphs) Glyph(rune) (Glyph, bool) {
	return Glyph{Width: 8, Height: 8, Depth: 1, Pattern: make([]byte, 8)}, true
}

func TestDRCSAllocatesAndReusesGlyphs(t *testing.T) {
	d := NewDRCS(squareGlyphs{})
	first, ok := d.AllocateDRCS('\U0001F600')
	if !ok || first != 0x2121 {
		t.Fatalf("first cell = %#04x, ok = %v", first, ok)
	}
	second, ok := d.AllocateDRCS('\U0001F601')
	if !ok || second != first {
		t.Fatalf("second cell = %#04x", second)
	}
	if d.Allocated != 1 || d.Reused != 1 {
		t.Fatalf("allocated %d, reused %d", d.Allocated, d.Reused)
	}
	unit := d.Definitions()
	if len(unit) == 0 || unit[1] != arib.UnitDRCS2Byte {
		t.Fatalf("definition data unit = % x", unit)
	}
	if d.Definitions() != nil {
		t.Fatal("the same definition was written twice")
	}
}

func TestWithoutGlyphSourceDRCSRefuses(t *testing.T) {
	d := NewDRCS(nil)
	if _, ok := d.AllocateDRCS('\U0001F600'); ok {
		t.Fatal("a glyph was invented with no font")
	}
}

func TestStatementStartsWithClearAndFormat(t *testing.T) {
	w := NewWriter(3840, 2160, nil)
	unit := w.Cue(Cue{Blocks: []Block{{Spans: []Span{{Text: "あ😀"}}}}})
	if unit[0] != arib.UnitSeparator || unit[1] != arib.UnitStatementBody {
		t.Fatalf("data unit header = % x", unit[:2])
	}
	body := unit[5:]
	if body[0] != arib.CodeCS {
		t.Fatalf("statement does not start with a clear: % x", body[:4])
	}
	if !strings.Contains(string(body), string([]byte{arib.CodeCSI})) {
		t.Fatal("no 8-unit C1 control sequence was written")
	}
	if strings.Contains(string(body), "あ") || strings.Contains(string(body), "😀") {
		t.Fatalf("UTF-8 leaked into an 8-unit caption statement: % x", body)
	}
	if !strings.Contains(string(body), string([]byte{0x24, 0x22})) {
		t.Fatalf("8-unit hiragana is missing: % x", body)
	}
}

func TestStatementPlacesTheRegion(t *testing.T) {
	w := NewWriter(3840, 2160, nil)
	unit := w.Cue(Cue{Blocks: []Block{{
		HasRegion: true,
		Region: Region{
			OriginX: 1672, OriginY: 1796, HasOrigin: true,
			ExtentW: 480, ExtentH: 240, HasExtent: true,
		},
		Spans: []Span{{Text: "あ"}},
	}}})
	body := string(unit[5:])
	extent := string([]byte{arib.CodeCSI}) + "120;60" + string([]byte{0x20, arib.CSISDF})
	if !strings.Contains(body, extent) {
		t.Fatalf("the region extent is not the display format: % x", unit)
	}
	position := string([]byte{arib.CodeCSI}) + "418;449" + string([]byte{0x20, arib.CSISDP})
	if !strings.Contains(body, position) {
		t.Fatalf("the region origin is not the display position: % x", unit)
	}
	if arib.CSISDP != 0x5f || arib.CSISSM != 0x57 || arib.CSISHS != 0x58 || arib.CSISVS != 0x59 {
		t.Fatalf("control sequence final bytes drifted from STD-B24 table 7-14")
	}
}

func TestCueWithoutBeginUsesTheMPUTime(t *testing.T) {
	const clear = `<?xml version="1.0" encoding="utf-8"?>
<tt xmlns="http://www.w3.org/ns/ttml"><body><div><p>字幕</p></div></body></tt>`
	s := NewStream(AdditionalInfo{
		SubtitleTag: 0x30, Language: "jpn", Type: TypeClosedCaption,
		TMD: TMDReference, DMF: 0xa, Resolution: 0x1,
	}, NewDRCS(nil))
	done, ok := s.Push(10, mfu(0x30, 1, 0, 0, DataTypeTTML, []byte(clear)))
	if !ok {
		t.Fatal("the MPU never completed")
	}
	const mpuTime = 5000000
	out, err := s.Convert(done, Timing{
		MPUPresentation: mpuTime, HasMPU: true,
		ReferenceStart: 0, HasReference: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var statement *Output
	for i := range out {
		if !out[i].Management {
			statement = &out[i]
		}
	}
	if statement == nil {
		t.Fatalf("no statement was produced: %+v", out)
	}
	if statement.PTS != mpuTime {
		t.Fatalf("a cue with no begin is at %d, want the MPU time %d", statement.PTS, mpuTime)
	}
	body := statement.Payload
	if !bytes.Contains(body, []byte{arib.UnitSeparator, arib.UnitStatementBody}) {
		t.Fatalf("no statement body data unit: % x", body)
	}
}

func TestManagementIsTimedWithItsStatements(t *testing.T) {
	s := NewStream(AdditionalInfo{
		SubtitleTag: 0x30, Language: "jpn", Type: TypeClosedCaption,
		TMD: TMDReference, DMF: 0xa, Resolution: 0x1,
	}, NewDRCS(nil))
	done, ok := s.Push(10, mfu(0x30, 1, 0, 0, DataTypeTTML, []byte(sampleTTML)))
	if !ok {
		t.Fatal("the MPU never completed")
	}
	const reference = 200000
	out, err := s.Convert(done, Timing{
		MPUPresentation: 900000, HasMPU: true,
		ReferenceStart: reference, HasReference: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || !out[0].Management || out[1].Management {
		t.Fatalf("outputs = %+v", out)
	}
	if want := int64(reference + 1500*90); out[1].PTS != want {
		t.Fatalf("statement PTS = %d, want %d", out[1].PTS, want)
	}
	if out[0].PTS != out[1].PTS {
		t.Fatalf("management at %d but the statement it introduces is at %d",
			out[0].PTS, out[1].PTS)
	}
	if !out[0].HasPTS {
		t.Fatal("the management group of a synchronised caption has no time stamp")
	}
}

func TestSpansShareOneDesignationState(t *testing.T) {
	symbols := []byte{0x1b, 0x24, 0x3b}
	kanji := []byte{0x1b, 0x24, 0x42}
	w := NewWriter(3840, 2160, nil)
	body := w.Cue(Cue{Blocks: []Block{{Spans: []Span{
		{Text: "あ♬"},
		{Text: "い"},
	}}}})[5:]
	i := bytes.Index(body, []byte{0x7d, 0x7a})
	if i < 0 {
		t.Fatalf("the note was not written at all: % x", body)
	}
	if !bytes.Contains(body[:i], symbols) {
		t.Fatalf("the note was written without designating its set: % x", body)
	}
	if !bytes.Contains(body[i:], kanji) {
		t.Fatalf("the span after the note is read out of the additional symbol set: % x", body)
	}
	w2 := NewWriter(3840, 2160, nil)
	body2 := w2.Cue(Cue{Blocks: []Block{
		{Spans: []Span{{Text: "♬"}}},
		{Spans: []Span{{Text: "あ"}}},
	}})[5:]
	j := bytes.Index(body2, []byte{0x7d, 0x7a})
	if j < 0 || !bytes.Contains(body2[j:], kanji) {
		t.Fatalf("the paragraph after the note is read out of the wrong set: % x", body2)
	}
}

func TestDivisionParagraphsShareOneStatement(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<tt xmlns="http://www.w3.org/ns/ttml" xmlns:tts="http://www.w3.org/ns/ttml#styling">
 <head><layout>
  <region xml:id="upper" tts:origin="968px 116px" tts:extent="1452px 200px"/>
  <region xml:id="lower" tts:origin="968px 316px" tts:extent="1848px 200px"/>
 </layout></head>
 <body><div begin="00:00:01.000" end="00:00:03.000">
  <p region="upper"><span>うえ</span></p>
  <p region="lower"><span>した</span></p>
 </div></body>
</tt>`
	parsed, err := ParseTTML([]byte(doc), 3840, 2160)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Cues) != 1 {
		t.Fatalf("cues = %d, want the one division", len(parsed.Cues))
	}
	c := parsed.Cues[0]
	if len(c.Blocks) != 2 {
		t.Fatalf("blocks = %+v", c.Blocks)
	}
	if c.Blocks[0].Region.OriginY != 116 || c.Blocks[1].Region.OriginY != 316 {
		t.Fatalf("the paragraphs lost their regions: %+v", c.Blocks)
	}
	if !c.Begin.Set || c.Begin.Ticks != 90000 || c.End.Ticks != 270000 {
		t.Fatalf("timing = %+v %+v", c.Begin, c.End)
	}

	w := NewWriter(3840, 2160, nil)
	body := w.Cue(c)[5:]
	if got := bytes.Count(body, []byte{arib.CodeCS}); got != 1 {
		t.Errorf("the statement clears the screen %d times: % x", got, body)
	}
	for _, want := range []string{"242;29", "242;79"} {
		seq := append([]byte{arib.CodeCSI}, want...)
		seq = append(seq, 0x20, arib.CSISDP, arib.CodeAPS, 0x40, 0x40)
		if !bytes.Contains(body, seq) {
			t.Errorf("no display position %s followed by APS: % x", want, body)
		}
	}
	if !bytes.Contains(body, []byte{0x24, 0x26, 0x24, 0x28}) { // うえ
		t.Errorf("the first paragraph is missing: % x", body)
	}
	if !bytes.Contains(body, []byte{0x24, 0x37, 0x24, 0x3f}) { // した
		t.Errorf("the second paragraph is missing: % x", body)
	}
}

func TestBlockSetsItsCharacterSizeBeforeItsPosition(t *testing.T) {
	w := NewWriter(3840, 2160, nil)
	small := Style{FontSizeW: 72, FontSizeH: 72}
	normal := Style{FontSizeW: 144, FontSizeH: 144}
	body := w.Cue(Cue{Blocks: []Block{
		{
			HasRegion: true,
			Region: Region{
				OriginX: 1432, OriginY: 1676, HasOrigin: true,
				ExtentW: 320, ExtentH: 120, HasExtent: true,
			},
			Spans: []Span{{Text: "まくはり", Style: small}},
		},
		{
			HasRegion: true,
			Region: Region{
				OriginX: 1432, OriginY: 1796, HasOrigin: true,
				ExtentW: 1120, ExtentH: 240, HasExtent: true,
			},
			Spans: []Span{{Text: "幕張", Style: normal}},
		},
	}})[5:]

	ruby := []byte{arib.CodeCSI}
	ruby = append(ruby, "80;30"...)
	ruby = append(ruby, 0x20, arib.CSISDF, arib.CodeSSZ, arib.CodeCSI)
	ruby = append(ruby, "358;419"...)
	ruby = append(ruby, 0x20, arib.CSISDP, arib.CodeAPS, 0x40, 0x40)
	if !bytes.Contains(body, ruby) {
		t.Errorf("the ruby area does not set the small size before its position: % x", body)
	}
	base := []byte{arib.CodeCSI}
	base = append(base, "280;60"...)
	base = append(base, 0x20, arib.CSISDF, arib.CodeNSZ, arib.CodeCSI)
	base = append(base, "358;449"...)
	base = append(base, 0x20, arib.CSISDP, arib.CodeAPS, 0x40, 0x40)
	if !bytes.Contains(body, base) {
		t.Errorf("the base area does not set the normal size before its position: % x", body)
	}
	if got := bytes.Count(body, []byte{arib.CodeSSZ}); got != 1 {
		t.Errorf("the small size control appears %d times, want once: % x", got, body)
	}
}

func TestTTMLPreservesAnIdeographicSpaceSpan(t *testing.T) {
	doc := `<tt xmlns="http://www.w3.org/ns/ttml"><body><div><p><span>　</span></p></div></body></tt>`
	parsed, err := ParseTTML([]byte(doc), 3840, 2160)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Cues) != 1 || len(parsed.Cues[0].Blocks) != 1 ||
		len(parsed.Cues[0].Blocks[0].Spans) != 1 || parsed.Cues[0].Blocks[0].Spans[0].Text != "　" {
		t.Fatalf("ideographic space span was lost: %+v", parsed.Cues)
	}
}

func TestARIBExtensionNamespaceVariants(t *testing.T) {
	for _, ns := range []string{
		"http://www.arib.or.jp/ns/arib-ttml/v1_0",
		"http://www.arib.or.jp/ns/arib-tt",
	} {
		doc := `<?xml version="1.0"?>
<tt xmlns="http://www.w3.org/ns/ttml" xmlns:tts="http://www.w3.org/ns/ttml#styling"
    xmlns:a="` + ns + `"><head><styling>
 <style xml:id="s" tts:fontSize="144px 144px" tts:lineHeight="240px" a:letter-spacing="16px"/>
</styling></head><body><div><p><span style="s">あ</span></p></div></body></tt>`
		parsed, err := ParseTTML([]byte(doc), 3840, 2160)
		if err != nil {
			t.Fatalf("%s: %v", ns, err)
		}
		st := parsed.Cues[0].Blocks[0].Spans[0].Style
		if !st.HasLetterSpacing || st.LetterSpacing != 16 {
			t.Errorf("%s: letter spacing = %+v", ns, st)
		}
		if !st.HasLineHeight || st.LineHeight != 240 {
			t.Errorf("%s: line height = %+v", ns, st)
		}
	}
}

func TestCellComesFromTheDocument(t *testing.T) {
	ssm := func(v string) []byte {
		b := []byte{arib.CodeCSI}
		b = append(b, v...)
		return append(b, 0x20, arib.CSISSM)
	}
	one := func(v string, final byte) []byte {
		b := []byte{arib.CodeCSI}
		b = append(b, v...)
		return append(b, 0x20, final)
	}
	qvc := Style{
		FontSizeW: 120, FontSizeH: 120,
		LineHeight: 200, HasLineHeight: true,
		LetterSpacing: 12, HasLetterSpacing: true,
	}
	w := NewWriter(3840, 2160, nil)
	body := w.Cue(Cue{Blocks: []Block{{Spans: []Span{{Text: "あ", Style: qvc}}}}})[5:]
	for _, want := range [][]byte{ssm("30;30"), one("3", arib.CSISHS), one("20", arib.CSISVS)} {
		if !bytes.Contains(body, want) {
			t.Errorf("missing % x in % x", want, body)
		}
	}
	if !bytes.Contains(body, []byte{arib.CodeNSZ}) {
		t.Errorf("the span is not the normal size: % x", body)
	}
	for what := range w.Stats().Unsupported {
		if strings.Contains(what, "fontSize") || strings.Contains(what, "lineHeight") {
			t.Errorf("an exact layout was reported: %q", what)
		}
	}

	w2 := NewWriter(3840, 2160, nil)
	body2 := w2.Cue(Cue{Blocks: []Block{{Spans: []Span{{Text: "あ"}}}}})[5:]
	if !bytes.Contains(body2, ssm("36;36")) {
		t.Errorf("the default cell is not 36x36: % x", body2)
	}
	if bytes.Contains(body2, []byte{0x20, arib.CSISHS}) || bytes.Contains(body2, []byte{0x20, arib.CSISVS}) {
		t.Errorf("spacing was written for a document that stated none: % x", body2)
	}
}

func TestHalfSizesAreRelativeToTheCell(t *testing.T) {
	full := Style{FontSizeW: 144, FontSizeH: 144}
	middle := Style{FontSizeW: 72, FontSizeH: 144}
	small := Style{FontSizeW: 72, FontSizeH: 72}
	w := NewWriter(3840, 2160, nil)
	body := w.Cue(Cue{Blocks: []Block{{Spans: []Span{
		{Text: "あ", Style: middle},
		{Text: "い", Style: full},
		{Text: "う", Style: small},
	}}}})[5:]
	cell := append([]byte{arib.CodeCSI}, "36;36"...)
	cell = append(cell, 0x20, arib.CSISSM)
	if !bytes.Contains(body, cell) {
		t.Errorf("the cell is not the largest font size: % x", body)
	}
	for _, code := range []byte{arib.CodeMSZ, arib.CodeNSZ, arib.CodeSSZ} {
		if !bytes.Contains(body, []byte{code}) {
			t.Errorf("size %#02x missing: % x", code, body)
		}
	}
	for what := range w.Stats().Unsupported {
		if strings.Contains(what, "fontSize") {
			t.Errorf("an exact size was reported: %q", what)
		}
	}
}

func TestHintListIsCheckedAgainstTheSubsamples(t *testing.T) {
	hinted := func(sizes ...int) []byte {
		b := []byte{0x30, 1, 0, byte(len(sizes)), DataTypeTTML<<4 | 0x04}
		b = binary.BigEndian.AppendUint16(b, uint16(len(sampleTTML)))
		for _, n := range sizes {
			b = append(b, DataTypePNG<<4)
			b = binary.BigEndian.AppendUint16(b, uint16(n))
		}
		return append(b, sampleTTML...)
	}
	s := captionStream()
	s.Push(10, hinted(4))
	done, ok := s.Push(10, mfu(0x30, 1, 1, 1, DataTypePNG, []byte{0x89, 'P'}))
	if !ok {
		t.Fatal("the MPU never completed")
	}
	if len(done.Resources) != 1 {
		t.Fatalf("resources = %+v", done.Resources)
	}
	found := false
	for what := range s.Stats().Unsupported {
		if strings.Contains(what, "hint list announced 4 bytes") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the size difference was not reported: %v", s.Stats().Unsupported)
	}
}

func TestDefaultCLUTMatchesTheTable(t *testing.T) {
	if len(defaultCLUT) != 128 {
		t.Fatalf("the default CLUT has %d entries", len(defaultCLUT))
	}
	for index, want := range map[int]RGBA{
		0:   {0, 0, 0, 255},
		7:   {255, 255, 255, 255},
		8:   {0, 0, 0, 0},
		9:   {170, 0, 0, 255},
		15:  {170, 170, 170, 255},
		16:  {0, 0, 85, 255},
		30:  {85, 85, 85, 255},
		41:  {170, 0, 85, 255},
		64:  {255, 255, 170, 255},
		65:  {0, 0, 0, 128},
		72:  {255, 255, 255, 128},
		73:  {170, 0, 0, 128},
		101: {85, 255, 0, 128},
		119: {255, 85, 0, 128},
		127: {255, 255, 85, 128},
	} {
		if got := defaultCLUT[index]; got != want {
			t.Errorf("CLUT entry %d = %+v, want %+v", index, got, want)
		}
	}
	for i, c := range defaultCLUT {
		if c.A == 0 && i != transparentIndex {
			t.Errorf("entry %d is transparent as well as entry %d", i, transparentIndex)
		}
		if c.A != 0 && c.A != 128 && c.A != 255 {
			t.Errorf("entry %d has alpha %d", i, c.A)
		}
		for _, v := range []uint8{c.R, c.G, c.B} {
			if v != 0 && v != 85 && v != 170 && v != 255 {
				t.Errorf("entry %d = %+v has a component off the table's levels", i, c)
			}
		}
	}
}

func TestTranslucentColoursReachTheHalfOpacityEntries(t *testing.T) {
	for _, tc := range []struct {
		css            string
		palette, index byte
		exact          bool
	}{
		{"#00000080", 4, 1, true},
		{"#FFFFFFFF", 0, 7, true},
		{"#FFFFFF80", 4, 8, true},
		{"#00000000", 0, 8, true},
		{"#FFFFFF00", 0, 8, true},
		{"#000000FF", 0, 0, true},
		{"#AA0000FF", 0, 9, true},
		{"#00000090", 4, 1, false},
	} {
		palette, index, exact := nearestColour(tc.css)
		if palette != tc.palette || index != tc.index || exact != tc.exact {
			t.Errorf("%s -> palette %d index %d exact %v, want %d/%d/%v",
				tc.css, palette, index, exact, tc.palette, tc.index, tc.exact)
		}
	}
}

func TestSpanColoursSelectThePaletteAndTheEdge(t *testing.T) {
	w := NewWriter(3840, 2160, nil)
	unit := w.Cue(Cue{Blocks: []Block{{Spans: []Span{{
		Text: "あ",
		Style: Style{
			Color:      "#FFFFFFFF",
			Background: "#00000080",
			Outline:    "#000000FF",
			HasOutline: true,
		},
	}}}}})
	body := unit[5:]
	foreground := []byte{arib.CodeCOL, 0x20, 0x40, arib.CodeBKF + 7}
	if !bytes.Contains(body, foreground) {
		t.Errorf("the foreground is not palette 0 then WHF: % x", body)
	}
	background := []byte{arib.CodeCOL, 0x20, 0x44, arib.CodeCOL, 0x51}
	if !bytes.Contains(body, background) {
		t.Errorf("the background is not palette 4 index 1: % x", body)
	}
	edge := append([]byte{arib.CodeCSI, arib.ORNHemming, 0x3b}, "0000"...)
	edge = append(edge, 0x20, arib.CSIORN)
	if !bytes.Contains(body, edge) {
		t.Errorf("the character edge is not black hemming: % x", body)
	}
	if got := w.Stats().Colours; got != 3 {
		t.Errorf("colours counted = %d, want 3", got)
	}
	if got := w.Stats().ColourExact; got != 3 {
		t.Errorf("exact colours = %d, want 3; %v", got, w.Stats().Unsupported)
	}
}

func TestForegroundBeyondTheEightUsesCOL(t *testing.T) {
	w := NewWriter(3840, 2160, nil)
	body := w.Cue(Cue{Blocks: []Block{{Spans: []Span{
		{Text: "あ", Style: Style{Color: "#AA0000FF"}},
	}}}})[5:]
	if !bytes.Contains(body, []byte{arib.CodeCOL, 0x20, 0x40, arib.CodeCOL, 0x49}) {
		t.Errorf("half intensity red is not palette 0 then COL 04/9: % x", body)
	}
}

func TestOrnamentIsTurnedOffWhenTheEdgeEnds(t *testing.T) {
	w := NewWriter(3840, 2160, nil)
	unit := w.Cue(Cue{Blocks: []Block{{Spans: []Span{
		{Text: "あ", Style: Style{Outline: "#000000FF", HasOutline: true}},
		{Text: "い"},
	}}}})
	off := []byte{arib.CodeCSI, arib.ORNNone, 0x20, arib.CSIORN}
	if !bytes.Contains(unit[5:], off) {
		t.Fatalf("the edge was left on: % x", unit)
	}
}

func TestTextOutlineReadsTheOptionalColour(t *testing.T) {
	for _, tc := range []struct {
		value  string
		colour string
		has    bool
	}{
		{"#000000FF 4px 0px", "#000000FF", true},
		{"#000000FF", "#000000FF", true},
		{"4px", "", true},
		{"none", "", false},
		{"", "", false},
	} {
		p := &ttmlParser{seen: make(map[string]bool)}
		colour, has := p.textOutline(tc.value)
		if colour != tc.colour || has != tc.has {
			t.Errorf("textOutline(%q) = %q, %v; want %q, %v", tc.value, colour, has, tc.colour, tc.has)
		}
	}
	w := NewWriter(3840, 2160, nil)
	if got := w.outlineColour(Style{HasOutline: true, Color: "yellow"}); got != "yellow" {
		t.Errorf("an edge with no colour of its own = %q", got)
	}
}

func TestFontSizePairSelectsTheCharacterSize(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<tt xmlns="http://www.w3.org/ns/ttml" xmlns:tts="http://www.w3.org/ns/ttml#styling">
 <head><styling>
  <style xml:id="normal" tts:fontSize="144px 144px"/>
  <style xml:id="middle" tts:fontSize="72px 144px"/>
  <style xml:id="small" tts:fontSize="72px 72px"/>
 </styling></head>
 <body><div begin="0s" end="1s"><p>` +
		`<span style="middle">（</span><span style="normal">歓声</span><span style="small">A</span></p></div></body>
</tt>`
	parsed, err := ParseTTML([]byte(doc), 3840, 2160)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Cues) != 1 || len(parsed.Cues[0].Blocks) != 1 {
		t.Fatalf("cues = %+v", parsed.Cues)
	}
	spans := parsed.Cues[0].Blocks[0].Spans
	if len(spans) != 3 {
		t.Fatalf("spans = %+v", spans)
	}
	for i, want := range [][2]int{{72, 144}, {144, 144}, {72, 72}} {
		if got := [2]int{spans[i].Style.FontSizeW, spans[i].Style.FontSizeH}; got != want {
			t.Fatalf("span %d font size = %v, want %v", i, got, want)
		}
	}

	w := NewWriter(3840, 2160, nil)
	body := w.Cue(parsed.Cues[0])[5:]
	if got := []byte{arib.CodeMSZ, arib.CodeNSZ, arib.CodeSSZ}; !bytes.Contains(body, got[:1]) ||
		!bytes.Contains(body, got[1:2]) || !bytes.Contains(body, got[2:3]) {
		t.Fatalf("not every character size was written: % x", body)
	}
	if bytes.Index(body, []byte{arib.CodeMSZ}) > bytes.Index(body, []byte{arib.CodeNSZ}) {
		t.Fatalf("the sizes are in the wrong order: % x", body)
	}
	for what := range w.Stats().Unsupported {
		if strings.Contains(what, "fontSize") {
			t.Fatalf("an exact B24 size was reported as approximate: %q", what)
		}
	}
}

func TestStatementIsReadableByTheDecoder(t *testing.T) {
	w := NewWriter(1920, 1080, nil)
	unit := w.Cue(Cue{Blocks: []Block{{
		HasRegion: true,
		Region:    Region{HasOrigin: true, OriginX: 320, OriginY: 800, HasExtent: true, ExtentW: 1280, ExtentH: 200},
		Spans: []Span{
			{Text: "日本語の", Style: Style{Color: "#ffffff", HasOutline: true, Outline: "#000000"}},
			{Text: "字幕 ABC", NewLine: true, Style: Style{Color: "#ffff00"}},
		},
	}}})
	body := unit[5:]

	got := arib.DecodeString(body)
	if got.Text != "日本語の\n\r字幕 ABC" {
		t.Fatalf("decoded text = %q", got.Text)
	}
	if !got.Lossless() {
		t.Fatalf("undecodable cells in a statement this package wrote: %+v", got.Undecodable)
	}
	if len(got.Controls) == 0 || got.Controls[0].Code != arib.CodeCS {
		t.Fatalf("controls = %+v", got.Controls)
	}
	var finals []byte
	for _, c := range got.Controls {
		if c.Code == arib.CodeCSI && len(c.Params) > 0 {
			finals = append(finals, c.Params[len(c.Params)-1])
		}
	}
	for _, want := range []byte{arib.CSISWF, arib.CSISDF, arib.CSISSM, arib.CSISDP, arib.CSIORN} {
		if !bytes.Contains(finals, []byte{want}) {
			t.Errorf("no control sequence ended in %#02x; finals were % x", want, finals)
		}
	}
}

func TestWaitIsReadableByTheDecoder(t *testing.T) {
	got := arib.DecodeString(append(Wait(12), 0x46, 0x7c))
	if got.Text != "日" {
		t.Fatalf("text after the wait = %q, want the character that follows it", got.Text)
	}
	for _, c := range got.Controls {
		if c.Code != arib.CodeTIME || len(c.Params) != 2 || c.Params[0] != 0x20 {
			t.Errorf("control = %#02x % x, want a TIME with the 02/00 form", c.Code, c.Params)
		}
	}
}
