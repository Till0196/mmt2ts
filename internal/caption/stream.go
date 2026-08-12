// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package caption

import (
	"fmt"
	"sort"

	"mmt2ts/internal/arib"
)

type Resource struct {
	Number   byte
	DataType byte
	Size     int
	Header   []byte
	Data     []byte
}

type MPU struct {
	Sequence    uint32
	SubtitleTag byte
	SequenceNo  byte
	TTML        []byte
	TTMLHeader  []byte
	LastNumber  byte
	Resources   []Resource
	Missing     []byte
}

type Timing struct {
	MPUPresentation int64
	HasMPU          bool
	UTCOrigin       int64
	HasUTC          bool
	EventStart      int64
	HasEvent        bool
	ReferenceStart  int64
	HasReference    bool
}

type Output struct {
	PTS        int64
	HasPTS     bool
	Payload    []byte
	Management bool
}

type StreamStats struct {
	MPUs            uint64
	Documents       uint64
	ParseErrors     uint64
	IncompleteMPUs  uint64
	Statements      uint64
	ManagementSent  uint64
	Cues            uint64
	CuesWithoutTime uint64
	CuesWithoutEnd  uint64
	Resources       map[string]uint64
	ResourceBytes   uint64
	Unsupported     map[string]uint64
	Writer          WriterStats
	Rounded         uint64
}

func (s *StreamStats) resource(t byte, size int) {
	if s.Resources == nil {
		s.Resources = make(map[string]uint64)
	}
	s.Resources[DataTypeName(t)]++
	s.ResourceBytes += uint64(size)
}

func (s *StreamStats) note(what string) {
	if s.Unsupported == nil {
		s.Unsupported = make(map[string]uint64)
	}
	s.Unsupported[what]++
}

type Stream struct {
	Info              AdditionalInfo
	Writer            *Writer
	KeepResourceBytes bool

	current  *MPU
	pending  map[byte]*MFU
	lastSeq  uint32
	haveSeq  bool
	hints    []Hint
	stats    StreamStats
	drcs     *DRCS
	lastMgmt int64
	haveMgmt bool
}

const ManagementInterval = 45000

func NewStream(info AdditionalInfo, drcs *DRCS) *Stream {
	w, h, ok := info.DisplaySize()
	if !ok {
		w, h = 1920, 1080
	}
	return &Stream{
		Info:    info,
		Writer:  NewWriter(w, h, drcs),
		pending: make(map[byte]*MFU),
		drcs:    drcs,
	}
}

func (s *Stream) Stats() StreamStats {
	out := s.stats
	out.Writer = s.Writer.Stats()
	return out
}

func (s *Stream) Push(mpuSequence uint32, data []byte) (*MPU, bool) {
	m, err := ParseMFU(data)
	if err != nil {
		s.stats.ParseErrors++
		return nil, false
	}
	m.Data = append([]byte(nil), m.Data...)
	var done *MPU
	if s.haveSeq && mpuSequence != s.lastSeq {
		done = s.finish()
	}
	s.lastSeq, s.haveSeq = mpuSequence, true
	if m.Number == 0 {
		s.hints = m.Hints
		s.stats.MPUs++
	}
	s.pending[m.Number] = m
	if m.Number == m.LastNumber && done == nil {
		done = s.finish()
		s.haveSeq = false
	}
	return done, done != nil
}

func (s *Stream) Flush() (*MPU, bool) {
	m := s.finish()
	return m, m != nil
}

func (s *Stream) finish() *MPU {
	if len(s.pending) == 0 {
		return nil
	}
	out := &MPU{Sequence: s.lastSeq}
	numbers := make([]int, 0, len(s.pending))
	for n := range s.pending {
		numbers = append(numbers, int(n))
	}
	sort.Ints(numbers)
	last := byte(0)
	for _, n := range numbers {
		m := s.pending[byte(n)]
		out.SubtitleTag, out.SequenceNo = m.SubtitleTag, m.SequenceNumber
		if m.LastNumber > last {
			last = m.LastNumber
		}
		if m.Trailing > 0 {
			s.stats.note(fmt.Sprintf("%d bytes after the declared subsample size", m.Trailing))
		}
		if m.DataType == DataTypeTTML && n == 0 {
			out.TTML = m.Data
			out.TTMLHeader = append([]byte(nil), m.Header...)
		} else {
			r := Resource{Number: m.Number, DataType: m.DataType, Size: len(m.Data), Header: append([]byte(nil), m.Header...)}
			if s.KeepResourceBytes {
				r.Data = m.Data
			}
			out.Resources = append(out.Resources, r)
			s.stats.resource(m.DataType, len(m.Data))
		}
	}
	out.LastNumber = last
	for n := byte(0); n <= last; n++ {
		if _, ok := s.pending[n]; !ok {
			out.Missing = append(out.Missing, n)
		}
	}
	if len(out.Missing) > 0 {
		s.stats.IncompleteMPUs++
	}
	s.checkHints(out)
	s.pending = make(map[byte]*MFU)
	s.hints = nil
	return out
}

func (s *Stream) checkHints(out *MPU) {
	if len(s.hints) == 0 {
		return
	}
	if got := len(out.Resources); got != len(s.hints) {
		s.stats.note(fmt.Sprintf("the hint list announced %d resources and %d arrived",
			len(s.hints), got))
		return
	}
	for i, h := range s.hints {
		r := out.Resources[i]
		if h.DataType != r.DataType {
			s.stats.note(fmt.Sprintf("the hint list announced %s for subsample %d and %s arrived",
				DataTypeName(h.DataType), r.Number, DataTypeName(r.DataType)))
		}
		if int(h.Size) != r.Size {
			s.stats.note(fmt.Sprintf("the hint list announced %d bytes for subsample %d and %d arrived",
				h.Size, r.Number, r.Size))
		}
	}
}

func (s *Stream) Convert(mpu *MPU, t Timing) ([]Output, error) {
	if len(mpu.TTML) == 0 {
		if len(mpu.Resources) > 0 {
			s.stats.note("caption MPU with resources but no TTML document")
		}
		return nil, nil
	}
	if s.Info.Compression != 0 {
		s.stats.note("compressed TTML documents are not decoded")
		return nil, nil
	}
	w, h, _ := s.Info.DisplaySize()
	doc, err := ParseTTML(mpu.TTML, w, h)
	if err != nil {
		s.stats.ParseErrors++
		return nil, err
	}
	s.stats.Documents++
	s.stats.Rounded += uint64(doc.Rounded)
	for _, u := range doc.Unsupported {
		s.stats.note(u)
	}
	for _, e := range doc.External {
		s.stats.note(e)
	}

	times := make([]int64, len(doc.Cues))
	timed := make([]bool, len(doc.Cues))
	for i, cue := range doc.Cues {
		times[i], timed[i] = s.cuePTS(cue, t)
	}

	var out []Output
	if mgmt, ok := s.management(s.documentStart(times, timed, t)); ok {
		out = append(out, mgmt)
	}
	for i, cue := range doc.Cues {
		s.stats.Cues++
		pts, hasPTS := times[i], timed[i]
		if !hasPTS {
			s.stats.CuesWithoutTime++
		}
		units := s.Writer.Cue(cue)
		if defs := s.Writer.DRCS.Definitions(); len(defs) != 0 {
			units = append(defs, units...)
		}
		switch {
		case cue.End.Set && cue.Begin.Set && cue.End.Ticks > cue.Begin.Ticks:
			tenths := int((cue.End.Ticks - cue.Begin.Ticks) / (ticksPerSecond / 10))
			units = append(units, arib.DataUnit(arib.UnitStatementBody, append(Wait(tenths), arib.CodeCS))...)
		case len(cue.Blocks) > 0 && hasText(cue):
			s.stats.CuesWithoutEnd++
		}
		body := arib.Statement(s.tmd(), nil, units)
		group, ok := arib.DataGroup(s.groupID(false), 0, 0, 0, body)
		if !ok {
			s.stats.note("statement data group larger than 65535 bytes")
			continue
		}
		payload, ok := arib.PESPayload(s.dataIdentifier(), nil, group)
		if !ok {
			s.stats.note("caption PES header longer than the four-bit length allows")
			continue
		}
		s.stats.Statements++
		out = append(out, Output{PTS: pts, HasPTS: hasPTS && s.synchronised(), Payload: payload})
	}
	return out, nil
}

func hasText(c Cue) bool {
	for _, blk := range c.Blocks {
		for _, span := range blk.Spans {
			if span.Text != "" {
				return true
			}
		}
	}
	return false
}

func (s *Stream) cuePTS(c Cue, t Timing) (int64, bool) {
	if !c.Begin.Set {
		return t.MPUPresentation, t.HasMPU
	}
	offset := int64(c.Begin.Ticks)
	switch s.Info.TMD {
	case TMDMPUOnly, TMDNone:
		return t.MPUPresentation, t.HasMPU
	case TMDMPUTime:
		return t.MPUPresentation + offset, t.HasMPU
	case TMDUTC:
		if !t.HasUTC {
			s.stats.note("UTC time control needs a clock reference the input did not provide")
			return t.MPUPresentation, t.HasMPU
		}
		return t.UTCOrigin + offset, true
	case TMDEITStart:
		if !t.HasEvent {
			s.stats.note("MH-EIT based time control needs the event start time")
			return t.MPUPresentation, t.HasMPU
		}
		return t.EventStart + offset, true
	case TMDReference:
		if !t.HasReference {
			s.stats.note("reference start time control needs the reference time of the descriptor")
			return t.MPUPresentation, t.HasMPU
		}
		return t.ReferenceStart + offset, true
	default:
		s.stats.note("NPT time control is not converted")
		return t.MPUPresentation, t.HasMPU
	}
}

func (s *Stream) documentStart(times []int64, timed []bool, t Timing) (int64, bool) {
	start, have := int64(0), false
	for i, pts := range times {
		if timed[i] && (!have || pts < start) {
			start, have = pts, true
		}
	}
	if !have {
		return t.MPUPresentation, t.HasMPU
	}
	return start, true
}

func (s *Stream) management(at int64, haveAt bool) (Output, bool) {
	if s.haveMgmt && haveAt && at-s.lastMgmt < ManagementInterval {
		return Output{}, false
	}
	s.lastMgmt, s.haveMgmt = at, true
	entry := arib.LanguageEntry{
		Tag:      0,
		DMF:      s.Info.DMF,
		Language: s.Info.Language,
		Format:   0x08,
		TCS:      0,
	}
	body := arib.Management(0, nil, []arib.LanguageEntry{entry}, nil)
	group, ok := arib.DataGroup(s.groupID(true), 0, 0, 0, body)
	if !ok {
		return Output{}, false
	}
	payload, ok := arib.PESPayload(s.dataIdentifier(), nil, group)
	if !ok {
		return Output{}, false
	}
	s.stats.ManagementSent++
	return Output{PTS: at, HasPTS: haveAt && s.synchronised(), Payload: payload, Management: true}, true
}

func (s *Stream) synchronised() bool { return !s.Info.Superimposition() }

func (s *Stream) dataIdentifier() byte {
	if s.synchronised() {
		return arib.DataIdentifierSynchronised
	}
	return arib.DataIdentifierAsynchronous
}

func (s *Stream) groupID(management bool) byte {
	if management {
		return arib.GroupManagementA
	}
	return arib.GroupStatementA
}

func (s *Stream) tmd() byte { return 0 }
