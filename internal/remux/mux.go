// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"container/heap"
	"fmt"
	"slices"

	"mmt2ts/internal/codec"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/pes"
	"mmt2ts/internal/siconv"
	"mmt2ts/internal/timeline"
)

type queued struct {
	stream        *stream
	dts           int64
	pts           int64
	streamID      byte
	payload       []byte
	randomAccess  bool
	discontinuity bool
	carryLoss     uint32
	noPTS         bool
	privateData   []byte
	stuffing      int
	seq           uint64
	audio         bool
}

type auQueue []queued

func (q auQueue) Len() int { return len(q) }
func (q auQueue) Less(i, j int) bool {
	if q[i].dts != q[j].dts {
		return q[i].dts < q[j].dts
	}
	return q[i].seq < q[j].seq
}
func (q auQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *auQueue) Push(x any)   { *q = append(*q, x.(queued)) }
func (q *auQueue) Pop() any     { old := *q; n := len(old); it := old[n-1]; *q = old[:n-1]; return it }

type muxer struct {
	w *mpegts.Writer
	c *converter

	queue  auQueue
	seq    uint64
	maxDTS int64

	origin     int64
	haveOrigin bool
	started    bool
	lastPSI    int64
	lastPCR    int64

	patVersion byte
	patBuilt   []mpegts.Program

	siTables    []siTable
	siGeneraton uint64
	siBuilt     bool

	patSections uint64
	pmtSections uint64
	pcrOnly     uint64
	lastOut     int64

	scratch []byte
	header  []byte
	spare   [][]byte
}

const maxSpare = 64

func (m *muxer) take(payload []byte) []byte {
	if n := len(m.spare); n > 0 {
		b := m.spare[n-1]
		m.spare = m.spare[:n-1]
		if cap(b) >= len(payload) {
			return append(b[:0], payload...)
		}
	}
	return append(make([]byte, 0, len(payload)), payload...)
}

func (m *muxer) release(b []byte) {
	if b == nil || len(m.spare) >= maxSpare {
		return
	}
	m.spare = append(m.spare, b)
}

type siTable struct {
	table siconv.Table
	last  int64
	sent  uint64
}

func newMuxer(w *mpegts.Writer, c *converter) *muxer {
	return &muxer{w: w, c: c, patVersion: 0x1f}
}

func (m *muxer) push(item queued) error {
	item.seq = m.seq
	m.seq++
	if item.dts > m.maxDTS {
		m.maxDTS = item.dts
	}
	heap.Push(&m.queue, item)
	return m.drain(false)
}

func (m *muxer) drain(final bool) error {
	for len(m.queue) > 0 {
		if !final && m.maxDTS-m.queue[0].dts <= m.c.opts.ReorderWindow {
			return nil
		}
		item := heap.Pop(&m.queue).(queued)
		if err := m.emit(item); err != nil {
			return err
		}
	}
	return nil
}

func (m *muxer) emit(item queued) error {
	if !m.haveOrigin {
		m.origin, m.haveOrigin = item.dts, true
		m.lastPCR = 0
		m.lastPSI = -m.c.opts.PSIInterval
	}
	muxTime := item.dts - m.origin
	if muxTime < 0 {
		m.c.report.ReorderDrops++
		muxTime = m.lastPCR
	}
	if err := m.advance(muxTime); err != nil {
		return err
	}
	if item.carryLoss > 0 {
		m.w.SkipContinuity(item.stream.pid, item.carryLoss)
		item.stream.stat.LostPacketsCarried += uint64(item.carryLoss)
	}
	af := mpegts.Adaptation{
		RandomAccess:  item.randomAccess,
		Discontinuity: item.discontinuity,
	}
	if item.discontinuity {
		item.stream.stat.Discontinuity++
	}
	if item.stream.pid == item.stream.pkg.pcrPID {
		af.HasPCR = true
		af.PCR = timeline.To27MHz(muxTime)
		m.lastPCR = muxTime
		item.stream.pkg.lastPCR = muxTime
	}
	owned := item.payload
	if item.audio {
		framed, err := m.frameAudio(item.stream, item.payload)
		if err != nil {
			item.stream.stat.AUsCodecError++
			m.release(owned)
			return nil
		}
		item.payload = framed
	}
	m.header = pes.AppendHeader(m.header[:0], pes.Packet{
		StreamID:    item.streamID,
		PTS:         item.pts - m.origin + m.c.opts.Preroll,
		DTS:         item.dts - m.origin + m.c.opts.Preroll,
		HasPTS:      !item.noPTS,
		HasDTS:      !item.noPTS && item.pts != item.dts,
		Aligned:     true,
		PrivateData: item.privateData,
		Stuffing:    item.stuffing,
		Payload:     item.payload,
	})
	item.stream.stat.AUsOut++
	item.stream.stat.BytesOut += uint64(len(m.header) + len(item.payload))
	if muxTime > m.lastOut {
		m.lastOut = muxTime
	}
	err := m.w.WriteUnitParts(item.stream.pid, m.header, item.payload, af)
	m.release(owned)
	return err
}

func (m *muxer) frameAudio(s *stream, ame []byte) ([]byte, error) {
	var framed []byte
	var err error
	if s.streamType == mpegts.StreamTypeLATMAAC {
		framed, err = codec.LOASFrame(m.scratch[:0], ame)
	} else {
		framed, err = s.adts.Convert(m.scratch[:0], ame)
	}
	if cap(framed) > cap(m.scratch) {
		m.scratch = framed
	}
	return framed, err
}

func (m *muxer) advance(muxTime int64) error {
	for muxTime-m.lastPCR >= m.c.opts.PCRInterval {
		m.lastPCR += m.c.opts.PCRInterval
		if m.lastPCR-m.lastPSI >= m.c.opts.PSIInterval {
			if err := m.writePSI(); err != nil {
				return err
			}
			m.lastPSI = m.lastPCR
		}
		if err := m.writeSI(m.lastPCR); err != nil {
			return err
		}
		if err := m.writeCarousel(m.lastPCR); err != nil {
			return err
		}
		if err := m.writePCRs(m.lastPCR); err != nil {
			return err
		}
	}
	if !m.started || m.c.pmtDirty || muxTime-m.lastPSI >= m.c.opts.PSIInterval {
		if err := m.writePSI(); err != nil {
			return err
		}
		m.lastPSI = muxTime
		m.started = true
	}
	if err := m.writeSI(muxTime); err != nil {
		return err
	}
	return m.writeCarousel(muxTime)
}

func (m *muxer) writeCarousel(muxTime int64) error {
	if m.c.pres == nil {
		return nil
	}
	return m.c.pres.rec.Emit(muxTime, func(pid uint16, section []byte) error {
		return m.w.WriteSection(pid, section)
	})
}

func (m *muxer) idle(muxTime int64) error {
	if m.haveOrigin {
		return nil
	}
	if !m.started || m.c.pmtDirty || muxTime-m.lastPSI >= m.c.opts.PSIInterval {
		if err := m.writePSI(); err != nil {
			return err
		}
		m.lastPSI, m.started = muxTime, true
	}
	if err := m.writeSI(muxTime); err != nil {
		return err
	}
	return m.writeCarousel(muxTime)
}

func (m *muxer) writePCRs(muxTime int64) error {
	for _, p := range m.c.packages {
		if p.pcrPID == 0 || p.pcrPID == mpegts.PIDNull {
			continue
		}
		if muxTime-p.lastPCR < m.c.opts.PCRInterval {
			continue
		}
		p.lastPCR = muxTime
		m.pcrOnly++
		if err := m.w.WriteAdaptationOnly(p.pcrPID, mpegts.Adaptation{HasPCR: true, PCR: timeline.To27MHz(muxTime)}); err != nil {
			return err
		}
	}
	return nil
}

func (m *muxer) writePSI() error {
	programs := make([]mpegts.Program, 0, len(m.c.packages))
	for _, p := range m.c.packages {
		if !p.pcrLocked {
			pid, locked := choosePCRPID(p.activeStreams())
			if pid != p.pcrPID {
				p.pcrPID, p.dirty = pid, true
			}
			p.pcrLocked = locked
		}
		programs = append(programs, mpegts.Program{Number: p.serviceID, PID: p.pmtPID})
	}
	if !slices.Equal(programs, m.patBuilt) {
		m.patVersion = (m.patVersion + 1) & 0x1f
		m.patBuilt = programs
	}
	m.c.pmtDirty, m.c.patDirty = false, false
	pat := mpegts.BuildPAT(m.c.opts.TSID, m.patVersion, programs, m.networkPID())
	if err := m.w.WriteSection(mpegts.PIDPAT, pat); err != nil {
		return err
	}
	m.patSections++

	for _, p := range m.c.packages {
		if err := m.writePMT(p); err != nil {
			return err
		}
	}
	return nil
}

func (m *muxer) writePMT(p *pkg) error {
	if p.dirty {
		p.pmtVersion = (p.pmtVersion + 1) & 0x1f
		p.dirty = false
		m.c.report.PMTVersions++
	}
	streams := p.activeStreams()
	es := make([]mpegts.ElementaryStream, 0, len(streams)+2)
	peers := p.hierarchyPeers()
	for _, s := range streams {
		es = append(es, mpegts.ElementaryStream{
			StreamType:  s.streamType,
			PID:         s.pid,
			Descriptors: s.esDescriptors(peers[s]),
		})
	}
	if m.c.pres != nil && p.index == 0 {
		es = append(es, m.c.pres.carouselStreams()...)
	}
	pmt := mpegts.BuildPMT(p.serviceID, p.pmtVersion, p.pcrPID, p.programDescriptors(), es)
	if err := m.w.WriteSection(p.pmtPID, pmt); err != nil {
		return err
	}
	m.pmtSections++
	return nil
}

func (m *muxer) networkPID() uint16 {
	for _, t := range m.siTables {
		if t.table.PID == mpegts.PIDNIT {
			return mpegts.PIDNIT
		}
	}
	return 0
}

func (m *muxer) refreshSI() {
	if m.siBuilt && m.c.si.Generation == m.siGeneraton {
		return
	}
	m.siGeneraton, m.siBuilt = m.c.si.Generation, true
	built := m.c.sigen.BuildStream()
	for _, p := range m.c.packages {
		for _, t := range p.sigen.BuildService() {
			if len(m.c.packages) > 1 {
				t.Name = fmt.Sprintf("%s %#04x", t.Name, p.serviceID)
			}
			built = append(built, t)
		}
	}
	next := make([]siTable, 0, len(built))
	for _, t := range built {
		entry := siTable{table: t, last: -t.Interval}
		for _, old := range m.siTables {
			if old.table.Name == t.Name {
				entry.last, entry.sent = old.last, old.sent
				break
			}
		}
		next = append(next, entry)
	}
	m.siTables = next
}

func (m *muxer) writeSI(muxTime int64) error {
	m.refreshSI()
	for i := range m.siTables {
		t := &m.siTables[i]
		if muxTime-t.last < t.table.Interval {
			continue
		}
		t.last = muxTime
		for _, section := range t.table.Sections {
			if err := m.w.WriteSection(t.table.PID, section); err != nil {
				return err
			}
			t.sent++
		}
	}
	return nil
}

func choosePCRPID(streams []*stream) (pid uint16, final bool) {
	for _, s := range streams {
		if s.kind == KindVideo {
			return s.pid, true
		}
	}
	for _, s := range streams {
		if s.kind == KindAudio {
			return s.pid, false
		}
	}
	if len(streams) > 0 {
		return streams[0].pid, false
	}
	return mpegts.PIDNull, false
}

func (m *muxer) fillReport(r *Report) {
	r.TSPackets = m.w.Packets
	r.TSBytes = m.w.Bytes
	r.PATSections = m.patSections
	r.PMTSections = m.pmtSections
	for _, t := range m.siTables {
		r.SITables = append(r.SITables, SITableStat{
			Name:     t.table.Name,
			PID:      t.table.PID,
			Sections: len(t.table.Sections),
			Sent:     t.sent,
		})
	}
	r.PCROnly = m.pcrOnly
	r.DurationOut90k = m.lastOut
	r.QueuePeak = cap(m.queue)
}
