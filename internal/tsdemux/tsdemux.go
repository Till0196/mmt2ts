// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package tsdemux はTSからPSIとPESをPIDごとに取り出す。
package tsdemux

import (
	"encoding/binary"

	"mmt2ts/internal/mpegts"
)

const packetSize = 188

type PES struct {
	PID           uint16
	StreamID      byte
	HasPTS        bool
	PTS           int64
	HasDTS        bool
	DTS           int64
	Payload       []byte
	RandomAccess  bool
	Discontinuity bool
	LostPackets   uint32
}

type Section struct {
	PID     uint16
	TableID byte
	Data    []byte
}

type Program struct {
	Number uint16
	PID    uint16
}

type PAT struct {
	Programs   []Program
	NetworkPID uint16
}

type StreamInfo struct {
	StreamType   byte
	PID          uint16
	ComponentTag byte
	HasTag       bool
	Descriptors  []byte
}

type PMT struct {
	ProgramNumber uint16
	PCRPID        uint16
	Streams       []StreamInfo
}

type pidState struct {
	streamType byte
	isSection  bool
	isPMT      bool

	section    []byte
	sectionLen int

	cc     byte
	haveCC bool
	lost   uint32

	pesOpen  bool
	pes      PES
	body     []byte
	declared int
}

type Demuxer struct {
	Handlers Handlers

	Lost map[uint16]uint64

	Scrambled map[uint16]uint64

	states  map[uint16]*pidState
	pmtPIDs map[uint16]bool
}

type Handlers struct {
	OnPAT     func(PAT)
	OnPMT     func(PMT)
	OnSection func(Section)
	OnPES     func(PES)
}

func New() *Demuxer {
	return &Demuxer{
		Lost:      make(map[uint16]uint64),
		Scrambled: make(map[uint16]uint64),
		states:    make(map[uint16]*pidState),
		pmtPIDs:   make(map[uint16]bool),
	}
}

func (st *pidState) continuity(cc byte, hasPayload, discontinuity bool) uint32 {
	previous, had := st.cc, st.haveCC
	st.cc, st.haveCC = cc, true
	if !had || discontinuity {
		return 0
	}
	if !hasPayload {
		return 0
	}
	if cc == previous {
		return 0
	}
	return uint32((cc - previous - 1) & 0x0f)
}

func (d *Demuxer) state(pid uint16) *pidState {
	st := d.states[pid]
	if st == nil {
		st = &pidState{isSection: mpegts.IsFixedSIPID(pid)}
		d.states[pid] = st
	}
	return st
}

func (d *Demuxer) Push(b []byte) {
	if len(b) != packetSize {
		return
	}
	pid := binary.BigEndian.Uint16(b[1:3]) & 0x1fff
	if pid == 0x1fff {
		return
	}
	st := d.state(pid)
	afc := (b[3] >> 4) & 0x03
	hasPayload := afc&0x01 != 0
	payload := b[4:]
	discontinuity, randomAccess := false, false
	if afc&0x02 != 0 {
		afLen := int(b[4])
		if afLen > 183 {
			return
		}
		if afLen > 0 {
			flags := b[5]
			discontinuity = flags&0x80 != 0
			randomAccess = flags&0x40 != 0
		}
		payload = b[5+afLen:]
	}
	lost := st.continuity(b[3]&0x0f, hasPayload, discontinuity)
	if lost > 0 {
		st.lost += lost
		d.Lost[pid] += uint64(lost)
	}
	if !hasPayload || len(payload) == 0 {
		return
	}
	if b[3]&0xc0 != 0 {
		d.Scrambled[pid]++
		return
	}
	start := b[1]&0x40 != 0

	if st.isSection {
		d.section(pid, st, start, payload)
		return
	}
	d.pes(pid, st, start, payload, discontinuity, randomAccess)
}

func (d *Demuxer) Flush() {
	for pid, st := range d.states {
		d.closePES(pid, st)
	}
}

func (d *Demuxer) section(pid uint16, st *pidState, start bool, payload []byte) {
	if !start {
		d.sectionContinue(pid, st, payload)
		return
	}
	if len(payload) < 1 {
		return
	}
	pointer := int(payload[0])
	if 1+pointer > len(payload) {
		return
	}
	d.sectionContinue(pid, st, payload[1:1+pointer])
	st.section = st.section[:0]
	st.sectionLen = 0
	for payload = payload[1+pointer:]; len(payload) >= 3; payload = payload[st.sectionLen:] {
		if payload[0] == 0xff {
			st.sectionLen = 0
			return
		}
		st.sectionLen = int(binary.BigEndian.Uint16(payload[1:3])&0x0fff) + 3
		if st.sectionLen > len(payload) {
			st.section = append(st.section[:0], payload...)
			return
		}
		sec := append(st.section[:0], payload[:st.sectionLen]...)
		st.section = nil
		d.table(pid, st, sec)
	}
	st.sectionLen = 0
}

func (d *Demuxer) sectionContinue(pid uint16, st *pidState, payload []byte) {
	if st.sectionLen == 0 || len(payload) == 0 {
		return
	}
	need := min(st.sectionLen-len(st.section), len(payload))
	st.section = append(st.section, payload[:need]...)
	if len(st.section) < st.sectionLen {
		return
	}
	sec := st.section
	st.section = nil
	st.sectionLen = 0
	d.table(pid, st, sec)
}

func (d *Demuxer) table(pid uint16, st *pidState, section []byte) {
	if len(section) < 8+4 {
		return
	}
	if mpegts.CRC32(section) != 0 {
		return
	}
	tableID := section[0]
	switch {
	case pid == 0 && tableID == mpegts.TableIDPAT:
		d.pat(section)
	case st.isPMT && tableID == mpegts.TableIDPMT:
		d.pmt(section)
	default:
		if d.Handlers.OnSection != nil {
			d.Handlers.OnSection(Section{PID: pid, TableID: tableID, Data: section})
		}
	}
}

func (d *Demuxer) pat(b []byte) {
	body := b[8 : len(b)-4]
	pat := PAT{}
	for len(body) >= 4 {
		program := binary.BigEndian.Uint16(body[:2])
		pid := binary.BigEndian.Uint16(body[2:4]) & 0x1fff
		if program == 0 {
			pat.NetworkPID = pid
		} else {
			pat.Programs = append(pat.Programs, Program{Number: program, PID: pid})
			if !d.pmtPIDs[pid] {
				d.pmtPIDs[pid] = true
				d.state(pid).isSection = true
				d.state(pid).isPMT = true
			}
		}
		body = body[4:]
	}
	if d.Handlers.OnPAT != nil {
		d.Handlers.OnPAT(pat)
	}
}

func (d *Demuxer) pmt(b []byte) {
	if len(b) < 16 {
		return
	}
	pmt := PMT{
		ProgramNumber: binary.BigEndian.Uint16(b[3:5]),
		PCRPID:        binary.BigEndian.Uint16(b[8:10]) & 0x1fff,
	}
	infoLen := int(binary.BigEndian.Uint16(b[10:12]) & 0x0fff)
	p := 12 + infoLen
	end := len(b) - 4
	for p+5 <= end {
		streamType := b[p]
		pid := binary.BigEndian.Uint16(b[p+1:p+3]) & 0x1fff
		esLen := int(binary.BigEndian.Uint16(b[p+3:p+5]) & 0x0fff)
		p += 5
		if p+esLen > end {
			return
		}
		desc := b[p : p+esLen]
		si := StreamInfo{StreamType: streamType, PID: pid, Descriptors: desc}
		for dd := desc; len(dd) >= 2 && len(dd) >= 2+int(dd[1]); dd = dd[2+int(dd[1]):] {
			if dd[0] == mpegts.DescStreamIdentifier && dd[1] == 1 {
				si.ComponentTag, si.HasTag = dd[2], true
			}
		}
		pmt.Streams = append(pmt.Streams, si)
		st := d.state(pid)
		st.streamType = streamType
		if mpegts.CarriesDSMCCSections(streamType) {
			st.isSection = true
		}
		p += esLen
	}
	if d.Handlers.OnPMT != nil {
		d.Handlers.OnPMT(pmt)
	}
}

func (d *Demuxer) pes(pid uint16, st *pidState, start bool, payload []byte, discontinuity, randomAccess bool) {
	if start {
		d.closePES(pid, st)
		if len(payload) < 9 || payload[0] != 0 || payload[1] != 0 || payload[2] != 1 {
			return
		}
		flags := payload[7] >> 6
		headerLen := int(payload[8])
		if len(payload) < 9+headerLen {
			return
		}
		pes := PES{PID: pid, StreamID: payload[3], Discontinuity: discontinuity, RandomAccess: randomAccess,
			LostPackets: st.lost}
		st.lost = 0
		if flags&0x02 != 0 && headerLen >= 5 {
			pes.PTS, pes.HasPTS = readTimestamp(payload[9:14]), true
		}
		if flags == 0x03 && headerLen >= 10 {
			pes.DTS, pes.HasDTS = readTimestamp(payload[14:19]), true
		}
		st.pesOpen = true
		st.pes = pes
		st.body = append(st.body[:0], payload[9+headerLen:]...)
		return
	}
	if st.pesOpen {
		st.body = append(st.body, payload...)
	}
}

func (d *Demuxer) closePES(pid uint16, st *pidState) {
	if !st.pesOpen {
		return
	}
	st.pesOpen = false
	pes := st.pes
	pes.Payload = st.body
	st.body = nil
	if d.Handlers.OnPES != nil {
		d.Handlers.OnPES(pes)
	}
}

func readTimestamp(b []byte) int64 {
	return int64(b[0]&0x0e)<<29 |
		int64(b[1])<<22 |
		int64(b[2]&0xfe)<<14 |
		int64(b[3])<<7 |
		int64(b[4])>>1
}
