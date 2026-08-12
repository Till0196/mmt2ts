// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package tscheck はTSを生成側とは別の実装で読み返し、構造と時刻を検査する。
package tscheck

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

const packetSize = 188

type PIDStat struct {
	PID           uint16
	Packets       uint64
	Scrambled     uint64
	CCErrors      uint64
	Discontinuity uint64
	PCRPackets    uint64
	RandomAccess  uint64
	StreamType    byte
	ComponentTag  byte
	HasTag        bool

	PESUnits       uint64
	PESBytes       uint64
	PESLengthBad   uint64
	PESHeaderShort uint64
	StartCodeBad   uint64
	SyncWordBad    uint64
	NoAUD          uint64

	FirstPTS, LastPTS int64
	HavePTS           bool
	PTSBackwards      uint64
	PTSGaps           uint64
	MaxPTSGap         int64
	DTSBackwards      uint64
	MaxPTSDTSDelta    int64
}

type Report struct {
	Bytes       uint64
	Packets     uint64
	SyncLosses  uint64
	NullPackets uint64
	CRCErrors   uint64
	PATSections uint64
	PMTSections uint64
	SITSections uint64
	DITSections uint64

	DSMCCSections         uint64
	DIISections           uint64
	DDBSections           uint64
	ModulesComplete       uint64
	ModulesVerified       uint64
	ModuleKinds           map[byte]uint64
	BootstrapModules      uint64
	DirectoryVerified     uint64
	DirectoryUnadvertised uint64
	ManifestsCommitted    uint64
	ObjectsResolved       uint64
	DDBBeforeDII          uint64
	DDBNotInDII           uint64
	DDBStaleVersion       uint64
	DDBRepeats            uint64
	DSMCCErrors           uint64
	DSMCCProblems         []string
	Programs              map[uint16]uint16
	NetworkPID            uint16
	PMTVersions           map[byte]uint64
	PCRPID                uint16
	PCRCount              uint64
	PCRBackwards          uint64
	MaxPCRGap             int64
	PCRIntervalHi         uint64
	FirstPCR              int64
	LastPCR               int64
	HavePCR               bool
	Tables                map[byte]uint64
	PIDs                  map[uint16]*PIDStat
	AVSkew                map[uint16]int64
}

func (r *Report) Errors() uint64 {
	total := r.SyncLosses + r.CRCErrors + r.PCRBackwards + r.PCRIntervalHi + r.DSMCCErrors + uint64(len(r.ProfileErrors()))
	for _, p := range r.PIDs {
		total += p.CCErrors + p.PESLengthBad + p.StartCodeBad + p.SyncWordBad + p.PTSBackwards + p.DTSBackwards + p.PESHeaderShort
	}
	return total
}

type pidState struct {
	stat         *PIDStat
	cc           byte
	haveCC       bool
	pesOpen      bool
	pesDeclared  int
	pesSeen      int
	bodyLen      int
	loasDeclared int
	lastDTS      int64
	haveDTS      bool
	section      []byte
	sectionLen   int
}

type scanner struct {
	report    Report
	states    map[uint16]*pidState
	pmtPIDs   map[uint16]bool
	carousels map[uint16]*carousel
	lastPCR   int64
	havePCR   bool
}

func Scan(r io.Reader) (Report, error) {
	s := &scanner{
		report: Report{
			Programs:    make(map[uint16]uint16),
			PMTVersions: make(map[byte]uint64),
			PIDs:        make(map[uint16]*PIDStat),
			Tables:      make(map[byte]uint64),
			AVSkew:      make(map[uint16]int64),
		},
		states:  make(map[uint16]*pidState),
		pmtPIDs: make(map[uint16]bool),
	}
	br := bufio.NewReaderSize(r, 1<<20)
	buf := make([]byte, packetSize)
	for {
		if _, err := io.ReadFull(br, buf); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return s.report, err
		}
		if buf[0] != 0x47 {
			s.report.SyncLosses++
			if err := s.resync(br, buf); err != nil {
				break
			}
		}
		s.report.Packets++
		s.report.Bytes += packetSize
		s.packet(buf)
	}
	s.finish()
	return s.report, nil
}

func (s *scanner) resync(br *bufio.Reader, buf []byte) error {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		if b != 0x47 {
			continue
		}
		buf[0] = b
		if _, err := io.ReadFull(br, buf[1:]); err != nil {
			return err
		}
		return nil
	}
}

func (s *scanner) state(pid uint16) *pidState {
	st := s.states[pid]
	if st == nil {
		stat := &PIDStat{PID: pid}
		s.report.PIDs[pid] = stat
		st = &pidState{stat: stat}
		s.states[pid] = st
	}
	return st
}

func (s *scanner) packet(b []byte) {
	pid := binary.BigEndian.Uint16(b[1:3]) & 0x1fff
	if pid == 0x1fff {
		s.report.NullPackets++
		return
	}
	st := s.state(pid)
	st.stat.Packets++
	if b[3]&0xc0 != 0 {
		st.stat.Scrambled++
	}
	afc := (b[3] >> 4) & 0x03
	cc := b[3] & 0x0f
	hasPayload := afc&0x01 != 0
	if st.haveCC {
		want := st.cc
		if hasPayload {
			want = (st.cc + 1) & 0x0f
		}
		if cc != want {
			st.stat.CCErrors++
		}
	}
	st.cc, st.haveCC = cc, true

	payload := b[4:]
	if afc&0x02 != 0 {
		afLen := int(b[4])
		if afLen > 183 {
			return
		}
		if afLen > 0 {
			flags := b[5]
			if flags&0x80 != 0 {
				st.stat.Discontinuity++
			}
			if flags&0x40 != 0 {
				st.stat.RandomAccess++
			}
			if flags&0x10 != 0 && afLen >= 7 {
				s.pcr(pid, st, b[6:12])
			}
		}
		payload = b[5+afLen:]
	}
	if !hasPayload || len(payload) == 0 {
		return
	}
	start := b[1]&0x40 != 0
	switch {
	case pid == 0x0000 || s.pmtPIDs[pid] || isSIPID(pid) || s.isDSMCC(st):
		s.section(pid, st, start, payload)
	default:
		s.pes(st, start, payload)
	}
}

func isSIPID(pid uint16) bool {
	switch pid {
	case 0x0001, 0x0010, 0x0011, 0x0012, 0x0014, 0x001e, 0x001f, 0x0024, 0x0029:
		return true
	}
	return false
}

func (s *scanner) pcr(pid uint16, st *pidState, b []byte) {
	base := int64(b[0])<<25 | int64(b[1])<<17 | int64(b[2])<<9 | int64(b[3])<<1 | int64(b[4]>>7)
	ext := int64(b[4]&0x01)<<8 | int64(b[5])
	pcr := base*300 + ext
	st.stat.PCRPackets++
	s.report.PCRCount++
	s.report.PCRPID = pid
	if !s.report.HavePCR {
		s.report.FirstPCR, s.report.HavePCR = pcr, true
	}
	if s.havePCR {
		delta := pcr - s.lastPCR
		if delta < 0 {
			s.report.PCRBackwards++
		} else {
			if delta > s.report.MaxPCRGap {
				s.report.MaxPCRGap = delta
			}
			if delta > 100*27000 {
				s.report.PCRIntervalHi++
			}
		}
	}
	s.lastPCR, s.havePCR = pcr, true
	s.report.LastPCR = pcr
}

func (s *scanner) section(pid uint16, st *pidState, start bool, payload []byte) {
	if start {
		if len(payload) < 1 {
			return
		}
		pointer := int(payload[0])
		if 1+pointer > len(payload) {
			return
		}
		payload = payload[1+pointer:]
		st.section = st.section[:0]
		st.sectionLen = 0
		if len(payload) < 3 {
			return
		}
		st.sectionLen = int(binary.BigEndian.Uint16(payload[1:3])&0x0fff) + 3
	}
	if st.sectionLen == 0 {
		return
	}
	need := st.sectionLen - len(st.section)
	if need > len(payload) {
		need = len(payload)
	}
	st.section = append(st.section, payload[:need]...)
	if len(st.section) < st.sectionLen {
		return
	}
	s.table(pid, st.section)
	st.section = st.section[:0]
	st.sectionLen = 0
}

func (s *scanner) table(pid uint16, section []byte) {
	if len(section) < 4 {
		return
	}
	tableID := section[0]
	if tableID != 0x7e {
		if len(section) < 8 || crc32(section) != 0 {
			s.report.CRCErrors++
			return
		}
	}
	switch tableID {
	case 0x00:
		s.report.PATSections++
		s.pat(section)
	case 0x02:
		s.report.PMTSections++
		s.pmt(section)
	case 0x7f:
		s.report.SITSections++
	case 0x7e:
		s.report.DITSections++
	case dsmccTableDII, dsmccTableDDB:
		s.dsmcc(pid, section)
	}
	if s.report.Tables == nil {
		s.report.Tables = make(map[byte]uint64)
	}
	s.report.Tables[tableID]++
}

func (r *Report) ProfileErrors() []string {
	var out []string
	partial := r.Tables[0x7f] > 0 || r.Tables[0x7e] > 0
	full := []struct {
		id   byte
		name string
	}{
		{0x40, "NIT actual"}, {0x41, "NIT other"}, {0x42, "SDT actual"}, {0x46, "SDT other"},
		{0x4e, "EIT p/f"}, {0x70, "TDT"}, {0x73, "TOT"}, {0xc4, "BIT"}, {0xc8, "CDT"},
	}
	for id := byte(0x50); id <= 0x5f; id++ {
		full = append(full, struct {
			id   byte
			name string
		}{id, "EIT schedule"})
	}
	for _, t := range full {
		if r.Tables[t.id] == 0 {
			continue
		}
		if partial {
			out = append(out, t.name+" is not allowed in a partial transport stream")
		}
	}
	if !partial && r.Tables[0x7f] > 0 {
		out = append(out, "SIT is not allowed in a full transport stream")
	}
	return out
}

func (s *scanner) pat(b []byte) {
	body := b[8 : len(b)-4]
	for len(body) >= 4 {
		program := binary.BigEndian.Uint16(body[:2])
		pid := binary.BigEndian.Uint16(body[2:4]) & 0x1fff
		if program == 0 {
			s.report.NetworkPID = pid
		} else {
			s.report.Programs[program] = pid
			s.pmtPIDs[pid] = true
		}
		body = body[4:]
	}
}

func (s *scanner) pmt(b []byte) {
	if len(b) < 16 {
		return
	}
	s.report.PMTVersions[(b[5]>>1)&0x1f]++
	s.report.PCRPID = binary.BigEndian.Uint16(b[8:10]) & 0x1fff
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
		stat := s.state(pid).stat
		stat.StreamType = streamType
		for d := b[p : p+esLen]; len(d) >= 2 && len(d) >= 2+int(d[1]); d = d[2+int(d[1]):] {
			if d[0] == 0x52 && d[1] == 1 {
				stat.ComponentTag, stat.HasTag = d[2], true
			}
		}
		p += esLen
	}
}

func (s *scanner) pes(st *pidState, start bool, payload []byte) {
	if start {
		s.closePES(st)
		st.pesOpen = false
		if len(payload) < 9 {
			st.stat.PESHeaderShort++
			return
		}
		if payload[0] != 0 || payload[1] != 0 || payload[2] != 1 {
			st.stat.StartCodeBad++
			return
		}
		st.stat.PESUnits++
		declared := int(binary.BigEndian.Uint16(payload[4:6]))
		headerLen := int(payload[8])
		if len(payload) < 9+headerLen {
			st.stat.PESHeaderShort++
			return
		}
		flags := payload[7] >> 6
		var pts, dts int64
		havePTS, haveDTS := false, false
		if flags&0x02 != 0 && headerLen >= 5 {
			pts, havePTS = readTimestamp(payload[9:14]), true
		}
		if flags == 0x03 && headerLen >= 10 {
			dts, haveDTS = readTimestamp(payload[14:19]), true
		}
		if havePTS {
			s.observePTS(st, pts, dts, haveDTS)
		}
		body := payload[9+headerLen:]
		st.loasDeclared = s.checkPayloadStart(st.stat, body)
		st.pesOpen = true
		st.pesDeclared = declared
		st.pesSeen = len(payload) - 6
		st.bodyLen = len(body)
		st.stat.PESBytes += uint64(len(body))
		return
	}
	if st.pesOpen {
		st.pesSeen += len(payload)
		st.bodyLen += len(payload)
		st.stat.PESBytes += uint64(len(payload))
	}
}

func (s *scanner) closePES(st *pidState) {
	if !st.pesOpen {
		return
	}
	if st.pesDeclared > 0 && st.pesSeen != st.pesDeclared {
		st.stat.PESLengthBad++
	}
	if st.loasDeclared > 0 && st.loasDeclared != st.bodyLen {
		st.stat.SyncWordBad++
	}
	st.loasDeclared = 0
}

func (s *scanner) checkPayloadStart(stat *PIDStat, body []byte) int {
	switch stat.StreamType {
	case 0x24:
		if len(body) < 6 || body[0] != 0 || body[1] != 0 || body[2] != 0 || body[3] != 1 {
			stat.StartCodeBad++
			return 0
		}
		if (body[4]>>1)&0x3f != 35 {
			stat.NoAUD++
		}
	case 0x0f:
		if len(body) < 7 || body[0] != 0xff || body[1]&0xf6 != 0xf0 {
			stat.SyncWordBad++
			return 0
		}
		return int(body[3]&0x03)<<11 | int(body[4])<<3 | int(body[5]>>5)
	case 0x11:
		if len(body) < 3 || body[0] != 0x56 || body[1]&0xe0 != 0xe0 {
			stat.SyncWordBad++
			return 0
		}
		return int(body[1]&0x1f)<<8 | int(body[2]) + 3
	}
	return 0
}

func (s *scanner) observePTS(st *pidState, pts, dts int64, haveDTS bool) {
	stat := st.stat
	if !haveDTS {
		dts = pts
	}
	if !stat.HavePTS {
		stat.FirstPTS, stat.HavePTS = pts, true
	} else if gap := dts - st.lastDTS; st.haveDTS {
		switch {
		case gap < 0:
			stat.DTSBackwards++
		case gap > 45000:
			stat.PTSGaps++
			if gap > stat.MaxPTSGap {
				stat.MaxPTSGap = gap
			}
		}
	}
	st.lastDTS, st.haveDTS = dts, true
	if pts > stat.LastPTS {
		stat.LastPTS = pts
	}
	if delta := pts - dts; delta > stat.MaxPTSDTSDelta {
		stat.MaxPTSDTSDelta = delta
	}
	if dts > pts {
		stat.PTSBackwards++
	}
}

func (s *scanner) finish() {
	for _, st := range s.states {
		s.closePES(st)
	}
	var video *PIDStat
	for _, p := range s.report.PIDs {
		if p.StreamType == 0x24 && p.HavePTS {
			video = p
			break
		}
	}
	if video == nil {
		return
	}
	for pid, p := range s.report.PIDs {
		if (p.StreamType == 0x0f || p.StreamType == 0x11) && p.HavePTS {
			s.report.AVSkew[pid] = p.FirstPTS - video.FirstPTS
		}
	}
}

func readTimestamp(b []byte) int64 {
	return int64(b[0]&0x0e)<<29 |
		int64(b[1])<<22 |
		int64(b[2]&0xfe)<<14 |
		int64(b[3])<<7 |
		int64(b[4])>>1
}

func crc32(b []byte) uint32 {
	crc := uint32(0xffffffff)
	for _, v := range b {
		for i := 7; i >= 0; i-- {
			bit := (v >> uint(i)) & 1
			top := crc >> 31
			crc <<= 1
			if top^uint32(bit) != 0 {
				crc ^= 0x04c11db7
			}
		}
	}
	return crc
}

func WriteReport(w io.Writer, r Report) {
	fmt.Fprintf(w, "packets: %d (%d bytes), null %d, sync losses %d, CRC errors %d\n",
		r.Packets, r.Bytes, r.NullPackets, r.SyncLosses, r.CRCErrors)
	fmt.Fprintf(w, "sections: PAT %d, PMT %d, SIT %d, DIT %d\n", r.PATSections, r.PMTSections, r.SITSections, r.DITSections)
	writeDSMCCReport(w, r)
	if len(r.Tables) > 0 {
		ids := make([]int, 0, len(r.Tables))
		for id := range r.Tables {
			ids = append(ids, int(id))
		}
		sort.Ints(ids)
		fmt.Fprint(w, "table ids:")
		for _, id := range ids {
			fmt.Fprintf(w, " %#02x=%d", id, r.Tables[byte(id)])
		}
		fmt.Fprintln(w)
	}
	for _, e := range r.ProfileErrors() {
		fmt.Fprintf(w, "profile error: %s\n", e)
	}
	fmt.Fprintf(w, "programs: %v, network/SIT PID %#04x, PCR PID %#04x, PMT versions %v\n",
		r.Programs, r.NetworkPID, r.PCRPID, r.PMTVersions)
	if r.HavePCR {
		fmt.Fprintf(w, "PCR: %d values, span %.3f s, largest interval %.3f s, over 100 ms %d, backwards %d\n",
			r.PCRCount, float64(r.LastPCR-r.FirstPCR)/27000000, float64(r.MaxPCRGap)/27000000,
			r.PCRIntervalHi, r.PCRBackwards)
	}
	pids := make([]uint16, 0, len(r.PIDs))
	for pid := range r.PIDs {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	fmt.Fprintln(w, "\n   PID  type  tag   packets       PES     bytes  cc_err len_err frame_err pts_back pts_gaps  span(s)")
	for _, pid := range pids {
		p := r.PIDs[pid]
		tag := "-"
		if p.HasTag {
			tag = fmt.Sprintf("%#04x", p.ComponentTag)
		}
		span := 0.0
		if p.HavePTS {
			span = float64(p.LastPTS-p.FirstPTS) / 90000
		}
		fmt.Fprintf(w, "  %04x  %#04x %-5s %8d %9d %9d %7d %7d %9d %8d %8d %8.3f\n",
			pid, p.StreamType, tag, p.Packets, p.PESUnits, p.PESBytes, p.CCErrors,
			p.PESLengthBad, p.StartCodeBad+p.SyncWordBad+p.PESHeaderShort, p.PTSBackwards, p.PTSGaps, span)
	}
	for _, pid := range pids {
		p := r.PIDs[pid]
		if !p.HavePTS {
			continue
		}
		fmt.Fprintf(w, "  %04x first PTS %d, last PTS %d, largest PTS gap %.3f s, max PTS-DTS %.3f s, RAP %d, discontinuity %d\n",
			pid, p.FirstPTS, p.LastPTS, float64(p.MaxPTSGap)/90000, float64(p.MaxPTSDTSDelta)/90000,
			p.RandomAccess, p.Discontinuity)
		if p.NoAUD > 0 {
			fmt.Fprintf(w, "  %04x access units without an access unit delimiter: %d\n", pid, p.NoAUD)
		}
	}
	if len(r.AVSkew) > 0 {
		fmt.Fprintln(w, "\nfirst-PTS skew against the first video stream:")
		for pid, skew := range r.AVSkew {
			fmt.Fprintf(w, "  %04x %+.3f s\n", pid, float64(skew)/90000)
		}
	}
	fmt.Fprintf(w, "\nproblems: %d\n", r.Errors())
}
