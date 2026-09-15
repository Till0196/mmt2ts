// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package tsremux はTSを解析し、保存情報を合わせてMMT/TLVを再構成する。
package tsremux

import (
	"bufio"
	"fmt"
	"io"
	"sort"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/tsdemux"
	"mmt2ts/internal/tsremux/carouselin"
	"mmt2ts/internal/tsremux/siup"
	"mmt2ts/internal/tsremux/tlvwrite"
)

const packetSize = 188

type Report struct {
	InputProfile           string
	TSPackets              uint64
	SyncLosses             uint64
	Segments               int
	SegmentGaps            int
	Epochs                 int
	LateRecords            int
	SignallingRecords      int
	AVAccessUnits          int
	CaptionUnits           int
	ApplicationItems       int
	InputLoss              map[uint16]uint64
	InputLossCarried       uint64
	ServicesConverted      int
	ServicesWithoutStreams int
	ServicesScrambled      int
	CarouselLogos          int
	SIDescriptors          []siup.TagStat
	Problems               []string
}

func (r *Report) problem(format string, args ...any) {
	if len(r.Problems) < 500 {
		r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
	}
}

func WriteReport(w io.Writer, r Report) {
	if r.InputProfile != "" {
		fmt.Fprintf(w, "input profile: %s\n", r.InputProfile)
	}
	fmt.Fprintf(w, "TS packets: %d (sync losses %d)\n", r.TSPackets, r.SyncLosses)
	fmt.Fprintf(w, "segments replayed: %d, signalling records: %d\n", r.Segments, r.SignallingRecords)
	if r.SegmentGaps > 0 || r.LateRecords > 0 || r.Epochs > 0 {
		fmt.Fprintf(w, "segment sequence gaps: %d, clock epochs after the first: %d, records written after their window: %d\n",
			r.SegmentGaps, r.Epochs, r.LateRecords)
	}
	fmt.Fprintf(w, "AV access units: %d, caption units: %d, application items: %d\n",
		r.AVAccessUnits, r.CaptionUnits, r.ApplicationItems)
	if total := totalLoss(r.InputLoss); total > 0 {
		fmt.Fprintf(w, "input drops: %d TS packet(s) lost, %d carried into MMTP sequence numbers\n",
			total, r.InputLossCarried)
		for _, pid := range sortedPIDs(r.InputLoss) {
			fmt.Fprintf(w, "  PID %#04x: %d\n", pid, r.InputLoss[pid])
		}
	}
	if r.ServicesConverted > 0 || r.ServicesScrambled > 0 {
		fmt.Fprintf(w, "services: %d converted to MMT packages, %d scrambled, %d announced without elementary streams\n",
			r.ServicesConverted, r.ServicesScrambled, r.ServicesWithoutStreams)
	}
	if r.CarouselLogos > 0 {
		fmt.Fprintf(w, "logos: %d from a DSM-CC carousel converted to MH-CDT\n", r.CarouselLogos)
	}
	if len(r.SIDescriptors) > 0 {
		converted, dropped := 0, 0
		for _, d := range r.SIDescriptors {
			converted += d.Converted
			dropped += d.Dropped
		}
		fmt.Fprintf(w, "SI descriptors: %d converted to MH-SI, %d without an MH form\n", converted, dropped)
		for _, d := range r.SIDescriptors {
			if d.Dropped == 0 {
				fmt.Fprintf(w, "  TS %#02x -> MH %#04x: %d\n", d.TSTag, d.MHTag, d.Converted)
				continue
			}
			fmt.Fprintf(w, "  TS %#02x: %d dropped, nowhere to put it in MH-SI\n", d.TSTag, d.Dropped)
		}
	}
	fmt.Fprintf(w, "problems: %d\n", len(r.Problems))
	for _, p := range r.Problems {
		fmt.Fprintf(w, "  %s\n", p)
	}
}

func Run(r io.Reader, w io.Writer) (Report, error) {
	return RunWithOptions(r, w, Options{})
}

// 復元カルーセル付きの TS は読みながら書く。カルーセルのない TS は入力全体の
// PSI/SI から MH-SI を組むので、読み切ってから書く。
func RunWithOptions(r io.Reader, w io.Writer, opts Options) (Report, error) {
	var report Report

	d := tsdemux.New()
	carousels := carouselin.New()
	streamType := make(map[uint16]byte)
	dsmccPID := make(map[uint16]bool)
	aus := make(map[uint16]*auQueue)
	var generalSections []tsdemux.Section
	programs := make(map[uint16]tsdemux.PMT)
	var programOrder []uint16
	var replay *carouselReplay
	var replayErr error

	d.Handlers.OnPMT = func(p tsdemux.PMT) {
		if _, seen := programs[p.ProgramNumber]; !seen {
			programOrder = append(programOrder, p.ProgramNumber)
		}
		programs[p.ProgramNumber] = p
		for _, s := range p.Streams {
			streamType[s.PID] = s.StreamType
			if mpegts.CarriesDSMCCSections(s.StreamType) {
				dsmccPID[s.PID] = true
			}
		}
	}
	d.Handlers.OnSection = func(s tsdemux.Section) {
		if replay == nil {
			s.Data = append([]byte(nil), s.Data...)
			generalSections = append(generalSections, s)
		}
		if !dsmccPID[s.PID] || replayErr != nil {
			return
		}
		carousels.Push(s.PID, s.Data)
		if replay == nil {
			if carousels.Realtime.Bootstrap == nil && len(carousels.Realtime.Segments) == 0 {
				return
			}
			generalSections = nil
			replay = newCarouselReplay(w, &report, opts.Window, streamType, aus, &carousels.Object)
		}
		replay.drain(&carousels.Realtime)
		replayErr = replay.flush(false)
	}
	d.Handlers.OnPES = func(p tsdemux.PES) {
		q := aus[p.PID]
		if q == nil {
			q = &auQueue{}
			aus[p.PID] = q
		}
		q.push(p)
	}

	br := bufio.NewReaderSize(r, 1<<20)
	buf := make([]byte, packetSize)
	for replayErr == nil {
		if _, err := io.ReadFull(br, buf); err != nil {
			break
		}
		if buf[0] != mpegts.SyncByte {
			report.SyncLosses++
			if !resync(br, buf) {
				break
			}
		}
		d.Push(buf)
		report.TSPackets++
	}
	if replayErr != nil {
		return report, replayErr
	}
	d.Flush()

	if replay == nil {
		if report.TSPackets == 0 {
			return report, nil
		}
		report.InputProfile = "ARIB STD-B10 MPEG-2 TS"
		report.InputLoss = d.Lost
		ordered := make([]tsdemux.PMT, 0, len(programs))
		for _, number := range programOrder {
			ordered = append(ordered, programs[number])
		}
		byPID := make(map[uint16][]tsdemux.PES, len(aus))
		for pid, q := range aus {
			byPID[pid] = q.pes
		}
		return runGeneralTS(w, report, ordered, byPID, generalSections, d.Scrambled)
	}
	report.InputProfile = "mmt2ts restoration carousel"
	replay.drain(&carousels.Realtime)
	if err := replay.flush(true); err != nil {
		return report, err
	}
	for _, p := range carousels.Problems {
		report.problem("carousel: %s", p)
	}
	return report, nil
}

func resync(br *bufio.Reader, buf []byte) bool {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return false
		}
		if b != mpegts.SyncByte {
			continue
		}
		buf[0] = b
		if _, err := io.ReadFull(br, buf[1:]); err != nil {
			return false
		}
		return true
	}
}

func metaVariable(m preservation.Metadata, typ preservation.MetaType) []byte {
	for _, entry := range m {
		if entry.Type == typ {
			return append([]byte(nil), entry.Value...)
		}
	}
	return nil
}

func endpointOrDefault(meta preservation.Metadata, fallbackSrc, fallbackDst tlvwrite.Endpoint) (tlvwrite.Endpoint, tlvwrite.Endpoint) {
	src := metaIP(meta, preservation.MetaIPSource)
	dst := metaIP(meta, preservation.MetaIPDestination)
	if src == nil {
		src = fallbackSrc
	}
	if dst == nil {
		dst = fallbackDst
	}
	return src, dst
}

func portsOrDefault(meta preservation.Metadata, fallbackSrc, fallbackDst uint16) (uint16, uint16) {
	src, ok := metaU16(meta, preservation.MetaUDPSourcePort)
	if !ok {
		src = fallbackSrc
	}
	dst, ok := metaU16(meta, preservation.MetaUDPDestPort)
	if !ok {
		dst = fallbackDst
	}
	return src, dst
}

func totalLoss(m map[uint16]uint64) uint64 {
	var total uint64
	for _, n := range m {
		total += n
	}
	return total
}

func sortedPIDs(m map[uint16]uint64) []uint16 {
	out := make([]uint16, 0, len(m))
	for pid := range m {
		out = append(out, pid)
	}
	sort.Slice(out, func(i, j int) bool { return m[out[i]] > m[out[j]] })
	return out
}
