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
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/tsdemux"
	"mmt2ts/internal/tsremux/carouselin"
	"mmt2ts/internal/tsremux/mmtwrite"
	"mmt2ts/internal/tsremux/siup"
	"mmt2ts/internal/tsremux/tlvwrite"
)

const packetSize = 188

type Report struct {
	InputProfile           string
	TSPackets              uint64
	SyncLosses             uint64
	Segments               int
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

type replayEvent struct {
	ntp      uint64
	order    uint64
	priority byte
	write    func() error
}

type replayFlow struct {
	ntp              uint64
	src, dst         tlvwrite.Endpoint
	srcPort, dstPort uint16
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
	var report Report

	d := tsdemux.New()
	carousels := carouselin.New()
	streamType := make(map[uint16]byte)
	dsmccPID := make(map[uint16]bool)
	pes := make(map[uint16][][]byte)
	generalPES := make(map[uint16][]tsdemux.PES)
	var generalSections []tsdemux.Section
	programs := make(map[uint16]tsdemux.PMT)
	var programOrder []uint16

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
		s.Data = append([]byte(nil), s.Data...)
		generalSections = append(generalSections, s)
		if dsmccPID[s.PID] {
			carousels.Push(s.PID, s.Data)
		}
	}
	d.Handlers.OnPES = func(p tsdemux.PES) {
		pes[p.PID] = append(pes[p.PID], p.Payload)
		p.Payload = append([]byte(nil), p.Payload...)
		generalPES[p.PID] = append(generalPES[p.PID], p)
	}

	br := bufio.NewReaderSize(r, 1<<20)
	buf := make([]byte, packetSize)
	for {
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
	d.Flush()
	for _, p := range carousels.Problems {
		report.problem("carousel: %s", p)
	}

	if carousels.Realtime.Bootstrap == nil && len(carousels.Realtime.Segments) == 0 {
		if report.TSPackets == 0 {
			return report, nil
		}
		report.Problems = nil
		report.InputProfile = "ARIB STD-B10 MPEG-2 TS"
		report.InputLoss = d.Lost
		ordered := make([]tsdemux.PMT, 0, len(programs))
		for _, number := range programOrder {
			ordered = append(ordered, programs[number])
		}
		return runGeneralTS(w, report, ordered, generalPES, generalSections, d.Scrambled)
	}
	report.InputProfile = "mmt2ts restoration carousel"

	mmtSeq := mmtwrite.NewSequencer()

	seqs := carousels.Realtime.SegmentSequences()
	var allRecords []preservation.Record
	rawApplicationPIDs := make(map[uint16]bool)
	var events []replayEvent
	var eventOrder uint64
	for _, seq := range seqs {
		records := carousels.Realtime.Segments[seq]
		allRecords = append(allRecords, records...)
		report.Segments++
		for _, rec := range records {
			if rec.Kind == preservation.RecordRawSignalling || rec.Kind == preservation.RecordCAData {
				report.SignallingRecords++
			} else if rec.Kind == preservation.RecordGenericTimedData {
				if assetType, ok := metaBytes(rec.Metadata, preservation.MetaAssetType, 4); ok && string(assetType) == "aapp" {
					if packetID, ok := metaU16(rec.Metadata, preservation.MetaPacketID); ok {
						rawApplicationPIDs[packetID] = true
					}
				}
			}
		}
	}

	src, dst, srcPort, dstPort := defaultEndpoint(allRecords)
	for _, source := range allRecords {
		rec := source
		switch rec.Kind {
		case preservation.RecordRawSignalling, preservation.RecordCAData:
			events = append(events, replayEvent{ntp: rec.SourceNTP, order: eventOrder, priority: 0,
				write: func() error {
					return replaySignallingRecordAt(w, rec, mmtSeq, src, dst, srcPort, dstPort)
				}})
			eventOrder++
		case preservation.RecordGenericTimedData:
			events = append(events, replayEvent{ntp: rec.SourceNTP, order: eventOrder, priority: 1,
				write: func() error {
					return replayGenericRecordAt(w, rec, mmtSeq, src, dst, srcPort, dstPort)
				}})
			eventOrder++
		}
	}
	flows := collectAVFlows(allRecords)
	objects := carouselin.ResolvedObjects(&carousels.Object)

	type captionBatch struct {
		ntp              uint64
		packetID         uint16
		src, dst         tlvwrite.Endpoint
		srcPort, dstPort uint16
		resources        []CaptionResource
		order            uint64
	}
	captionBatches := make(map[string]*captionBatch)
	for _, rec := range allRecords {
		if rec.Kind != preservation.RecordObjectActivation {
			continue
		}
		activation, err := preservation.ParseObjectActivation(rec.Payload)
		if err != nil || activation.Action == preservation.ObjectDeactivate {
			continue
		}
		resolved, ok := objects[activation.ObjectID]
		if !ok {
			report.problem("object activation: object %#016x is not in a committed snapshot", activation.ObjectID)
			continue
		}
		packetID, havePacketID := metaU16(rec.Metadata, preservation.MetaPacketID)
		flowSrc, flowDst := endpointOrDefault(rec.Metadata, src, dst)
		flowSP, flowDP := portsOrDefault(rec.Metadata, srcPort, dstPort)
		if subtitle, ok := metaBytes(rec.Metadata, preservation.MetaSubtitleID, 6); ok {
			if !havePacketID {
				report.problem("caption activation: object %#016x has no packet id", activation.ObjectID)
				continue
			}
			tag, _ := metaU16(rec.Metadata, preservation.MetaComponentTag)
			mpuSeq, _ := metaU32(rec.Metadata, preservation.MetaMPUSequence)
			header := metaVariable(rec.Metadata, preservation.MetaCaptionHeader)
			key := fmt.Sprintf("%d/%d/%d/%d/%d", rec.SourceNTP, packetID, tag, mpuSeq, subtitle[1])
			batch := captionBatches[key]
			if batch == nil {
				batch = &captionBatch{ntp: rec.SourceNTP, packetID: packetID,
					src: flowSrc, dst: flowDst, srcPort: flowSP, dstPort: flowDP, order: eventOrder}
				captionBatches[key] = batch
				eventOrder++
			}
			batch.resources = append(batch.resources, CaptionResource{
				ComponentTag: tag, MPUSequence: mpuSeq, Tag: subtitle[0], SequenceNumber: subtitle[1],
				Number: subtitle[2], DataType: subtitle[4], Data: resolved.Data, Header: header,
			})
			continue
		}
		itemID, isItem := metaU32(rec.Metadata, preservation.MetaItemID)
		if isItem && havePacketID && !rawApplicationPIDs[packetID] {
			mpuSequence, _ := metaU32(rec.Metadata, preservation.MetaMPUSequence)
			item := ApplicationItem{ID: itemID, MPUSequence: mpuSequence, Data: resolved.Data}
			events = append(events, replayEvent{ntp: rec.SourceNTP, order: eventOrder, priority: 2,
				write: func() error {
					return replayApplicationItemsAt(w, []ApplicationItem{item}, packetID, mmtSeq,
						flowSrc, flowDst, flowSP, flowDP, rec.SourceNTP)
				}})
			eventOrder++
		}
	}
	for _, batch := range captionBatches {
		b := batch
		events = append(events, replayEvent{ntp: b.ntp, order: b.order, priority: 2, write: func() error {
			resolver := func(uint16) (uint16, bool) { return b.packetID, true }
			return replayCaptionResourcesAt(w, b.resources, resolver, mmtSeq,
				b.src, b.dst, b.srcPort, b.dstPort, b.ntp)
		}})
	}

	avMap := append([]preservation.AVMapEntry(nil), carousels.Realtime.AVMap...)
	sort.Slice(avMap, func(i, j int) bool {
		a, b := avMap[i], avMap[j]
		if a.StartNTP != b.StartNTP {
			return a.StartNTP < b.StartNTP
		}
		if a.OutputPID != b.OutputPID {
			return a.OutputPID < b.OutputPID
		}
		return a.MPUSequence < b.MPUSequence
	})
	for _, e := range avMap {
		e := e
		aus := pes[e.OutputPID]
		start := e.FirstAUOrdinal
		end := start + uint64(e.AUCount)
		if start > uint64(len(aus)) {
			report.problem("AV map: output PID %#04x wants AUs %d-%d but only %d were demultiplexed", e.OutputPID, start, end, len(aus))
			continue
		}
		if end > uint64(len(aus)) {
			end = uint64(len(aus))
		}
		st, ok := streamType[e.OutputPID]
		if !ok {
			report.problem("AV map: output PID %#04x was never declared in the PMT", e.OutputPID)
			continue
		}
		segment := append([][]byte(nil), aus[start:end]...)
		flow := flowAt(flows[e.OutputPID], e.StartNTP, replayFlow{src: src, dst: dst, srcPort: srcPort, dstPort: dstPort})
		events = append(events, replayEvent{ntp: e.StartNTP, order: eventOrder, priority: 3, write: func() error {
			if err := ReplayAV(w, e, st, segment, mmtSeq, flow.src, flow.dst, flow.srcPort, flow.dstPort); err != nil {
				report.problem("AV map: output PID %#04x: %v", e.OutputPID, err)
				return nil
			}
			report.AVAccessUnits += len(segment)
			return nil
		}})
		eventOrder++
	}

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].ntp != events[j].ntp {
			return events[i].ntp < events[j].ntp
		}
		if events[i].priority != events[j].priority {
			return events[i].priority < events[j].priority
		}
		return events[i].order < events[j].order
	})
	for _, event := range events {
		if err := event.write(); err != nil {
			return report, err
		}
	}
	for _, batch := range captionBatches {
		report.CaptionUnits += len(batch.resources)
	}
	for _, rec := range allRecords {
		if rec.Kind == preservation.RecordObjectActivation {
			if _, ok := metaU32(rec.Metadata, preservation.MetaItemID); ok {
				report.ApplicationItems++
			}
		}
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

func findMPT(records []preservation.Record) (*signaling.MPT, bool) {
	reasm := signaling.NewReassembler()
	for _, rec := range records {
		if rec.Kind != preservation.RecordRawSignalling {
			continue
		}
		kind, ok := metaU8(rec.Metadata, preservation.MetaSignallingKind)
		if !ok || kind != preservation.SignallingPA {
			continue
		}
		packetID, _ := metaU16(rec.Metadata, preservation.MetaPacketID)
		for _, msg := range reasm.Push(packetID, mmtwrite.WrapSignalling(rec.Payload)) {
			for _, tab := range msg.Tables {
				if tab.MPT != nil {
					return tab.MPT, true
				}
			}
		}
	}
	return nil, false
}

func aappPacketID(mpt *signaling.MPT, have bool) (uint16, bool) {
	if !have {
		return 0, false
	}
	for _, a := range mpt.Assets {
		if a.Type == "aapp" {
			return a.LocalPacketID()
		}
	}
	return 0, false
}

func defaultEndpoint(records []preservation.Record) (src, dst tlvwrite.Endpoint, srcPort, dstPort uint16) {
	for _, rec := range records {
		if rec.Kind != preservation.RecordRawSignalling && rec.Kind != preservation.RecordCAData {
			continue
		}
		kind, ok := metaU8(rec.Metadata, preservation.MetaSignallingKind)
		if !ok || kind == preservation.SignallingNTP || kind == preservation.SignallingTLVSI {
			continue
		}
		if s := metaIP(rec.Metadata, preservation.MetaIPSource); s != nil {
			src = s
			dst = metaIP(rec.Metadata, preservation.MetaIPDestination)
			srcPort, _ = metaU16(rec.Metadata, preservation.MetaUDPSourcePort)
			dstPort, _ = metaU16(rec.Metadata, preservation.MetaUDPDestPort)
			return
		}
	}
	return
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

func collectAVFlows(records []preservation.Record) map[uint16][]replayFlow {
	out := make(map[uint16][]replayFlow)
	for _, rec := range records {
		if rec.Kind != preservation.RecordTimelineAnchor {
			continue
		}
		anchor, err := preservation.ParseTimelineAnchor(rec.Payload)
		if err != nil || anchor.ClockKind != preservation.ClockPresentation {
			continue
		}
		src, dst := endpointOrDefault(rec.Metadata, nil, nil)
		sp, dp := portsOrDefault(rec.Metadata, 0, 0)
		out[anchor.OutputPID] = append(out[anchor.OutputPID], replayFlow{
			ntp: anchor.SourceNTP, src: src, dst: dst, srcPort: sp, dstPort: dp,
		})
	}
	for pid := range out {
		sort.Slice(out[pid], func(i, j int) bool { return out[pid][i].ntp < out[pid][j].ntp })
	}
	return out
}

func flowAt(flows []replayFlow, ntp uint64, fallback replayFlow) replayFlow {
	out := fallback
	for _, flow := range flows {
		if flow.ntp > ntp {
			break
		}
		out = flow
	}
	if out.src == nil {
		out.src = fallback.src
	}
	if out.dst == nil {
		out.dst = fallback.dst
	}
	if out.srcPort == 0 {
		out.srcPort = fallback.srcPort
	}
	if out.dstPort == 0 {
		out.dstPort = fallback.dstPort
	}
	return out
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
