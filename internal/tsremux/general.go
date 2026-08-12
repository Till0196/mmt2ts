// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"mmt2ts/internal/arib"
	"mmt2ts/internal/logocarousel"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/si"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/tsdemux"
	"mmt2ts/internal/tsremux/codecrev"
	"mmt2ts/internal/tsremux/mmtwrite"
	"mmt2ts/internal/tsremux/siup"
	"mmt2ts/internal/tsremux/tlvwrite"
)

const generalNTPBase = uint64(0xed003780) << 32

type generalFlow struct {
	cid              uint16
	src, dst         tlvwrite.Endpoint
	srcPort, dstPort uint16
}

func (f generalFlow) write(w io.Writer, packet []byte) error {
	return tlvwrite.WriteUDPContext(w, f.cid, f.src, f.dst, f.srcPort, f.dstPort, packet)
}

type generalAsset struct {
	stream   tsdemux.StreamInfo
	packetID uint16
	tag      uint16
	typeName string
	pes      []tsdemux.PES
	mpus     []generalMPU
}

type generalMPU struct {
	sequence uint32
	pes      []tsdemux.PES
	startPTS int64
	startNTP uint64
	rap      bool
}

type generalEvent struct {
	ntp      uint64
	priority byte
	order    int
	write    func() error
}

type generalService struct {
	number uint16
	assets []generalAsset
	flow   generalFlow
	mptPID uint16
	eit    [][]byte
	seq    *mmtwrite.Sequencer
}

func generalFlowFor(n int) generalFlow {
	src := tlvwrite.Endpoint{0x24, 0x01, 0xdb, 0xc0, 0x10, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := tlvwrite.Endpoint{0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa0, 0, 0x10 + byte(n), 0}
	return generalFlow{cid: uint16(n + 1), src: src, dst: dst, srcPort: 50000, dstPort: 51216}
}

func runGeneralTS(w io.Writer, report Report, programs []tsdemux.PMT, byPID map[uint16][]tsdemux.PES,
	sections []tsdemux.Section, scrambled map[uint16]uint64) (Report, error) {
	if len(programs) == 0 {
		return report, errors.New("ts2mmt: no PMT was found in the ordinary MPEG-2 TS")
	}
	sort.SliceStable(programs, func(i, j int) bool { return programs[i].ProgramNumber < programs[j].ProgramNumber })
	var services []*generalService
	empty, enciphered := 0, 0
	for _, pmt := range programs {
		if pmt.ProgramNumber == 0 {
			continue
		}
		assets := generalAssets(pmt, byPID)
		if len(assets) == 0 {
			if generalScrambled(pmt, scrambled) {
				enciphered++
			} else {
				empty++
			}
			continue
		}
		n := len(services)
		services = append(services, &generalService{
			number: pmt.ProgramNumber, assets: assets,
			flow: generalFlowFor(n), mptPID: 0xff01 + uint16(n),
			seq: mmtwrite.NewSequencer(),
		})
	}
	report.ServicesConverted = len(services)
	report.ServicesWithoutStreams = empty
	report.ServicesScrambled = enciphered
	if len(services) == 0 {
		return report, errors.New("ts2mmt: ordinary TS has no supported clear HEVC/AAC PES")
	}

	ntpBase := generalNTPBaseFromSections(sections)
	toNTP := func(firstPTS, pts int64) uint64 {
		delta := pts - firstPTS
		if delta < 0 {
			delta = 0
		}
		return ntpBase + uint64(delta)*(uint64(1)<<32)/90000
	}
	kept := services[:0]
	for _, s := range services {
		firstPTS, ok := earliestPTS(s.assets)
		if !ok {
			continue
		}
		for i := range s.assets {
			s.assets[i].pes = validGeneralPES(s.assets[i], &report)
			s.assets[i].mpus = groupGeneralMPUs(s.assets[i], func(pts int64) uint64 {
				return toNTP(firstPTS, pts)
			})
		}
		kept = append(kept, s)
	}
	services = kept
	if len(services) == 0 {
		return report, errors.New("ts2mmt: supported streams have no PTS")
	}
	report.ServicesConverted = len(services)

	conv := siup.New()
	networkID := generalNetworkID(services[0].number, sections)
	logoCDT, logoPointers, logoCount := buildGeneralLogos(sections, networkID, conv)
	report.CarouselLogos = logoCount
	nit := buildGeneralNIT(services[0].number, sections, conv)
	amt := buildGeneralAMT(networkID, services)
	sdt := buildGeneralMHSDT(sections, logoPointers, conv)
	schedule := buildGeneralMHEITSchedule(services, sections, conv)
	cdt := append(buildGeneralMHCDT(sections, conv), logoCDT...)
	bit := buildGeneralMHBIT(sections, conv)
	plt := buildGeneralPLT(services)
	for _, s := range services {
		s.eit = buildGeneralMHEIT(s.number, sections, ntpBase, conv)
	}

	writeStreamSI := func(ntp uint64, second uint64) error {
		if err := writeGeneralTLVSI(w, nit, amt); err != nil {
			return err
		}
		if err := writeGeneralNTP(w, ntp, services[0].flow.src); err != nil {
			return err
		}
		for _, s := range services {
			if err := writeGeneralMHTOT(w, ntp, s.seq, s.flow); err != nil {
				return err
			}
			if err := writeGeneralMHSDT(w, sdt, ntp, s.seq, s.flow); err != nil {
				return err
			}
			if second%10 != 0 {
				continue
			}
			if err := writeGeneralMHEITSchedule(w, schedule, ntp, s.seq, s.flow); err != nil {
				return err
			}
			if err := writeGeneralMHCDT(w, cdt, ntp, s.seq, s.flow); err != nil {
				return err
			}
			if err := writeGeneralMHBIT(w, bit, ntp, s.seq, s.flow); err != nil {
				return err
			}
		}
		return nil
	}
	if err := writeStreamSI(ntpBase, 0); err != nil {
		return report, err
	}
	for _, s := range services {
		if err := writeGeneralPA(w, plt, 0x0000, ntpBase, s.seq, s.flow); err != nil {
			return report, err
		}
	}
	for range 10 {
		for _, s := range services {
			if err := writeGeneralMHEIT(w, s.eit, ntpBase, s.seq, s.flow); err != nil {
				return report, err
			}
		}
	}

	var events []generalEvent
	order := 0
	lastMediaNTP := ntpBase
	for _, s := range services {
		for _, asset := range s.assets {
			for _, mpu := range asset.mpus {
				if mpu.startNTP > lastMediaNTP {
					lastMediaNTP = mpu.startNTP
				}
			}
		}
	}
	const signalInterval = (uint64(1) << 32) / 10
	for ntp := ntpBase; ntp <= lastMediaNTP+signalInterval; ntp += signalInterval {
		ntp := ntp
		for _, s := range services {
			s := s
			message, err := buildGeneralMPT(s.number, 0, s.assets, ntp)
			if err != nil {
				return report, err
			}
			events = append(events, generalEvent{ntp: ntp, priority: 0, order: order, write: func() error {
				return writeGeneralPA(w, plt, 0x0000, ntp, s.seq, s.flow)
			}})
			order++
			events = append(events, generalEvent{ntp: ntp, priority: 1, order: order, write: func() error {
				return writeGeneralPA(w, message, s.mptPID, ntp, s.seq, s.flow)
			}})
			order++
			events = append(events, generalEvent{ntp: ntp, priority: 2, order: order, write: func() error {
				return writeGeneralMHEIT(w, s.eit, ntp, s.seq, s.flow)
			}})
			order++
		}
	}
	for _, s := range services {
		s := s
		for _, asset := range s.assets {
			if asset.stream.StreamType != mpegts.StreamTypeHEVC || len(asset.mpus) == 0 {
				continue
			}
			admission := generalHEVCAdmissionNAL(asset.pes)
			if admission == nil {
				break
			}
			entry := preservation.AVMapEntry{PacketID: asset.packetID, MPUSequence: asset.mpus[0].sequence,
				StartNTP: asset.mpus[0].startNTP}
			events = append(events, generalEvent{ntp: entry.StartNTP, priority: 3, order: order, write: func() error {
				return writeHEVCAdmission(w, entry, admission, s.seq, s.flow)
			}})
			order++
			break
		}
	}
	for _, s := range services {
		s := s
		for _, asset := range s.assets {
			asset := asset
			for _, mpu := range asset.mpus {
				mpu := mpu
				entry := preservation.AVMapEntry{PacketID: asset.packetID, MPUSequence: mpu.sequence, StartNTP: mpu.startNTP}
				aus := make([][]byte, 0, len(mpu.pes))
				lost := uint32(0)
				for _, p := range mpu.pes {
					aus = append(aus, p.Payload)
					lost += p.LostPackets
				}
				events = append(events, generalEvent{ntp: entry.StartNTP, priority: 4, order: order, write: func() error {
					if lost > 0 {
						s.seq.Skip(asset.packetID, lost)
						report.InputLossCarried += uint64(lost)
					}
					if err := replayAV(w, entry, asset.stream.StreamType, aus, s.seq, s.flow, mpu.rap); err != nil {
						return err
					}
					report.AVAccessUnits += len(aus)
					return nil
				}})
				order++
			}
		}
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
	lastSecond := uint64(0)
	for _, event := range events {
		second := (event.ntp - ntpBase) >> 32
		if second > lastSecond {
			if err := writeStreamSI(event.ntp, second); err != nil {
				return report, err
			}
			lastSecond = second
		}
		if err := event.write(); err != nil {
			return report, err
		}
	}
	report.SIDescriptors = conv.Stats()
	return report, nil
}

func splitADTSAccessUnits(p tsdemux.PES) []tsdemux.PES {
	frames, rateIndex := codecrev.ADTSFrames(p.Payload)
	if len(frames) <= 1 {
		return []tsdemux.PES{p}
	}
	rate := codecrev.ADTSSampleRate(rateIndex)
	if rate == 0 {
		return []tsdemux.PES{p}
	}
	step := int64(1024) * 90000 / int64(rate)
	out := make([]tsdemux.PES, 0, len(frames))
	for i, frame := range frames {
		unit := p
		unit.Payload = frame
		unit.PTS = p.PTS + int64(i)*step
		unit.DTS = unit.PTS
		unit.HasDTS = false
		if i > 0 {
			unit.LostPackets = 0
			unit.Discontinuity = false
		}
		out = append(out, unit)
	}
	return out
}

func generalScrambled(pmt tsdemux.PMT, scrambled map[uint16]uint64) bool {
	for _, s := range pmt.Streams {
		switch s.StreamType {
		case mpegts.StreamTypeHEVC, mpegts.StreamTypeADTSAAC, mpegts.StreamTypeLATMAAC:
			if scrambled[s.PID] > 0 {
				return true
			}
		}
	}
	return false
}

func generalAssets(pmt tsdemux.PMT, byPID map[uint16][]tsdemux.PES) []generalAsset {
	var assets []generalAsset
	for _, s := range pmt.Streams {
		var typ string
		var packetID uint16
		switch s.StreamType {
		case mpegts.StreamTypeHEVC:
			typ, packetID = "hev1", 0xf100
		case mpegts.StreamTypeADTSAAC, mpegts.StreamTypeLATMAAC:
			typ, packetID = "mp4a", 0xf110
		default:
			continue
		}
		if len(byPID[s.PID]) == 0 {
			continue
		}
		tag := uint16(s.ComponentTag)
		if !s.HasTag && typ == "mp4a" {
			tag = 0x10
		}
		assets = append(assets, generalAsset{stream: s, packetID: packetID, tag: tag, typeName: typ, pes: byPID[s.PID]})
	}
	return assets
}

func generalHEVCAdmissionNAL(pes []tsdemux.PES) []byte {
	const maxCompleteAdmissionNAL = 60000
	for _, p := range pes {
		samples, err := codecrev.AnnexBToNALSamples(p.Payload)
		if err != nil {
			continue
		}
		for _, sample := range samples {
			if len(sample) < 6 || len(sample) > maxCompleteAdmissionNAL || (sample[4]>>1)&0x3f != 1 {
				continue
			}
			annexB := make([]byte, len(sample))
			copy(annexB, sample)
			copy(annexB[:4], []byte{0, 0, 0, 1})
			return annexB
		}
	}
	return nil
}

func writeGeneralMHEIT(w io.Writer, sections [][]byte, ntp uint64, seq *mmtwrite.Sequencer,
	flow generalFlow) error {
	for _, section := range sections {
		if err := writeGeneralM2Section(w, section, si.PacketIDMHEIT, ntp, seq, flow); err != nil {
			return err
		}
	}
	return nil
}

func writeGeneralM2Section(w io.Writer, section []byte, packetID uint16, ntp uint64, seq *mmtwrite.Sequencer,
	flow generalFlow) error {
	message := binary.BigEndian.AppendUint16(nil, si.MessageIDM2Section)
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, uint16(len(section)))
	message = append(message, section...)
	packet := mmtwrite.BuildPacket(mmtwrite.Header{
		PayloadType: mmtwrite.PayloadTypeSignaling, PacketID: packetID,
		SequenceNumber: seq.Next(packetID), Timestamp: mmtwrite.TimestampFromNTP(ntp),
	}, mmtwrite.WrapSignalling(message))
	return flow.write(w, packet)
}

type generalEITEvent struct {
	eventID     uint16
	start       [5]byte
	duration    [3]byte
	name        string
	text        string
	descriptors []byte
}

func buildGeneralMHEIT(service uint16, sections []tsdemux.Section, ntpBase uint64, conv *siup.Converter) [][]byte {
	present, following := generalEITEvents(service, sections, ntpBase, conv)
	return [][]byte{
		buildGeneralMHEITSection(service, 0, present),
		buildGeneralMHEITSection(service, 1, following),
	}
}

func generalEITEvents(service uint16, sections []tsdemux.Section, ntpBase uint64,
	conv *siup.Converter) (generalEITEvent, generalEITEvent) {
	var present, following generalEITEvent
	var havePresent, haveFollowing bool
	for _, s := range sections {
		if s.PID != mpegts.PIDEIT || s.TableID != mpegts.TableIDEITPFActual || len(s.Data) < 30 ||
			binary.BigEndian.Uint16(s.Data[3:5]) != service || s.Data[6] > 1 {
			continue
		}
		event, ok := parseGeneralEITEvent(s.Data, conv)
		if !ok {
			continue
		}
		if s.Data[6] == 0 && !havePresent {
			present, havePresent = event, true
		} else if s.Data[6] == 1 && !haveFollowing {
			following, haveFollowing = event, true
		}
		if havePresent && haveFollowing {
			break
		}
	}
	var now [5]byte
	copy(now[:], buildGeneralMHTOT(ntpBase)[3:8])
	if !havePresent {
		if scheduled, ok := generalScheduledEvent(service, sections, now, conv); ok {
			present, havePresent = scheduled, true
		}
	}
	if !havePresent {
		present.start = now
		present.eventID, present.duration = 1, [3]byte{0x01, 0x00, 0x00}
		if haveFollowing {
			if gap, ok := generalEITGap(present.start, following.start); ok {
				present.duration = gap
			}
		}
	}
	if !haveFollowing {
		next := generalEITAdvance(present.start, present.duration)
		if scheduled, ok := generalScheduledEvent(service, sections, next, conv); ok {
			following, haveFollowing = scheduled, true
		} else {
			following.eventID = present.eventID + 1
			following.start = next
			following.duration = [3]byte{0x01, 0x00, 0x00}
		}
	}
	// 番組名がなければサービス名を使う。
	fallbackName := generalServiceName(service, sections)
	if fallbackName == "" {
		fallbackName = "番組"
	}
	if present.name == "" {
		present.name = fallbackName
	}
	if following.name == "" {
		following.name = fallbackName
	}
	if following.eventID == present.eventID {
		following.eventID = present.eventID + 1
	}
	return present, following
}

func generalScheduledEvent(service uint16, sections []tsdemux.Section, at [5]byte,
	conv *siup.Converter) (generalEITEvent, bool) {
	want, ok := generalEITSeconds(at)
	if !ok {
		return generalEITEvent{}, false
	}
	day := binary.BigEndian.Uint16(at[0:2])
	var best generalEITEvent
	found := false
	for _, s := range sections {
		if s.PID != mpegts.PIDEIT || len(s.Data) < 18 ||
			s.TableID < mpegts.TableIDEITScheduleFirst || s.TableID > mpegts.TableIDEITScheduleLast ||
			binary.BigEndian.Uint16(s.Data[3:5]) != service {
			continue
		}
		for _, event := range parseGeneralEITEvents(s.Data, conv) {
			if binary.BigEndian.Uint16(event.start[0:2]) != day {
				continue
			}
			start, ok := generalEITSeconds(event.start)
			if !ok || start > want || want >= start+generalEITDurationSeconds(event.duration) {
				continue
			}
			if !found || (best.name == "" && event.name != "") {
				best, found = event, true
			}
		}
	}
	return best, found
}

func generalServiceName(service uint16, sections []tsdemux.Section) string {
	for _, s := range sections {
		if s.PID != mpegts.PIDSDT || s.TableID != mpegts.TableIDSDTActual || len(s.Data) < 15 {
			continue
		}
		for p, end := 11, len(s.Data)-4; p+5 <= end; {
			id := binary.BigEndian.Uint16(s.Data[p : p+2])
			descLen := int(binary.BigEndian.Uint16(s.Data[p+3:p+5]) & 0x0fff)
			if id == service {
				if name := generalServiceDescriptorName(s.Data[p+5 : min(p+5+descLen, end)]); name != "" {
					return name
				}
			}
			p += 5 + descLen
		}
	}
	return ""
}

func generalServiceDescriptorName(descriptors []byte) string {
	for q := 0; q+2 <= len(descriptors); {
		n := int(descriptors[q+1])
		if q+2+n > len(descriptors) {
			break
		}
		if descriptors[q] == 0x48 && n >= 3 {
			b := descriptors[q+2 : q+2+n]
			providerLen := int(b[1])
			if 2+providerLen < len(b) {
				nameLen := int(b[2+providerLen])
				if 3+providerLen+nameLen <= len(b) {
					return arib.DecodeString(b[3+providerLen : 3+providerLen+nameLen]).Text
				}
			}
		}
		q += 2 + n
	}
	return ""
}

func parseGeneralEITEvents(data []byte, conv *siup.Converter) []generalEITEvent {
	var out []generalEITEvent
	end := len(data) - 4
	for p := 14; p+12 <= end; {
		event, descLen, ok := parseGeneralEITEventAt(data, p, end, conv)
		if !ok {
			break
		}
		out = append(out, event)
		p += 12 + descLen
	}
	return out
}

func parseGeneralEITEvent(data []byte, conv *siup.Converter) (generalEITEvent, bool) {
	event, _, ok := parseGeneralEITEventAt(data, 14, len(data)-4, conv)
	return event, ok
}

func parseGeneralEITEventAt(data []byte, p, end int, conv *siup.Converter) (generalEITEvent, int, bool) {
	var event generalEITEvent
	if p+12 > end {
		return event, 0, false
	}
	event.eventID = binary.BigEndian.Uint16(data[p : p+2])
	copy(event.start[:], data[p+2:p+7])
	copy(event.duration[:], data[p+7:p+10])
	descLen := int(binary.BigEndian.Uint16(data[p+10:p+12]) & 0x0fff)
	event.descriptors = conv.Descriptors(data[p+12 : min(p+12+descLen, end)])
	for q, de := p+12, min(p+12+descLen, end); q+2 <= de; {
		n := int(data[q+1])
		q += 2
		if q+n > de {
			break
		}
		if data[q-2] == 0x4d && n >= 5 {
			b := data[q : q+n]
			nl := int(b[3])
			if 4+nl < len(b) {
				event.name = arib.DecodeString(b[4 : 4+nl]).Text
				tl := int(b[4+nl])
				if 5+nl+tl <= len(b) {
					event.text = arib.DecodeString(b[5+nl : 5+nl+tl]).Text
				}
			}
		}
		q += n
	}
	return event, descLen, true
}

func generalEITSeconds(start [5]byte) (int, bool) {
	h, m, s := fromBCD(start[2]), fromBCD(start[3]), fromBCD(start[4])
	if h > 23 || m > 59 || s > 59 {
		return 0, false
	}
	return h*3600 + m*60 + s, true
}

func generalEITDurationSeconds(d [3]byte) int {
	return fromBCD(d[0])*3600 + fromBCD(d[1])*60 + fromBCD(d[2])
}

func generalEITGap(from, to [5]byte) ([3]byte, bool) {
	a, aok := generalEITSeconds(from)
	b, bok := generalEITSeconds(to)
	if !aok || !bok || b <= a {
		return [3]byte{}, false
	}
	return bcdDuration(b - a), true
}

func generalEITAdvance(start [5]byte, d [3]byte) [5]byte {
	seconds, ok := generalEITSeconds(start)
	if !ok {
		return start
	}
	seconds += generalEITDurationSeconds(d)
	out := start
	mjd := binary.BigEndian.Uint16(start[0:2])
	binary.BigEndian.PutUint16(out[0:2], mjd+uint16(seconds/86400))
	seconds %= 86400
	out[2], out[3], out[4] = bcd(seconds/3600), bcd(seconds/60%60), bcd(seconds%60)
	return out
}

func bcdDuration(seconds int) [3]byte {
	if seconds > 99*3600 {
		seconds = 99 * 3600
	}
	return [3]byte{bcd(seconds / 3600), bcd(seconds / 60 % 60), bcd(seconds % 60)}
}

func buildGeneralMHEITSection(service uint16, sectionNumber byte, e generalEITEvent) []byte {
	desc := e.descriptors
	if len(desc) == 0 {
		short := append([]byte("jpn"), byte(len(e.name)))
		short = append(short, e.name...)
		short = binary.BigEndian.AppendUint16(short, uint16(len(e.text)))
		short = append(short, e.text...)
		desc = binary.BigEndian.AppendUint16(nil, si.TagMHShortEvent)
		desc = binary.BigEndian.AppendUint16(desc, uint16(len(short)))
		desc = append(desc, short...)
	}
	event := binary.BigEndian.AppendUint16(nil, e.eventID)
	event = append(event, e.start[:]...)
	event = append(event, e.duration[:]...)
	event = binary.BigEndian.AppendUint16(event, 0x8000|uint16(len(desc)))
	event = append(event, desc...)
	body := binary.BigEndian.AppendUint16(nil, service)
	body = binary.BigEndian.AppendUint16(body, service)
	body = append(body, 1, si.TableIDMHEITPF)
	body = append(body, event...)
	section := []byte{si.TableIDMHEITPF, 0, 0}
	section = binary.BigEndian.AppendUint16(section, service)
	section = append(section, 0xc1, sectionNumber, 1)
	section = append(section, body...)
	binary.BigEndian.PutUint16(section[1:3], 0xf000|uint16(len(section)-3+4))
	return binary.BigEndian.AppendUint32(section, mpegts.CRC32(section))
}

func writeGeneralMHTOT(w io.Writer, ntp uint64, seq *mmtwrite.Sequencer,
	flow generalFlow) error {
	section := buildGeneralMHTOT(ntp)
	message := binary.BigEndian.AppendUint16(nil, si.MessageIDM2ShortSection)
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, uint16(len(section)))
	message = append(message, section...)
	packet := mmtwrite.BuildPacket(mmtwrite.Header{
		PayloadType: mmtwrite.PayloadTypeSignaling, PacketID: si.PacketIDMHTOT,
		SequenceNumber: seq.Next(si.PacketIDMHTOT), Timestamp: mmtwrite.TimestampFromNTP(ntp),
	}, mmtwrite.WrapSignalling(message))
	return flow.write(w, packet)
}

func buildGeneralMHTOT(ntp uint64) []byte {
	const ntpUnixOffset = 2208988800
	seconds := int64(ntp >> 32)
	t := time.Unix(seconds-ntpUnixOffset, 0).In(time.FixedZone("JST", 9*60*60))
	mjd := uint16(t.Unix()/86400 + 40587)
	section := []byte{si.TableIDMHTOT, 0, 0}
	section = binary.BigEndian.AppendUint16(section, mjd)
	section = append(section, bcd(t.Hour()), bcd(t.Minute()), bcd(t.Second()), 0xf0, 0x00)
	binary.BigEndian.PutUint16(section[1:3], 0x7000|uint16(len(section)-3+4))
	return binary.BigEndian.AppendUint32(section, mpegts.CRC32(section))
}

func generalNTPBaseFromSections(sections []tsdemux.Section) uint64 {
	for _, s := range sections {
		if s.PID != mpegts.PIDTOT || s.TableID != mpegts.TableIDTOT || len(s.Data) < 8 {
			continue
		}
		mjd := int(binary.BigEndian.Uint16(s.Data[3:5]))
		h, mok := fromBCD(s.Data[5]), true
		m, sec := fromBCD(s.Data[6]), fromBCD(s.Data[7])
		if h > 23 || m > 59 || sec > 59 {
			mok = false
		}
		if !mok {
			continue
		}
		unix := int64(mjd-40587)*86400 + int64(h*3600+m*60+sec) - 9*3600
		return uint64(unix+2208988800) << 32
	}
	return generalNTPBase
}

func fromBCD(v byte) int { return int(v>>4)*10 + int(v&0x0f) }

func bcd(v int) byte { return byte(v/10)<<4 | byte(v%10) }

func validGeneralPES(asset generalAsset, report *Report) []tsdemux.PES {
	out := make([]tsdemux.PES, 0, len(asset.pes))
	for _, p := range asset.pes {
		if !p.HasPTS || len(p.Payload) == 0 {
			continue
		}
		var err error
		switch asset.stream.StreamType {
		case mpegts.StreamTypeHEVC:
			_, err = codecrev.AnnexBToNALSamples(p.Payload)
		case mpegts.StreamTypeADTSAAC:
			if complete := codecrev.CompleteADTSPrefix(p.Payload); complete < len(p.Payload) {
				report.problem("ordinary TS PID %#04x: PES at PTS %d ends mid-ADTS-frame: last %d byte(s) dropped",
					p.PID, p.PTS, len(p.Payload)-complete)
				p.Payload = p.Payload[:complete]
			}
			if len(p.Payload) == 0 {
				continue
			}
			if _, _, err := codecrev.SplitADTS(p.Payload); err != nil {
				report.problem("ordinary TS PID %#04x: incomplete PES at PTS %d skipped: %v", p.PID, p.PTS, err)
				continue
			}
			out = append(out, splitADTSAccessUnits(p)...)
			continue
		case mpegts.StreamTypeLATMAAC:
			_, err = codecrev.StripLOAS(p.Payload)
		}
		if err != nil {
			report.problem("ordinary TS PID %#04x: incomplete PES at PTS %d skipped: %v", p.PID, p.PTS, err)
			continue
		}
		out = append(out, p)
	}
	return out
}

func groupGeneralMPUs(asset generalAsset, toNTP func(int64) uint64) []generalMPU {
	pes := asset.pes
	if asset.typeName == "hev1" {
		first := -1
		for i, p := range pes {
			if p.RandomAccess || hevcHasIRAP(p.Payload) {
				first = i
				break
			}
		}
		if first < 0 {
			return nil
		}
		pes = pes[first:]
	}
	var groups [][]tsdemux.PES
	if asset.typeName == "hev1" {
		var current []tsdemux.PES
		for _, p := range pes {
			isRAP := p.RandomAccess || hevcHasIRAP(p.Payload)
			if isRAP && len(current) > 0 {
				groups = append(groups, current)
				current = nil
			}
			current = append(current, p)
			if len(current) == 60 {
				groups = append(groups, current)
				current = nil
			}
		}
		if len(current) > 0 {
			groups = append(groups, current)
		}
	} else {
		for len(pes) > 0 {
			n := min(4, len(pes))
			groups = append(groups, pes[:n])
			pes = pes[n:]
		}
	}
	out := make([]generalMPU, 0, len(groups))
	for i, group := range groups {
		start := group[0].PTS
		for _, p := range group[1:] {
			if p.PTS < start {
				start = p.PTS
			}
		}
		out = append(out, generalMPU{sequence: uint32(i), pes: group, startPTS: start,
			startNTP: toNTP(start), rap: asset.typeName == "mp4a" || group[0].RandomAccess || hevcHasIRAP(group[0].Payload)})
	}
	return out
}

func earliestPTS(assets []generalAsset) (int64, bool) {
	var first int64
	ok := false
	for _, a := range assets {
		for _, p := range a.pes {
			if p.HasPTS && (!ok || p.PTS < first) {
				first, ok = p.PTS, true
			}
		}
	}
	return first, ok
}

func hevcHasIRAP(b []byte) bool {
	for i := 0; i+5 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && ((b[i+2] == 1) || (b[i+2] == 0 && b[i+3] == 1)) {
			p := i + 3
			if b[i+2] == 0 {
				p++
			}
			typ := (b[p] >> 1) & 0x3f
			if typ >= 16 && typ <= 23 {
				return true
			}
		}
	}
	return false
}

func buildGeneralNIT(service uint16, sections []tsdemux.Section, conv *siup.Converter) []byte {
	for _, s := range sections {
		if s.PID != mpegts.PIDNIT || s.TableID != mpegts.TableIDNITActual {
			continue
		}
		if nit, ok := conv.TLVNIT(s.Data); ok {
			return nit
		}
	}
	section := []byte{si.TableIDTLVNITActual, 0, 0}
	section = binary.BigEndian.AppendUint16(section, service)
	section = append(section, 0xc1, 0, 0, 0xf0, 0)
	stream := binary.BigEndian.AppendUint16(nil, service)
	stream = binary.BigEndian.AppendUint16(stream, service)
	stream = binary.BigEndian.AppendUint16(stream, 0xf000)
	section = binary.BigEndian.AppendUint16(section, 0xf000|uint16(len(stream)))
	section = append(section, stream...)
	binary.BigEndian.PutUint16(section[1:3], 0xf000|uint16(len(section)-3+4))
	return binary.BigEndian.AppendUint32(section, mpegts.CRC32(section))
}

func buildGeneralMHSDT(sections []tsdemux.Section, logos map[uint16][]byte, conv *siup.Converter) [][]byte {
	var out [][]byte
	seen := map[[3]byte]bool{}
	for _, s := range sections {
		if s.PID != mpegts.PIDSDT || len(s.Data) < 15 ||
			(s.TableID != mpegts.TableIDSDTActual && s.TableID != mpegts.TableIDSDTOther) {
			continue
		}
		key := [3]byte{s.TableID, s.Data[3], s.Data[4]}
		if seen[key] {
			continue
		}
		seen[key] = true
		if sdt, ok := conv.MHSDT(s.Data, logos); ok {
			out = append(out, sdt)
		}
	}
	return out
}

func buildGeneralLogos(sections []tsdemux.Section, networkID uint16,
	conv *siup.Converter) ([][]byte, map[uint16][]byte, int) {
	reader := logocarousel.New()
	for _, s := range sections {
		if s.TableID == mpegts.TableIDDII || s.TableID == mpegts.TableIDDDB {
			reader.Push(s.PID, s.Data)
		}
	}
	var cdt [][]byte
	pointers := map[uint16][]byte{}
	sets := conv.Logos(reader.Logos(), networkID)
	for _, set := range sets {
		cdt = append(cdt, set.Sections...)
		for _, svc := range set.Services {
			if _, taken := pointers[svc.ServiceID]; !taken {
				pointers[svc.ServiceID] = set.Descriptor()
			}
		}
	}
	return cdt, pointers, len(reader.Logos())
}

func buildGeneralMHEITSchedule(services []*generalService, sections []tsdemux.Section, conv *siup.Converter) [][]byte {
	wanted := make(map[uint16]bool, len(services))
	for _, s := range services {
		wanted[s.number] = true
	}
	var out [][]byte
	seen := map[[4]byte]bool{}
	for _, s := range sections {
		if s.PID != mpegts.PIDEIT || len(s.Data) < 18 ||
			s.TableID < mpegts.TableIDEITScheduleFirst || s.TableID > mpegts.TableIDEITScheduleLast ||
			!wanted[binary.BigEndian.Uint16(s.Data[3:5])] {
			continue
		}
		key := [4]byte{s.TableID, s.Data[6], s.Data[3], s.Data[4]}
		if seen[key] {
			continue
		}
		seen[key] = true
		if section, ok := conv.MHEITSchedule(s.Data); ok {
			out = append(out, section)
		}
	}
	return out
}

func writeGeneralMHSDT(w io.Writer, sections [][]byte, ntp uint64, seq *mmtwrite.Sequencer,
	flow generalFlow) error {
	for _, section := range sections {
		if err := writeGeneralM2Section(w, section, si.PacketIDMHSDT, ntp, seq, flow); err != nil {
			return err
		}
	}
	return nil
}

func generalNetworkID(service uint16, sections []tsdemux.Section) uint16 {
	for _, s := range sections {
		if s.PID == mpegts.PIDSDT && s.TableID == mpegts.TableIDSDTActual && len(s.Data) >= 11 {
			return binary.BigEndian.Uint16(s.Data[8:10])
		}
	}
	for _, s := range sections {
		if s.PID == mpegts.PIDNIT && s.TableID == mpegts.TableIDNITActual && len(s.Data) >= 5 {
			return binary.BigEndian.Uint16(s.Data[3:5])
		}
	}
	return service
}

func buildGeneralMHBIT(sections []tsdemux.Section, conv *siup.Converter) [][]byte {
	var out [][]byte
	seen := map[byte]bool{}
	for _, s := range sections {
		if s.PID != mpegts.PIDBIT || s.TableID != mpegts.TableIDBIT || len(s.Data) < 14 {
			continue
		}
		if seen[s.Data[6]] {
			continue
		}
		seen[s.Data[6]] = true
		if section, ok := conv.MHBIT(s.Data); ok {
			out = append(out, section)
		}
	}
	return out
}

func writeGeneralMHBIT(w io.Writer, sections [][]byte, ntp uint64, seq *mmtwrite.Sequencer,
	flow generalFlow) error {
	for _, section := range sections {
		if err := writeGeneralM2Section(w, section, si.PacketIDMHBIT, ntp, seq, flow); err != nil {
			return err
		}
	}
	return nil
}

func buildGeneralMHCDT(sections []tsdemux.Section, conv *siup.Converter) [][]byte {
	var out [][]byte
	seen := map[[3]byte]bool{}
	for _, s := range sections {
		if s.PID != mpegts.PIDCDT || s.TableID != mpegts.TableIDCDT || len(s.Data) < 17 {
			continue
		}
		key := [3]byte{s.Data[3], s.Data[4], s.Data[6]}
		if seen[key] {
			continue
		}
		seen[key] = true
		if section, ok := conv.MHCDT(s.Data); ok {
			out = append(out, section)
		}
	}
	return out
}

func writeGeneralMHCDT(w io.Writer, sections [][]byte, ntp uint64, seq *mmtwrite.Sequencer,
	flow generalFlow) error {
	for _, section := range sections {
		if err := writeGeneralM2Section(w, section, si.PacketIDMHCDT, ntp, seq, flow); err != nil {
			return err
		}
	}
	return nil
}

func writeGeneralMHEITSchedule(w io.Writer, sections [][]byte, ntp uint64, seq *mmtwrite.Sequencer,
	flow generalFlow) error {
	for _, section := range sections {
		if err := writeGeneralM2Section(w, section, si.PacketIDMHEIT, ntp, seq, flow); err != nil {
			return err
		}
	}
	return nil
}

func buildGeneralAMT(networkID uint16, services []*generalService) []byte {
	_ = networkID
	section := []byte{si.TableIDAMT, 0, 0}
	section = binary.BigEndian.AppendUint16(section, 0)
	section = append(section, 0xc1, 0, 0)
	section = binary.BigEndian.AppendUint16(section, 0x007f)
	for _, svc := range services {
		section = binary.BigEndian.AppendUint16(section, svc.number)
		section = binary.BigEndian.AppendUint16(section, 0xfc00|uint16(2*(16+1)))
		section = append(section, pad16(svc.flow.src)...)
		section = append(section, 0x80)
		section = append(section, pad16(svc.flow.dst)...)
		section = append(section, 0x80)
	}
	binary.BigEndian.PutUint16(section[1:3], 0xf000|uint16(len(section)-3+4))
	return binary.BigEndian.AppendUint32(section, mpegts.CRC32(section))
}

func pad16(e tlvwrite.Endpoint) []byte {
	b := make([]byte, 16)
	copy(b, e)
	return b
}

func writeGeneralTLVSI(w io.Writer, nit, amt []byte) error {
	if err := tlvwrite.WriteControl(w, nit); err != nil {
		return err
	}
	return tlvwrite.WriteControl(w, amt)
}

func buildGeneralPLT(services []*generalService) []byte {
	pltBody := []byte{byte(len(services))}
	for _, s := range services {
		pkg := binary.BigEndian.AppendUint16(nil, s.number)
		pltBody = append(pltBody, byte(len(pkg)))
		pltBody = append(pltBody, pkg...)
		pltBody = append(pltBody, 0x02)
		pltBody = append(pltBody, pad16(s.flow.src)...)
		pltBody = append(pltBody, pad16(s.flow.dst)...)
		pltBody = binary.BigEndian.AppendUint16(pltBody, s.flow.dstPort)
		pltBody = binary.BigEndian.AppendUint16(pltBody, s.mptPID)
	}
	pltBody = append(pltBody, 0x00)
	return paWithTable(signaling.TableIDPLT, 0, pltBody)
}

func buildGeneralMPT(service uint16, version byte, assets []generalAsset, at uint64) ([]byte, error) {
	pkg := binary.BigEndian.AppendUint16(nil, service)
	mptBody := []byte{0xfc, byte(len(pkg))}
	mptBody = append(mptBody, pkg...)
	mptBody = binary.BigEndian.AppendUint16(mptBody, 0)
	mptBody = append(mptBody, byte(len(assets)))
	for _, a := range assets {
		desc := streamIdentifierDescriptor(a.tag)
		windowCount := 3
		if a.typeName == "mp4a" {
			windowCount = 15
		}
		window := generalMPUWindow(a.mpus, at, windowCount)
		if len(window) != 0 {
			stamps := make([]struct {
				seq uint32
				ntp uint64
			}, len(window))
			for i, mpu := range window {
				stamps[i] = struct {
					seq uint32
					ntp uint64
				}{mpu.sequence, mpu.startNTP}
			}
			desc = append(desc, timestampDescriptors([]struct {
				seq uint32
				ntp uint64
			}(stamps))...)
		}
		if a.typeName == "hev1" {
			data := []byte{0x63, 0x88, byte(a.tag >> 8), byte(a.tag), 0x5f, 'j', 'p', 'n'}
			desc = appendDescriptor(desc, signaling.TagVideoComponent, data)
		}
		if a.typeName == "mp4a" {
			data := []byte{0x03, 0x03, byte(a.tag >> 8), byte(a.tag), 0x11, 0xff, 0x5f, 'j', 'p', 'n'}
			desc = appendDescriptor(desc, signaling.TagAudioComponent, data)
		}
		if len(window) != 0 {
			extended := extendedMPUWindow(window)
			fallback := uint16(3003)
			if a.typeName == "mp4a" {
				fallback = 3840
			}
			desc = append(desc, extendedTimestampDescriptors(extended, fallback)...)
		}
		mptBody = append(mptBody, 0x00)
		mptBody = binary.BigEndian.AppendUint32(mptBody, 0)
		mptBody = append(mptBody, 2)
		mptBody = binary.BigEndian.AppendUint16(mptBody, a.packetID)
		mptBody = append(mptBody, a.typeName...)
		mptBody = append(mptBody, 0xfe, 1, 0x00)
		mptBody = binary.BigEndian.AppendUint16(mptBody, a.packetID)
		mptBody = binary.BigEndian.AppendUint16(mptBody, uint16(len(desc)))
		mptBody = append(mptBody, desc...)
	}
	if len(mptBody) > 0xffff {
		return nil, fmt.Errorf("ts2mmt: generated MPT is %d bytes (limit 65535)", len(mptBody))
	}
	return paWithTable(signaling.TableIDMPTComplete, version, mptBody), nil
}

func generalMPUWindow(mpus []generalMPU, at uint64, count int) []generalMPU {
	if len(mpus) == 0 || count <= 0 {
		return nil
	}
	start := sort.Search(len(mpus), func(i int) bool { return mpus[i].startNTP > at }) - 1
	if start < 0 {
		start = 0
	}
	end := min(len(mpus), start+count)
	return mpus[start:end]
}

func extendedMPUWindow(mpus []generalMPU) []generalMPU {
	size, count := 7, 0
	for _, mpu := range mpus {
		n := 8 + 2*len(mpu.pes)
		if size+n > 255 {
			break
		}
		size += n
		count++
	}
	return mpus[:count]
}

func streamIdentifierDescriptor(tag uint16) []byte {
	return appendDescriptor(nil, signaling.TagStreamIdentifier, []byte{byte(tag >> 8), byte(tag)})
}

func timestampDescriptors(stamps []struct {
	seq uint32
	ntp uint64
}) []byte {
	var out []byte
	for len(stamps) > 0 {
		n := min(21, len(stamps))
		data := make([]byte, 0, n*12)
		for _, s := range stamps[:n] {
			data = binary.BigEndian.AppendUint32(data, s.seq)
			data = binary.BigEndian.AppendUint64(data, s.ntp)
		}
		out = appendDescriptor(out, signaling.TagMPUTimestamp, data)
		stamps = stamps[n:]
	}
	return out
}

func extendedTimestampDescriptors(mpus []generalMPU, fallbackInterval uint16) []byte {
	if len(mpus) == 0 {
		return nil
	}
	data := []byte{0x03}
	data = binary.BigEndian.AppendUint32(data, 180000)
	interval := nominalPTSInterval(mpus)
	if interval == 0 {
		interval = fallbackInterval
	}
	data = binary.BigEndian.AppendUint16(data, interval)
	for _, mpu := range mpus {
		if len(mpu.pes) == 0 || len(mpu.pes) > 60 {
			continue
		}
		firstDTS := mpu.pes[0].PTS
		if mpu.pes[0].HasDTS {
			firstDTS = mpu.pes[0].DTS
		}
		decodingOffset := clampU16(mpu.startPTS - firstDTS)
		data = binary.BigEndian.AppendUint32(data, mpu.sequence)
		data = append(data, 0)
		data = binary.BigEndian.AppendUint16(data, clampU16(int64(decodingOffset)*2))
		data = append(data, byte(len(mpu.pes)))
		for _, p := range mpu.pes {
			dts := p.PTS
			if p.HasDTS {
				dts = p.DTS
			}
			data = binary.BigEndian.AppendUint16(data, clampU16((p.PTS-dts)*2))
		}
	}
	return appendDescriptor(nil, signaling.TagMPUExtendedTimestamp, data)
}

func nominalPTSInterval(mpus []generalMPU) uint16 {
	var total int64
	var count int64
	var previous int64
	havePrevious := false
	for _, mpu := range mpus {
		for _, pes := range mpu.pes {
			current := pes.PTS
			if pes.HasDTS {
				current = pes.DTS
			}
			if havePrevious && current > previous {
				total += (current - previous) * 2
				count++
			}
			previous, havePrevious = current, true
		}
	}
	if count == 0 {
		return 0
	}
	return clampU16((total + count/2) / count)
}

func clampU16(v int64) uint16 {
	if v <= 0 {
		return 0
	}
	if v > 0xffff {
		return 0xffff
	}
	return uint16(v)
}

func appendDescriptor(dst []byte, tag uint16, data []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, tag)
	dst = append(dst, byte(len(data)))
	return append(dst, data...)
}

func paWithTable(tableID, version byte, tableBody []byte) []byte {
	table := []byte{tableID, version}
	table = binary.BigEndian.AppendUint16(table, uint16(len(tableBody)))
	table = append(table, tableBody...)
	body := append([]byte{0}, table...)
	msg := binary.BigEndian.AppendUint16(nil, signaling.MessageIDPA)
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(body)))
	return append(msg, body...)
}

func writeGeneralPA(w io.Writer, message []byte, packetID uint16, ntp uint64, seq *mmtwrite.Sequencer,
	flow generalFlow) error {
	p := mmtwrite.BuildPacket(mmtwrite.Header{PayloadType: mmtwrite.PayloadTypeSignaling, PacketID: packetID,
		Timestamp: mmtwrite.TimestampFromNTP(ntp), SequenceNumber: seq.Next(packetID)}, mmtwrite.WrapSignalling(message))
	return flow.write(w, p)
}

func writeGeneralNTP(w io.Writer, ntp uint64, src tlvwrite.Endpoint) error {
	p := make([]byte, 48)
	p[0], p[1] = 0x24, 1
	binary.BigEndian.PutUint64(p[40:48], ntp)
	dst := tlvwrite.Endpoint{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	return tlvwrite.WriteUncompressedUDP(w, src, dst, 123, 123, p)
}
