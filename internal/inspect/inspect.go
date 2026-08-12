// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package inspect はTLV入力を走査し、サービスとアセットの構成をまとめる。
package inspect

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/tlv"
)

type Asset struct {
	Type         string
	PacketID     uint16
	ComponentTag *uint16
	Video        *VideoComponent
	Audio        *AudioComponent
	Group        *AssetGroup
	Hierarchy    *Hierarchy
	Descriptors  []Descriptor
}

type AssetGroup = signaling.AssetGroup
type Hierarchy = signaling.Hierarchy
type AudioComponent = signaling.AudioComponent
type VideoComponent = signaling.VideoComponent
type Descriptor = signaling.Descriptor

type MPT struct {
	Offset    uint64
	ServiceID uint16
	PacketID  uint16
	Version   byte
	Assets    []Asset
}

type Report struct {
	Bytes          uint64
	TLVPackets     uint64
	NullPackets    uint64
	MMTPPackets    uint64
	MMTPVersions   [4]uint64
	MMTPFECTypes   [4]uint64
	MMTPCounters   uint64
	InvalidPackets uint64
	PacketIDs      map[AssetKey]uint64
	RAPPackets     map[AssetKey]uint64
	Flows          map[string]uint64
	SignalingIDs   map[AssetKey]uint64
	FirstSignals   map[AssetKey][]byte
	MPTs           []MPT
	Timings        map[AssetKey][]MPUTiming
	ExtendedTiming map[AssetKey]*ExtendedTimingStats
	AUValidation   map[AssetKey]AUValidation
}

type AssetKey struct {
	Flow     uint16
	PacketID uint16
}

type AUValidation struct {
	ExpectedMPUs, MatchedMPUs, MismatchedMPUs, MissingMPUs  uint64
	ExpectedAUs, ObservedAUs                                uint64
	ExtraObservedMPUs                                       uint64
	FragmentedPayloads, AggregatedPayloads, InvalidPayloads uint64
	NonzeroMovieFragment, NonzeroSample, NonzeroOffset      uint64
	NonzeroPriority, NonzeroDependency                      uint64
	Examples                                                []string
}

type MPUTiming = signaling.MPUTimestamp

type ExtendedTimingStats struct {
	Descriptors      uint64
	Invalid          uint64
	Entries          uint64
	AccessUnits      uint64
	TimestampMatched uint64
	Timescales       map[uint32]uint64
	OffsetTypes      [4]uint64
	MinDTSOffset     uint16
	MaxDTSOffset     uint16
	MinPTSInterval   uint16
	MaxPTSInterval   uint16
	NonzeroLeap      uint64
	sequences        map[uint32]struct{}
}

type scanner struct {
	report     Report
	sig        *signaling.Reassembler
	flowSig    map[string]*signaling.Reassembler
	mptKeys    map[string]struct{}
	flowIndex  map[string]uint16
	flow       uint16
	timingSeen map[AssetKey]map[uint32]uint64
	expectedAU map[AssetKey]map[uint32]uint16
	observedAU map[AssetKey]map[uint32]uint32
	mediaStats map[AssetKey]*AUValidation
	mediaTypes map[AssetKey]string
	units      []mmtp.DataUnit
}

func Scan(r io.Reader) (Report, error) {
	s := &scanner{
		report: Report{
			PacketIDs:      make(map[AssetKey]uint64),
			RAPPackets:     make(map[AssetKey]uint64),
			Flows:          make(map[string]uint64),
			SignalingIDs:   make(map[AssetKey]uint64),
			FirstSignals:   make(map[AssetKey][]byte),
			Timings:        make(map[AssetKey][]MPUTiming),
			ExtendedTiming: make(map[AssetKey]*ExtendedTimingStats),
			AUValidation:   make(map[AssetKey]AUValidation),
		},
		sig:        signaling.NewReassembler(),
		flowSig:    make(map[string]*signaling.Reassembler),
		mptKeys:    make(map[string]struct{}),
		flowIndex:  make(map[string]uint16),
		timingSeen: make(map[AssetKey]map[uint32]uint64),
		expectedAU: make(map[AssetKey]map[uint32]uint16),
		observedAU: make(map[AssetKey]map[uint32]uint32),
		mediaStats: make(map[AssetKey]*AUValidation),
		mediaTypes: make(map[AssetKey]string),
	}
	tr := tlv.NewReader(r)
	for {
		packet, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return s.report, err
		}
		datagram, ok := tr.Datagram(packet)
		if !ok || datagram.IsNTP() {
			continue
		}
		m, err := mmtp.Parse(datagram.Payload)
		if err != nil {
			s.report.InvalidPackets++
			continue
		}
		flow := fmt.Sprintf("%x:%d>%x:%d", datagram.Src, datagram.SrcPort, datagram.Dst, datagram.DstPort)
		s.report.Flows[flow]++
		asm := s.flowSig[flow]
		if asm == nil {
			asm = signaling.NewReassembler()
			s.flowSig[flow] = asm
			s.flowIndex[flow] = uint16(len(s.flowIndex))
		}
		s.sig = asm
		s.flow = s.flowIndex[flow]
		s.processMMTP(m, packet.Offset)
	}
	ts := tr.Stats()
	s.report.Bytes = ts.Bytes
	s.report.TLVPackets = ts.Packets
	s.report.NullPackets = ts.NullPackets
	s.report.InvalidPackets += ts.Resyncs + ts.TruncatedPackets + ts.MalformedIP + ts.FragmentErrors
	for _, count := range ts.UnknownType {
		s.report.InvalidPackets += count
	}
	for _, count := range ts.UnknownCIDHeader {
		s.report.InvalidPackets += count
	}
	for _, asm := range s.flowSig {
		sig := asm.Stats()
		s.report.InvalidPackets += sig.MalformedTables + sig.DroppedFragments + sig.Overflows
	}
	sort.Slice(s.report.MPTs, func(i, j int) bool {
		if s.report.MPTs[i].ServiceID != s.report.MPTs[j].ServiceID {
			return s.report.MPTs[i].ServiceID < s.report.MPTs[j].ServiceID
		}
		return s.report.MPTs[i].Version < s.report.MPTs[j].Version
	})
	s.finalizeAUValidation()
	return s.report, nil
}

func (s *scanner) processMMTP(packet mmtp.Packet, offset uint64) {
	packetID := AssetKey{Flow: s.flow, PacketID: packet.PacketID}
	s.report.MMTPPackets++
	s.report.MMTPVersions[packet.Version]++
	s.report.MMTPFECTypes[packet.FECType]++
	if packet.HasCounter {
		s.report.MMTPCounters++
	}
	s.report.PacketIDs[packetID]++
	if packet.RAP {
		s.report.RAPPackets[packetID]++
	}
	if packet.Scrambled {
		s.report.InvalidPackets++
		return
	}
	if packet.PayloadType == mmtp.PayloadTypeMPU {
		s.processMedia(packet)
		return
	}
	if packet.PayloadType != mmtp.PayloadTypeSignaling {
		return
	}
	s.report.SignalingIDs[packetID]++
	if _, exists := s.report.FirstSignals[packetID]; !exists {
		end := min(len(packet.Payload), 2048)
		s.report.FirstSignals[packetID] = append([]byte(nil), packet.Payload[:end]...)
	}
	for _, message := range s.sig.Push(packetID.PacketID, packet.Payload) {
		for _, table := range message.Tables {
			if table.MPT != nil {
				s.processMPT(packetID, offset, table.MPT)
			}
		}
	}
}

func (s *scanner) processMedia(packet mmtp.Packet) {
	packetID := AssetKey{Flow: s.flow, PacketID: packet.PacketID}
	stats := s.mediaStats[packetID]
	if stats == nil {
		stats = &AUValidation{}
		s.mediaStats[packetID] = stats
	}
	payload, err := mmtp.ParseMPU(packet.Payload, s.units)
	if err != nil {
		stats.InvalidPayloads++
		return
	}
	s.units = payload.Units[:0]
	if payload.FragmentType != mmtp.FragmentTypeMFU || !payload.Timed {
		return
	}
	if payload.Fragmentation != mmtp.FragmentIndicatorComplete {
		stats.FragmentedPayloads++
	}
	if payload.Aggregation {
		stats.AggregatedPayloads++
	}
	for _, unit := range payload.Units {
		stats.observeTimedUnit(unit)
		if payload.Aggregation || payload.Fragmentation == mmtp.FragmentIndicatorComplete ||
			payload.Fragmentation == mmtp.FragmentIndicatorFirst {
			if s.isAUStart(packetID, unit.Offset, unit.Data) {
				s.recordObservedAU(packetID, payload.MPUSequence)
			}
		}
	}
}

func (s *AUValidation) observeTimedUnit(unit mmtp.DataUnit) {
	if unit.MovieFragment != 0 {
		s.NonzeroMovieFragment++
	}
	if unit.Sample != 0 {
		s.NonzeroSample++
	}
	if unit.Offset != 0 {
		s.NonzeroOffset++
	}
	if unit.Priority != 0 {
		s.NonzeroPriority++
	}
	if unit.DependencyCounter != 0 {
		s.NonzeroDependency++
	}
}

func (s *scanner) isAUStart(packetID AssetKey, offset uint32, data []byte) bool {
	switch s.mediaTypes[packetID] {
	case "hev1", "hvc1":
		return len(data) >= 6 && binary.BigEndian.Uint32(data[:4]) >= 2 && (data[4]>>1)&0x3f == 35
	case "mp4a":
		return offset == 0
	default:
		return false
	}
}

func (s *scanner) recordObservedAU(packetID AssetKey, mpu uint32) {
	byMPU := s.observedAU[packetID]
	if byMPU == nil {
		byMPU = make(map[uint32]uint32)
		s.observedAU[packetID] = byMPU
	}
	byMPU[mpu]++
}

func (s *scanner) processMPT(packetID AssetKey, offset uint64, table *signaling.MPT) {
	assets := make([]Asset, 0, len(table.Assets))
	for i := range table.Assets {
		source := &table.Assets[i]
		mediaPID, _ := source.LocalPacketID()
		asset := Asset{
			Type:         source.Type,
			PacketID:     mediaPID,
			ComponentTag: source.ComponentTag,
			Video:        source.Video,
			Audio:        source.Audio,
			Group:        source.Group,
			Hierarchy:    source.Hierarchy,
			Descriptors:  source.Descriptors,
		}
		if mediaPID != 0 {
			media := AssetKey{Flow: packetID.Flow, PacketID: mediaPID}
			s.mediaTypes[media] = source.Type
			for _, d := range source.Descriptors {
				switch d.Tag {
				case signaling.TagMPUTimestamp:
					s.recordMPUTimings(media, d.Data)
				case signaling.TagMPUExtendedTimestamp:
					s.recordExtendedTiming(media, d.Data)
				}
			}
		}
		assets = append(assets, asset)
	}
	key := fmt.Sprintf("%04x/%02x/%s", packetID.PacketID, table.Version, assetKey(assets))
	if _, exists := s.mptKeys[key]; exists {
		return
	}
	s.mptKeys[key] = struct{}{}
	s.report.MPTs = append(s.report.MPTs, MPT{
		Offset: offset, ServiceID: table.ServiceID(), PacketID: packetID.PacketID, Version: table.Version, Assets: assets,
	})
}

func (s *scanner) recordExtendedTiming(packetID AssetKey, data []byte) {
	stats := s.report.ExtendedTiming[packetID]
	if stats == nil {
		stats = &ExtendedTimingStats{Timescales: make(map[uint32]uint64), sequences: make(map[uint32]struct{}), MinDTSOffset: ^uint16(0), MinPTSInterval: ^uint16(0)}
		s.report.ExtendedTiming[packetID] = stats
	}
	stats.Descriptors++
	descriptor := signaling.ParseExtendedTimestamp(data)
	if descriptor.Invalid {
		stats.Invalid++
		return
	}
	ptsType := descriptor.PTSOffsetType
	stats.OffsetTypes[ptsType]++
	if descriptor.HasTimescale {
		stats.Timescales[descriptor.Timescale]++
	}
	if ptsType == 1 {
		stats.observePTSInterval(descriptor.DefaultPTSOffset)
	}
	for _, entry := range descriptor.Entries {
		if entry.Leap != 0 {
			stats.NonzeroLeap++
		}
		stats.observeDTSOffset(entry.DecodingTimeOffset)
		if _, exists := stats.sequences[entry.Sequence]; !exists {
			stats.sequences[entry.Sequence] = struct{}{}
			stats.Entries++
			stats.AccessUnits += uint64(len(entry.AUs))
			if s.expectedAU == nil {
				s.expectedAU = make(map[AssetKey]map[uint32]uint16)
			}
			expected := s.expectedAU[packetID]
			if expected == nil {
				expected = make(map[uint32]uint16)
				s.expectedAU[packetID] = expected
			}
			expected[entry.Sequence] = uint16(len(entry.AUs))
			if _, ok := s.timingSeen[packetID][entry.Sequence]; ok {
				stats.TimestampMatched++
			}
		}
		for _, au := range entry.AUs {
			stats.observeDTSOffset(au.DTSPTSOffset)
			if ptsType == 2 {
				stats.observePTSInterval(au.PTSOffset)
			}
		}
	}
}

func (s *scanner) finalizeAUValidation() {
	for pid, expected := range s.expectedAU {
		result := AUValidation{}
		if stats := s.mediaStats[pid]; stats != nil {
			result.FragmentedPayloads, result.AggregatedPayloads, result.InvalidPayloads = stats.FragmentedPayloads, stats.AggregatedPayloads, stats.InvalidPayloads
			result.NonzeroMovieFragment, result.NonzeroSample, result.NonzeroOffset = stats.NonzeroMovieFragment, stats.NonzeroSample, stats.NonzeroOffset
			result.NonzeroPriority, result.NonzeroDependency = stats.NonzeroPriority, stats.NonzeroDependency
		}
		observed := s.observedAU[pid]
		sequences := make([]uint32, 0, len(expected))
		for mpu := range expected {
			sequences = append(sequences, mpu)
		}
		sort.Slice(sequences, func(i, j int) bool { return sequences[i] < sequences[j] })
		for _, mpu := range sequences {
			count := expected[mpu]
			result.ExpectedMPUs++
			result.ExpectedAUs += uint64(count)
			got := int(observed[mpu])
			result.ObservedAUs += uint64(got)
			switch {
			case got == 0:
				result.MissingMPUs++
			case got == int(count):
				result.MatchedMPUs++
			default:
				result.MismatchedMPUs++
			}
			if got != int(count) && len(result.Examples) < 8 {
				result.Examples = append(result.Examples, fmt.Sprintf("mpu=%d expected=%d observed=%d", mpu, count, got))
			}
		}
		for mpu := range observed {
			if _, ok := expected[mpu]; !ok {
				result.ExtraObservedMPUs++
			}
		}
		s.report.AUValidation[pid] = result
	}
}

func (s *ExtendedTimingStats) observeDTSOffset(value uint16) {
	if value < s.MinDTSOffset {
		s.MinDTSOffset = value
	}
	if value > s.MaxDTSOffset {
		s.MaxDTSOffset = value
	}
}
func (s *ExtendedTimingStats) observePTSInterval(value uint16) {
	if value < s.MinPTSInterval {
		s.MinPTSInterval = value
	}
	if value > s.MaxPTSInterval {
		s.MaxPTSInterval = value
	}
}

func (s *scanner) recordMPUTimings(packetID AssetKey, data []byte) {
	seen := s.timingSeen[packetID]
	if seen == nil {
		seen = make(map[uint32]uint64)
		s.timingSeen[packetID] = seen
	}
	for _, timing := range signaling.ParseMPUTimestamps(data) {
		if old, exists := seen[timing.Sequence]; exists {
			if old != timing.NTP {
				s.report.InvalidPackets++
			}
			continue
		}
		seen[timing.Sequence] = timing.NTP
		s.report.Timings[packetID] = append(s.report.Timings[packetID], timing)
	}
}

func assetKey(assets []Asset) string {
	key := ""
	for _, a := range assets {
		key += fmt.Sprintf("%s:%04x:", a.Type, a.PacketID)
		if a.ComponentTag != nil {
			key += fmt.Sprintf("%04x", *a.ComponentTag)
		}
		if a.Audio != nil {
			key += fmt.Sprintf("/audio:%02x:%02x:%02x:%02x:%s",
				a.Audio.ComponentType, a.Audio.StreamType, a.Audio.SimulcastGroupTag,
				a.Audio.Flags, a.Audio.Language)
		}
		if a.Group != nil {
			key += fmt.Sprintf("/group:%02x:%02x", a.Group.Identification, a.Group.SelectionLevel)
		}
		if a.Hierarchy != nil {
			key += fmt.Sprintf("/hierarchy:%02x:%02x:%02x:%02x",
				a.Hierarchy.Type, a.Hierarchy.LayerIndex, a.Hierarchy.EmbeddedLayerIndex, a.Hierarchy.Channel)
		}
		key += ";"
	}
	return key
}
