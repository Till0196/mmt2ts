// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"bytes"
	"encoding/binary"
	"testing"

	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/tlv"
)

func TestParseDescriptorsAndAudioComponent(t *testing.T) {
	raw := []byte{
		0x80, 0x11, 0x02, 0x00, 0x10,
		0x80, 0x14, 0x0a, 0xf3, 0x03, 0x00, 0x10, 0x11, 0xff, 0x5f, 'j', 'p', 'n',
	}
	descriptors := signaling.ParseDescriptors(raw)
	if len(descriptors) != 2 {
		t.Fatalf("descriptor count = %d, want 2", len(descriptors))
	}
	if descriptors[0].Tag != 0x8011 || !bytes.Equal(descriptors[0].Data, []byte{0, 0x10}) {
		t.Fatalf("stream identification = %#v", descriptors[0])
	}
	data := descriptors[1].Data
	audio := AudioComponent{
		StreamContent:     data[0] & 0x0f,
		ComponentType:     data[1],
		ComponentTag:      uint16(data[2])<<8 | uint16(data[3]),
		StreamType:        data[4],
		SimulcastGroupTag: data[5],
		Flags:             data[6],
		Language:          string(data[7:10]),
	}
	if audio.StreamContent != 3 || audio.ComponentType != 3 || audio.ComponentTag != 0x10 ||
		audio.StreamType != 0x11 || audio.SimulcastGroupTag != 0xff || audio.Language != "jpn" {
		t.Fatalf("audio component = %+v", audio)
	}
}

func TestAssetGroupAndHierarchyDescriptor(t *testing.T) {
	raw := []byte{
		0x80, 0x00, 0x02, 0x07, 0x00,
		0x80, 0x37, 0x04, 0x21, 0x02, 0x81, 0x03,
	}
	descriptors := signaling.ParseDescriptors(raw)
	if len(descriptors) != 2 {
		t.Fatalf("descriptor count = %d, want 2", len(descriptors))
	}
	group := AssetGroup{Identification: descriptors[0].Data[0], SelectionLevel: descriptors[0].Data[1]}
	if group.Identification != 7 || group.SelectionLevel != 0 {
		t.Fatalf("group = %+v", group)
	}
	d := descriptors[1].Data
	hierarchy := Hierarchy{
		SpatialScalabilityFlag: d[0]&0x20 != 0,
		Type:                   d[0] & 0x0f,
		LayerIndex:             d[1] & 0x3f,
		TREFPresent:            d[2]&0x80 != 0,
		EmbeddedLayerIndex:     d[2] & 0x3f,
		Channel:                d[3] & 0x3f,
	}
	if !hierarchy.SpatialScalabilityFlag || hierarchy.Type != 1 || hierarchy.LayerIndex != 2 ||
		!hierarchy.TREFPresent || hierarchy.EmbeddedLayerIndex != 1 || hierarchy.Channel != 3 {
		t.Fatalf("hierarchy = %+v", hierarchy)
	}
}

func TestRecordMPUTimings(t *testing.T) {
	s := &scanner{report: Report{Timings: make(map[AssetKey][]MPUTiming)}, timingSeen: make(map[AssetKey]map[uint32]uint64)}
	raw := []byte{0, 0, 0, 7, 0xe1, 0x23, 0x45, 0x67, 0x80, 0, 0, 0}
	s.recordMPUTimings(AssetKey{PacketID: 0xf100}, raw)
	s.recordMPUTimings(AssetKey{PacketID: 0xf100}, raw)
	if got := s.report.Timings[AssetKey{PacketID: 0xf100}]; len(got) != 1 || got[0].Sequence != 7 || got[0].NTP != 0xe123456780000000 {
		t.Fatalf("timings = %#v", got)
	}
}

func TestRecordExtendedTiming(t *testing.T) {
	s := &scanner{
		report:     Report{ExtendedTiming: make(map[AssetKey]*ExtendedTimingStats)},
		timingSeen: map[AssetKey]map[uint32]uint64{AssetKey{PacketID: 0xf110}: {7: 1}},
	}
	raw := []byte{
		0x03,
		0x00, 0x02, 0xbf, 0x20,
		0x0f, 0x00,
		0x00, 0x00, 0x00, 0x07,
		0x00,
		0x00, 0x00,
		0x02,
		0x00, 0x00, 0x00, 0x00,
	}
	s.recordExtendedTiming(AssetKey{PacketID: 0xf110}, raw)
	stats := s.report.ExtendedTiming[AssetKey{PacketID: 0xf110}]
	if stats.Invalid != 0 || stats.Entries != 1 || stats.TimestampMatched != 1 || stats.AccessUnits != 2 ||
		stats.Timescales[180000] != 1 || stats.MinPTSInterval != 3840 || stats.MaxPTSInterval != 3840 {
		t.Fatalf("extended timing = %+v", stats)
	}
}

func TestMediaAUDetection(t *testing.T) {
	s := &scanner{
		mediaStats: make(map[AssetKey]*AUValidation), mediaTypes: map[AssetKey]string{AssetKey{PacketID: 0xf100}: "hev1", AssetKey{PacketID: 0xf110}: "mp4a"},
		observedAU: make(map[AssetKey]map[uint32]uint32),
	}
	video := make([]byte, 28)
	binary.BigEndian.PutUint16(video[:2], uint16(len(video)-2))
	video[2] = 0x28
	binary.BigEndian.PutUint32(video[4:8], 7)
	binary.BigEndian.PutUint32(video[22:26], 2)
	video[26] = 35 << 1
	s.processMedia(mmtp.Packet{PacketID: 0xf100, Payload: video})
	if got := s.observedAU[AssetKey{PacketID: 0xf100}][7]; got != 1 {
		t.Fatalf("video AU count = %d", got)
	}

	audio := make([]byte, 23)
	binary.BigEndian.PutUint16(audio[:2], uint16(len(audio)-2))
	audio[2] = 0x28
	binary.BigEndian.PutUint32(audio[4:8], 9)
	s.processMedia(mmtp.Packet{PacketID: 0xf110, Payload: audio})
	if got := s.observedAU[AssetKey{PacketID: 0xf110}][9]; got != 1 {
		t.Fatalf("audio AU count = %d", got)
	}
}

func TestScanUsesSharedTransportAndSignalingParsers(t *testing.T) {
	mpt := []byte{0x00, 0x02, 0x00, 0x66, 0x00, 0x00, 0x01}
	mpt = append(mpt, 0x00, 0, 0, 0, 0, 0x02, 0xf1, 0x00)
	mpt = append(mpt, 'h', 'e', 'v', '1', 0x00, 0x01, 0x00, 0xf1, 0x00)
	mpt = append(mpt, 0x00, 0x05, 0x80, 0x11, 0x02, 0x00, 0x00)
	table := []byte{signaling.TableIDMPTComplete, 1, 0, 0}
	binary.BigEndian.PutUint16(table[2:4], uint16(len(mpt)))
	table = append(table, mpt...)
	body := append([]byte{0}, table...)
	message := binary.BigEndian.AppendUint16(nil, signaling.MessageIDPA)
	message = append(message, 1)
	message = binary.BigEndian.AppendUint32(message, uint32(len(body)))
	message = append(message, body...)

	complete := append([]byte{0, 0}, message...)
	aggregated := []byte{1, 0}
	aggregated = binary.BigEndian.AppendUint16(aggregated, uint16(len(message)))
	aggregated = append(aggregated, message...)

	var input bytes.Buffer
	input.Write(inspectTLV(tlv.TypeCompressedIP, append([]byte{0, 0, 0x61}, inspectMMTP(0, complete)...)))
	input.Write(inspectTLV(tlv.TypeIPv4, inspectIPv4(inspectMMTP(0, aggregated))))
	report, err := Scan(&input)
	if err != nil {
		t.Fatal(err)
	}
	if report.TLVPackets != 2 || report.MMTPPackets != 2 || report.InvalidPackets != 0 {
		t.Fatalf("transport counts = %+v", report)
	}
	if len(report.MPTs) != 1 {
		t.Fatalf("MPT snapshots = %+v", report.MPTs)
	}
	got := report.MPTs[0]
	if got.ServiceID != 0x0066 || len(got.Assets) != 1 || got.Assets[0].PacketID != 0xf100 || got.Assets[0].Type != "hev1" {
		t.Fatalf("MPT = %+v", got)
	}
}

func inspectMMTP(pid uint16, payload []byte) []byte {
	b := make([]byte, 12)
	b[1] = mmtp.PayloadTypeSignaling
	binary.BigEndian.PutUint16(b[2:4], pid)
	return append(b, payload...)
}

func inspectTLV(typ byte, payload []byte) []byte {
	b := []byte{tlv.SyncByte, typ, 0, 0}
	binary.BigEndian.PutUint16(b[2:4], uint16(len(payload)))
	return append(b, payload...)
}

func inspectIPv4(payload []byte) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[2:4], 4000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)+len(payload)))
	udp = append(udp, payload...)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(udp)))
	ip[9] = 17
	return append(ip, udp...)
}
