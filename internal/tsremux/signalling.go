// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"encoding/binary"
	"io"

	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/tsremux/mmtwrite"
	"mmt2ts/internal/tsremux/tlvwrite"
)

func ReplaySignalling(w io.Writer, records []preservation.Record, seq *mmtwrite.Sequencer) error {
	for _, rec := range records {
		switch rec.Kind {
		case preservation.RecordRawSignalling, preservation.RecordCAData:
			if err := replaySignallingRecord(w, rec, seq); err != nil {
				return err
			}
		}
	}
	return nil
}

func replaySignallingRecord(w io.Writer, rec preservation.Record, seq *mmtwrite.Sequencer) error {
	return replaySignallingRecordAt(w, rec, seq, nil, nil, 0, 0)
}

func replaySignallingRecordAt(w io.Writer, rec preservation.Record, seq *mmtwrite.Sequencer,
	defaultSrc, defaultDst tlvwrite.Endpoint, defaultSrcPort, defaultDstPort uint16) error {
	kind, ok := metaU8(rec.Metadata, preservation.MetaSignallingKind)
	if !ok {
		return nil
	}
	src, dst := metaIP(rec.Metadata, preservation.MetaIPSource), metaIP(rec.Metadata, preservation.MetaIPDestination)
	srcPort, _ := metaU16(rec.Metadata, preservation.MetaUDPSourcePort)
	dstPort, _ := metaU16(rec.Metadata, preservation.MetaUDPDestPort)
	if len(src) == 0 {
		src = defaultSrc
	}
	if len(dst) == 0 {
		dst = defaultDst
	}
	if srcPort == 0 {
		srcPort = defaultSrcPort
	}
	if dstPort == 0 {
		dstPort = defaultDstPort
	}

	switch kind {
	case preservation.SignallingTLVSI:
		return tlvwrite.WriteControl(w, rec.Payload)
	case preservation.SignallingNTP:
		return tlvwrite.WriteUncompressedUDP(w, src, dst, srcPort, dstPort, rec.Payload)
	case preservation.SignallingPA, preservation.SignallingM2Section,
		preservation.SignallingCA, preservation.SignallingDataTransmission:
		packetID, _ := metaU16(rec.Metadata, preservation.MetaPacketID)
		packet := mmtwrite.BuildPacket(mmtwrite.Header{
			PayloadType:    mmtwrite.PayloadTypeSignaling,
			PacketID:       packetID,
			SequenceNumber: seq.Next(packetID),
			Timestamp:      mmtwrite.TimestampFromNTP(rec.SourceNTP),
		}, mmtwrite.WrapSignalling(rec.Payload))
		return tlvwrite.WriteUDP(w, src, dst, srcPort, dstPort, packet)
	}
	return nil
}

func ReplayGenericTimedData(w io.Writer, records []preservation.Record, seq *mmtwrite.Sequencer) error {
	for _, rec := range records {
		if rec.Kind != preservation.RecordGenericTimedData {
			continue
		}
		if err := replayGenericRecord(w, rec, seq); err != nil {
			return err
		}
	}
	return nil
}

func replayGenericRecord(w io.Writer, rec preservation.Record, seq *mmtwrite.Sequencer) error {
	return replayGenericRecordAt(w, rec, seq, nil, nil, 0, 0)
}

func replayGenericRecordAt(w io.Writer, rec preservation.Record, seq *mmtwrite.Sequencer,
	defaultSrc, defaultDst tlvwrite.Endpoint, defaultSrcPort, defaultDstPort uint16) error {
	src, dst := metaIP(rec.Metadata, preservation.MetaIPSource), metaIP(rec.Metadata, preservation.MetaIPDestination)
	srcPort, _ := metaU16(rec.Metadata, preservation.MetaUDPSourcePort)
	dstPort, _ := metaU16(rec.Metadata, preservation.MetaUDPDestPort)
	if len(src) == 0 {
		src = defaultSrc
	}
	if len(dst) == 0 {
		dst = defaultDst
	}
	if srcPort == 0 {
		srcPort = defaultSrcPort
	}
	if dstPort == 0 {
		dstPort = defaultDstPort
	}

	if mediaType, ok := metaText(rec.Metadata, preservation.MetaMediaType); ok && mediaType == "application/mmtp" {
		m, err := mmtp.Parse(rec.Payload)
		if err != nil {
			return err
		}
		if err := tlvwrite.WriteUDP(w, src, dst, srcPort, dstPort, rec.Payload); err != nil {
			return err
		}
		seq.ObserveRaw(m.PacketID, m.SequenceNumber)
		return nil
	}
	packetID, _ := metaU16(rec.Metadata, preservation.MetaPacketID)
	packet := mmtwrite.BuildPacket(mmtwrite.Header{
		PayloadType:    mmtwrite.PayloadTypeMPU,
		PacketID:       packetID,
		SequenceNumber: seq.Next(packetID),
		Timestamp:      mmtwrite.TimestampFromNTP(rec.SourceNTP),
	}, rec.Payload)
	return tlvwrite.WriteUDP(w, src, dst, srcPort, dstPort, packet)
}

func metaU8(m preservation.Metadata, t preservation.MetaType) (byte, bool) {
	for _, e := range m {
		if e.Type == t && len(e.Value) == 1 {
			return e.Value[0], true
		}
	}
	return 0, false
}

func metaU16(m preservation.Metadata, t preservation.MetaType) (uint16, bool) {
	for _, e := range m {
		if e.Type == t && len(e.Value) == 2 {
			return binary.BigEndian.Uint16(e.Value), true
		}
	}
	return 0, false
}

func metaU32(m preservation.Metadata, t preservation.MetaType) (uint32, bool) {
	for _, e := range m {
		if e.Type == t && len(e.Value) == 4 {
			return binary.BigEndian.Uint32(e.Value), true
		}
	}
	return 0, false
}

func metaBytes(m preservation.Metadata, t preservation.MetaType, n int) ([]byte, bool) {
	for _, e := range m {
		if e.Type == t && len(e.Value) == n {
			return e.Value, true
		}
	}
	return nil, false
}

func metaText(m preservation.Metadata, t preservation.MetaType) (string, bool) {
	for _, e := range m {
		if e.Type == t {
			return string(e.Value), true
		}
	}
	return "", false
}

func metaIP(m preservation.Metadata, t preservation.MetaType) tlvwrite.Endpoint {
	for _, e := range m {
		if e.Type == t && (len(e.Value) == 4 || len(e.Value) == 16) {
			return tlvwrite.Endpoint(e.Value)
		}
	}
	return nil
}
