// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"fmt"
	"io"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/tsremux/codecrev"
	"mmt2ts/internal/tsremux/mmtwrite"
	"mmt2ts/internal/tsremux/tlvwrite"
)

func ReplayAV(w io.Writer, entry preservation.AVMapEntry, streamType byte, aus [][]byte, seq *mmtwrite.Sequencer, src, dst tlvwrite.Endpoint, srcPort, dstPort uint16) error {
	flow := generalFlow{cid: tlvwrite.DefaultCID, src: src, dst: dst, srcPort: srcPort, dstPort: dstPort}
	return replayAV(w, entry, streamType, aus, seq, flow, true)
}

func writeHEVCAdmission(w io.Writer, entry preservation.AVMapEntry, annexB []byte, seq *mmtwrite.Sequencer,
	flow generalFlow) error {
	samples, err := codecrev.AnnexBToNALSamples(annexB)
	if err != nil {
		return fmt.Errorf("tsremux: HEVC admission NAL: %w", err)
	}
	if len(samples) != 1 {
		return fmt.Errorf("tsremux: HEVC admission contains %d NAL units", len(samples))
	}
	mpu := mmtwrite.BuildTimedMFU(entry.MPUSequence, 0, samples[0])
	packet := mmtwrite.BuildPacket(mmtwrite.Header{
		PayloadType: mmtwrite.PayloadTypeMPU, PacketID: entry.PacketID,
		SequenceNumber: seq.Next(entry.PacketID), Timestamp: mmtwrite.TimestampFromNTP(entry.StartNTP),
		ExtensionType: 0, Extension: mmtwrite.ClearScrambleExtension,
	}, mpu)
	return flow.write(w, packet)
}

func replayAV(w io.Writer, entry preservation.AVMapEntry, streamType byte, aus [][]byte, seq *mmtwrite.Sequencer, flow generalFlow, rap bool) error {
	rapPending := rap
	var header []byte
	write := func(sample []byte, media bool) error {
		fragmentIndex := 0
		return mmtwrite.ForEachTimedMFUFragment(sample, func(f mmtwrite.TimedMFUFragment) error {
			header = mmtwrite.AppendPacketHeader(header[:0], mmtwrite.Header{
				PayloadType:    mmtwrite.PayloadTypeMPU,
				PacketID:       entry.PacketID,
				SequenceNumber: seq.Next(entry.PacketID),
				Timestamp:      mmtwrite.TimestampFromNTP(entry.StartNTP),
				RAP:            media && fragmentIndex == 0 && rapPending,
				ExtensionType:  0,
				Extension:      mmtwrite.ClearScrambleExtension,
			})
			// 放送の fragment offset は 0。
			header = mmtwrite.AppendTimedMFUHeader(header, entry.MPUSequence, 0, f.Indicator, 0, len(f.Data))
			fragmentIndex++
			if media {
				rapPending = false
			}
			return flow.writeParts(w, header, f.Data)
		})
	}

	switch streamType {
	case mpegts.StreamTypeHEVC:
		for _, au := range aus {
			samples, err := codecrev.AnnexBToNALSamples(au)
			if err != nil {
				return fmt.Errorf("tsremux: HEVC access unit: %w", err)
			}
			for _, sample := range samples {
				if err := write(sample, true); err != nil {
					return err
				}
			}
		}
	case mpegts.StreamTypeADTSAAC:
		for _, au := range aus {
			infos, raws, err := codecrev.SplitADTS(au)
			if err != nil {
				return fmt.Errorf("tsremux: ADTS access unit: %w", err)
			}
			for i, raw := range raws {
				ame, err := codecrev.BuildAudioMuxElement(infos[i], raw)
				if err != nil {
					return fmt.Errorf("tsremux: AudioMuxElement: %w", err)
				}
				if err := write(ame, true); err != nil {
					return err
				}
			}
		}
	case mpegts.StreamTypeLATMAAC:
		for _, au := range aus {
			ame, err := codecrev.StripLOAS(au)
			if err != nil {
				return fmt.Errorf("tsremux: LOAS access unit: %w", err)
			}
			if err := write(ame, true); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("tsremux: unsupported AV stream type %#02x", streamType)
	}
	return nil
}
