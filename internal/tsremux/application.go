// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"io"

	"mmt2ts/internal/preservation"
	"mmt2ts/internal/tsremux/carouselin"
	"mmt2ts/internal/tsremux/mmtwrite"
	"mmt2ts/internal/tsremux/tlvwrite"
)

type ApplicationItem struct {
	ID          uint32
	MPUSequence uint32
	Data        []byte
}

func ExtractApplicationItems(st *carouselin.State) ([]ApplicationItem, error) {
	if st.Manifest == nil {
		return nil, nil
	}
	var out []ApplicationItem
	for _, obj := range st.Manifest.Objects {
		if obj.Class != preservation.ClassApplicationItem {
			continue
		}
		id, ok := metaU32(obj.Metadata, preservation.MetaItemID)
		if !ok {
			continue
		}
		data, err := carouselin.ResolveObject(st, obj)
		if err != nil {
			return nil, err
		}
		mpuSequence, _ := metaU32(obj.Metadata, preservation.MetaMPUSequence)
		out = append(out, ApplicationItem{ID: id, MPUSequence: mpuSequence, Data: data})
	}
	return out, nil
}

func ReplayApplicationItems(w io.Writer, items []ApplicationItem, packetID uint16, seq *mmtwrite.Sequencer,
	src, dst tlvwrite.Endpoint, srcPort, dstPort uint16) error {
	return replayApplicationItemsAt(w, items, packetID, seq, src, dst, srcPort, dstPort, 0)
}

func replayApplicationItemsAt(w io.Writer, items []ApplicationItem, packetID uint16, seq *mmtwrite.Sequencer,
	src, dst tlvwrite.Endpoint, srcPort, dstPort uint16, ntp uint64) error {
	for i, it := range items {
		mpuSequence := it.MPUSequence
		if mpuSequence == 0 && i > 0 {
			mpuSequence = uint32(i)
		}
		for _, mpu := range mmtwrite.BuildNonTimedMFUFragments(mpuSequence, it.ID, it.Data) {
			packet := mmtwrite.BuildPacket(mmtwrite.Header{
				PayloadType: mmtwrite.PayloadTypeMPU, PacketID: packetID, SequenceNumber: seq.Next(packetID),
				Timestamp: mmtwrite.TimestampFromNTP(ntp),
			}, mpu)
			if err := tlvwrite.WriteUDP(w, src, dst, srcPort, dstPort, packet); err != nil {
				return err
			}
		}
	}
	return nil
}
