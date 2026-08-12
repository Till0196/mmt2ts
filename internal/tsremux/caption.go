// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"encoding/binary"
	"io"
	"sort"

	"mmt2ts/internal/preservation"
	"mmt2ts/internal/tsremux/carouselin"
	"mmt2ts/internal/tsremux/mmtwrite"
	"mmt2ts/internal/tsremux/tlvwrite"
)

func BuildCaptionMFU(tag, sequenceNumber, number, lastNumber, dataType byte, data []byte) []byte {
	extended := len(data) > 0xffff
	flags := dataType << 4
	if extended {
		flags |= 0x08
	}
	out := []byte{tag, sequenceNumber, number, lastNumber, flags}
	if extended {
		out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	} else {
		out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	}
	return append(out, data...)
}

type CaptionResource struct {
	ComponentTag   uint16
	MPUSequence    uint32
	Tag            byte
	SequenceNumber byte
	Number         byte
	DataType       byte
	Data           []byte
	Header         []byte
}

func ExtractCaptionResources(st *carouselin.State) ([]CaptionResource, error) {
	if st.Manifest == nil {
		return nil, nil
	}
	var out []CaptionResource
	for _, obj := range st.Manifest.Objects {
		switch obj.Class {
		case preservation.ClassTTML, preservation.ClassImage, preservation.ClassFont, preservation.ClassAudio:
		default:
			continue
		}
		id, ok := metaBytes(obj.Metadata, preservation.MetaSubtitleID, 6)
		if !ok {
			continue
		}
		data, err := carouselin.ResolveObject(st, obj)
		if err != nil {
			return nil, err
		}
		tag, _ := metaU16(obj.Metadata, preservation.MetaComponentTag)
		seq, _ := metaU32(obj.Metadata, preservation.MetaMPUSequence)
		out = append(out, CaptionResource{
			ComponentTag: tag, MPUSequence: seq,
			Tag: id[0], SequenceNumber: id[1], Number: id[2], DataType: id[4],
			Data: data,
		})
	}
	return out, nil
}

type captionGroupKey struct {
	componentTag   uint16
	mpuSequence    uint32
	sequenceNumber byte
}

func ReplayCaptionResources(w io.Writer, resources []CaptionResource,
	packetIDFor func(componentTag uint16) (uint16, bool), seq *mmtwrite.Sequencer,
	src, dst tlvwrite.Endpoint, srcPort, dstPort uint16) error {
	return replayCaptionResourcesAt(w, resources, packetIDFor, seq, src, dst, srcPort, dstPort, 0)
}

func replayCaptionResourcesAt(w io.Writer, resources []CaptionResource,
	packetIDFor func(componentTag uint16) (uint16, bool), seq *mmtwrite.Sequencer,
	src, dst tlvwrite.Endpoint, srcPort, dstPort uint16, ntp uint64) error {
	groups := make(map[captionGroupKey][]CaptionResource)
	for _, r := range resources {
		key := captionGroupKey{r.ComponentTag, r.MPUSequence, r.SequenceNumber}
		groups[key] = append(groups[key], r)
	}
	keys := make([]captionGroupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].mpuSequence != keys[j].mpuSequence {
			return keys[i].mpuSequence < keys[j].mpuSequence
		}
		return keys[i].sequenceNumber < keys[j].sequenceNumber
	})

	for _, key := range keys {
		packetID, ok := packetIDFor(key.componentTag)
		if !ok {
			continue
		}
		group := groups[key]
		sort.Slice(group, func(i, j int) bool { return group[i].Number < group[j].Number })
		last := group[len(group)-1].Number
		firstPacket := true
		for _, r := range group {
			mfu := BuildCaptionMFU(r.Tag, r.SequenceNumber, r.Number, last, r.DataType, r.Data)
			if len(r.Header) > 0 {
				mfu = append(append([]byte(nil), r.Header...), r.Data...)
			}
			for _, mpu := range mmtwrite.BuildTimedMFUFragments(key.mpuSequence, uint32(r.Number), mfu) {
				packet := mmtwrite.BuildPacket(mmtwrite.Header{
					PayloadType: mmtwrite.PayloadTypeMPU, PacketID: packetID, SequenceNumber: seq.Next(packetID),
					Timestamp: mmtwrite.TimestampFromNTP(ntp), RAP: firstPacket,
				}, mpu)
				firstPacket = false
				if err := tlvwrite.WriteUDP(w, src, dst, srcPort, dstPort, packet); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
