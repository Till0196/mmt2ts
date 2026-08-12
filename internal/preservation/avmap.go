// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

const (
	MapIncomplete   = 0x0001
	MapRandomAccess = 0x0002
)

type AVMapEntry struct {
	PacketID       uint16
	OutputPID      uint16
	AssetType      [4]byte
	MPUSequence    uint32
	FirstAUOrdinal uint64
	AUCount        uint32
	Flags          uint16
	StartNTP       uint64
	EndNTP         uint64
	AssetID        []byte
}

func EncodeAVMap(entries []AVMapEntry) ([]byte, error) {
	entries = slices.Clone(entries)
	slices.SortStableFunc(entries, compareAVMap)
	out := binary.BigEndian.AppendUint32(nil, uint32(len(entries)))
	for _, e := range entries {
		if len(e.AssetID) > 0xffff {
			return nil, fmt.Errorf("preservation: AV map entry has a %d-byte asset id", len(e.AssetID))
		}
		out = binary.BigEndian.AppendUint16(out, e.PacketID)
		out = binary.BigEndian.AppendUint16(out, e.OutputPID)
		out = append(out, e.AssetType[:]...)
		out = binary.BigEndian.AppendUint32(out, e.MPUSequence)
		out = binary.BigEndian.AppendUint64(out, e.FirstAUOrdinal)
		out = binary.BigEndian.AppendUint32(out, e.AUCount)
		out = binary.BigEndian.AppendUint16(out, e.Flags)
		out = binary.BigEndian.AppendUint16(out, uint16(len(e.AssetID)))
		out = binary.BigEndian.AppendUint64(out, e.StartNTP)
		out = binary.BigEndian.AppendUint64(out, e.EndNTP)
		out = append(out, e.AssetID...)
	}
	return out, nil
}

func compareAVMap(a, b AVMapEntry) int {
	switch {
	case a.StartNTP < b.StartNTP:
		return -1
	case a.StartNTP > b.StartNTP:
		return 1
	case a.OutputPID != b.OutputPID:
		return int(a.OutputPID) - int(b.OutputPID)
	case a.MPUSequence < b.MPUSequence:
		return -1
	case a.MPUSequence > b.MPUSequence:
		return 1
	}
	return 0
}

func ParseAVMap(payload []byte) ([]AVMapEntry, error) {
	r := &reader{b: payload}
	count := int(r.u32())
	if r.err != nil {
		return nil, r.err
	}
	if count > len(payload) {
		return nil, errTruncated
	}
	out := make([]AVMapEntry, 0, count)
	for range count {
		var e AVMapEntry
		e.PacketID = r.u16()
		e.OutputPID = r.u16()
		copy(e.AssetType[:], r.take(4))
		e.MPUSequence = r.u32()
		e.FirstAUOrdinal = r.u64()
		e.AUCount = r.u32()
		e.Flags = r.u16()
		assetLen := int(r.u16())
		e.StartNTP = r.u64()
		e.EndNTP = r.u64()
		e.AssetID = r.bytes(assetLen)
		if r.err != nil {
			return nil, r.err
		}
		out = append(out, e)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	for i := 1; i < len(out); i++ {
		if compareAVMap(out[i-1], out[i]) > 0 {
			return nil, errors.New("preservation: AV map entries are not in start NTP, PID and MPU sequence order")
		}
	}
	return out, nil
}
