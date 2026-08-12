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
	ConfigHEVC          = 1
	ConfigAudioSpecific = 2
	ConfigStreamMux     = 3
	ConfigOther         = 4

	ConfigRawExact = 0x01
)

type CodecConfig struct {
	ConfigID      uint64
	AssetType     [4]byte
	PacketID      uint16
	OutputPID     uint16
	Kind          byte
	Flags         byte
	EffectiveFrom uint64
	AssetID       []byte
	Data          []byte
	SHA256        [32]byte
}

func EncodeCodecConfigs(entries []CodecConfig) ([]byte, error) {
	if len(entries) > 0xffff {
		return nil, fmt.Errorf("%w: %d codec config entries", ErrCapacityExceeded, len(entries))
	}
	entries = slices.Clone(entries)
	slices.SortStableFunc(entries, func(a, b CodecConfig) int {
		switch {
		case a.ConfigID < b.ConfigID:
			return -1
		case a.ConfigID > b.ConfigID:
			return 1
		}
		return 0
	})
	out := binary.BigEndian.AppendUint16(nil, uint16(len(entries)))
	out = binary.BigEndian.AppendUint16(out, 0)
	for _, e := range entries {
		if e.Kind < ConfigHEVC || e.Kind > ConfigOther {
			return nil, fmt.Errorf("preservation: codec config %d has kind %d", e.ConfigID, e.Kind)
		}
		if len(e.AssetID) > 0xffff {
			return nil, fmt.Errorf("preservation: codec config %d has a %d-byte asset id", e.ConfigID, len(e.AssetID))
		}
		out = binary.BigEndian.AppendUint64(out, e.ConfigID)
		out = append(out, e.AssetType[:]...)
		out = binary.BigEndian.AppendUint16(out, e.PacketID)
		out = binary.BigEndian.AppendUint16(out, e.OutputPID)
		out = append(out, e.Kind, e.Flags)
		out = binary.BigEndian.AppendUint16(out, uint16(len(e.AssetID)))
		out = binary.BigEndian.AppendUint64(out, e.EffectiveFrom)
		out = binary.BigEndian.AppendUint32(out, uint32(len(e.Data)))
		out = append(out, e.SHA256[:]...)
		out = append(out, e.AssetID...)
		out = append(out, e.Data...)
	}
	return out, nil
}

func ParseCodecConfigs(payload []byte) ([]CodecConfig, error) {
	r := &reader{b: payload}
	count := int(r.u16())
	r.skip(2)
	if r.err != nil {
		return nil, r.err
	}
	out := make([]CodecConfig, 0, count)
	for range count {
		var e CodecConfig
		e.ConfigID = r.u64()
		copy(e.AssetType[:], r.take(4))
		e.PacketID = r.u16()
		e.OutputPID = r.u16()
		e.Kind = r.u8()
		e.Flags = r.u8()
		assetLen := int(r.u16())
		e.EffectiveFrom = r.u64()
		dataLen := int64(r.u32())
		e.SHA256 = r.sha256()
		e.AssetID = r.bytes(assetLen)
		if r.err != nil {
			return nil, r.err
		}
		if dataLen > int64(len(r.b)) {
			return nil, errTruncated
		}
		e.Data = r.bytes(int(dataLen))
		out = append(out, e)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].ConfigID > out[i].ConfigID {
			return nil, errors.New("preservation: codec config entries are not in config id order")
		}
	}
	return out, nil
}
