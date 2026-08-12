// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package mmtp はMMTPヘッダを読み、メディアとシグナリングを取り出す。
package mmtp

import (
	"encoding/binary"
	"errors"
)

const (
	PayloadTypeMPU       = 0x00
	PayloadTypeSignaling = 0x02
	PayloadTypeRepair    = 0x03

	FragmentTypeMPUMetadata      = 0
	FragmentTypeMovieFragmentMD  = 1
	FragmentTypeMFU              = 2
	FragmentIndicatorComplete    = 0
	FragmentIndicatorFirst       = 1
	FragmentIndicatorMiddle      = 2
	FragmentIndicatorLast        = 3
	extensionTypeMultiType       = 0x0000
	headerExtensionTypeScramble  = 0x0001
	headerExtensionTypeDownload  = 0x0002
	minMMTPHeaderLength          = 12
	mpuPayloadHeaderLength       = 8
	timedMFUHeaderLength         = 14
	aggregatedUnitLengthPrefixSz = 2
)

var (
	ErrShortPacket  = errors.New("mmtp: packet shorter than header")
	ErrShortPayload = errors.New("mmtp: payload shorter than declared length")
	ErrBadExtension = errors.New("mmtp: malformed header extension")
	ErrBadFEC       = errors.New("mmtp: inconsistent or reserved AL-FEC fields")
)

type Packet struct {
	Version        byte
	FECType        byte
	RAP            bool
	PayloadType    byte
	PacketID       uint16
	Timestamp      uint32
	SequenceNumber uint32
	PacketCounter  uint32
	HasCounter     bool
	Extension      []byte
	Payload        []byte
	Scrambled      bool
	ExtensionType  uint16
}

func Parse(b []byte) (Packet, error) {
	if len(b) < minMMTPHeaderLength {
		return Packet{}, ErrShortPacket
	}
	p := Packet{
		Version:        b[0] >> 6,
		HasCounter:     b[0]&0x20 != 0,
		FECType:        (b[0] >> 3) & 0x03,
		RAP:            b[0]&0x01 != 0,
		PayloadType:    b[1] & 0x3f,
		PacketID:       binary.BigEndian.Uint16(b[2:4]),
		Timestamp:      binary.BigEndian.Uint32(b[4:8]),
		SequenceNumber: binary.BigEndian.Uint32(b[8:12]),
	}
	extensionFlag := b[0]&0x02 != 0
	off := minMMTPHeaderLength
	if p.HasCounter {
		if len(b)-off < 4 {
			return Packet{}, ErrShortPacket
		}
		p.PacketCounter = binary.BigEndian.Uint32(b[off : off+4])
		off += 4
	}
	if extensionFlag {
		if len(b)-off < 4 {
			return Packet{}, ErrBadExtension
		}
		p.ExtensionType = binary.BigEndian.Uint16(b[off : off+2])
		extLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if len(b)-off < extLen {
			return Packet{}, ErrBadExtension
		}
		p.Extension = b[off : off+extLen]
		off += extLen
		if p.ExtensionType == extensionTypeMultiType {
			p.Scrambled = hasScrambleExtension(p.Extension)
		}
	}
	p.Payload = b[off:]
	if p.FECType == 3 || (p.FECType == 2) != (p.PayloadType == PayloadTypeRepair) {
		return Packet{}, ErrBadFEC
	}
	return p, nil
}

func hasScrambleExtension(ext []byte) bool {
	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext[:2]) & 0x7fff
		end := ext[0]&0x80 != 0
		length := int(binary.BigEndian.Uint16(ext[2:4]))
		if len(ext)-4 < length {
			return false
		}
		if typ == headerExtensionTypeScramble {
			return length >= 1 && ext[4]&0x1f != 0
		}
		if end {
			return false
		}
		ext = ext[4+length:]
	}
	return false
}

type DataUnit struct {
	MovieFragment     uint32
	Sample            uint32
	Offset            uint32
	Priority          byte
	DependencyCounter byte
	Data              []byte
}

type MPUPayload struct {
	FragmentType  byte
	Timed         bool
	Fragmentation byte
	Aggregation   bool
	Counter       byte
	MPUSequence   uint32
	Units         []DataUnit
	Untimed       [][]byte
}

func ParseMPU(b []byte, units []DataUnit) (MPUPayload, error) {
	if len(b) < mpuPayloadHeaderLength {
		return MPUPayload{}, ErrShortPayload
	}
	length := int(binary.BigEndian.Uint16(b[:2]))
	if length > len(b)-2 || length < mpuPayloadHeaderLength-2 {
		return MPUPayload{}, ErrShortPayload
	}
	b = b[:2+length]
	flags := b[2]
	out := MPUPayload{
		FragmentType:  flags >> 4,
		Timed:         flags&0x08 != 0,
		Fragmentation: (flags >> 1) & 0x03,
		Aggregation:   flags&0x01 != 0,
		Counter:       b[3],
		MPUSequence:   binary.BigEndian.Uint32(b[4:8]),
		Units:         units[:0],
	}
	body := b[mpuPayloadHeaderLength:]
	if !out.Aggregation {
		unit, err := parseUnit(body, out.Timed)
		if err != nil {
			return out, err
		}
		out.Units = append(out.Units, unit)
		return out, nil
	}
	for len(body) > 0 {
		if len(body) < aggregatedUnitLengthPrefixSz {
			return out, ErrShortPayload
		}
		unitLen := int(binary.BigEndian.Uint16(body[:2]))
		body = body[2:]
		if unitLen > len(body) {
			return out, ErrShortPayload
		}
		unit, err := parseUnit(body[:unitLen], out.Timed)
		if err != nil {
			return out, err
		}
		out.Units = append(out.Units, unit)
		body = body[unitLen:]
	}
	return out, nil
}

func parseUnit(b []byte, timed bool) (DataUnit, error) {
	if !timed {
		if len(b) < 4 {
			return DataUnit{}, ErrShortPayload
		}
		return DataUnit{Sample: binary.BigEndian.Uint32(b[:4]), Data: b[4:]}, nil
	}
	if len(b) < timedMFUHeaderLength {
		return DataUnit{}, ErrShortPayload
	}
	return DataUnit{
		MovieFragment:     binary.BigEndian.Uint32(b[0:4]),
		Sample:            binary.BigEndian.Uint32(b[4:8]),
		Offset:            binary.BigEndian.Uint32(b[8:12]),
		Priority:          b[12],
		DependencyCounter: b[13],
		Data:              b[timedMFUHeaderLength:],
	}, nil
}
