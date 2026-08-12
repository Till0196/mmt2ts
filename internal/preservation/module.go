// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package preservation はTSで表現できないMMT情報を復元用カルーセルへ保存する。
package preservation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

const (
	Magic        = "MMTC"
	MajorVersion = 1
	HeaderLength = 48
)

type Kind byte

const (
	KindBootstrapManifest Kind = 0x01
	KindTimedSegment      Kind = 0x02
	KindStaticObject      Kind = 0x03
	KindObjectManifest    Kind = 0x04
	KindCodecConfig       Kind = 0x05
	KindAVMPUMap          Kind = 0x06
	KindLossReport        Kind = 0x07
)

func (k Kind) String() string {
	switch k {
	case KindBootstrapManifest:
		return "BOOTSTRAP_MANIFEST"
	case KindTimedSegment:
		return "TIMED_SEGMENT"
	case KindStaticObject:
		return "STATIC_OBJECT"
	case KindObjectManifest:
		return "OBJECT_MANIFEST"
	case KindCodecConfig:
		return "CODEC_CONFIG"
	case KindAVMPUMap:
		return "AV_MPU_MAP"
	case KindLossReport:
		return "LOSS_REPORT"
	}
	return fmt.Sprintf("kind(%#02x)", byte(k))
}

func (k Kind) valid() bool {
	return k >= KindBootstrapManifest && k <= KindLossReport
}

const (
	FlagIncomplete = 0x0001
	FlagRawExact   = 0x0002
	FlagCommit     = 0x0004

	definedFlags = FlagIncomplete | FlagRawExact | FlagCommit
)

const ObjectEpoch = 0xffffffff

type Header struct {
	Kind       Kind
	Flags      uint16
	EpochID    uint32
	LogicalID  uint64
	StartNTP   uint64
	DurationMS uint32
}

var (
	errShortHeader   = errors.New("preservation: module shorter than the common header")
	errBadMagic      = errors.New("preservation: module magic is not MMTC")
	errBadVersion    = errors.New("preservation: unsupported module major version")
	errBadHeaderLen  = errors.New("preservation: unexpected header_length")
	errHeaderCRC     = errors.New("preservation: module header CRC mismatch")
	errPayloadCRC    = errors.New("preservation: module payload CRC mismatch")
	errPayloadLength = errors.New("preservation: module payload length does not match the module")
)

func checksum(b []byte) uint32 { return crc32.ChecksumIEEE(b) }

func (h Header) validate() error {
	if !h.Kind.valid() {
		return fmt.Errorf("preservation: invalid module kind %#02x", byte(h.Kind))
	}
	if h.Flags&^definedFlags != 0 {
		return fmt.Errorf("preservation: undefined module flags %#04x", h.Flags)
	}
	if h.Flags&FlagCommit != 0 && h.Kind != KindObjectManifest {
		return fmt.Errorf("preservation: commit flag on %s", h.Kind)
	}
	if h.Flags&FlagCommit != 0 && h.Flags&FlagIncomplete != 0 {
		return errors.New("preservation: commit and incomplete flags are mutually exclusive")
	}
	return nil
}

func BuildModule(h Header, payload []byte) ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	if len(payload) > MaxModuleSize-HeaderLength {
		return nil, fmt.Errorf("%w: %d payload bytes", ErrCapacityExceeded, len(payload))
	}
	out := make([]byte, HeaderLength, HeaderLength+len(payload))
	copy(out, Magic)
	out[4] = MajorVersion
	out[5] = byte(h.Kind)
	binary.BigEndian.PutUint16(out[6:8], h.Flags)
	binary.BigEndian.PutUint32(out[8:12], h.EpochID)
	binary.BigEndian.PutUint16(out[12:14], HeaderLength)
	binary.BigEndian.PutUint64(out[16:24], h.LogicalID)
	binary.BigEndian.PutUint64(out[24:32], h.StartNTP)
	binary.BigEndian.PutUint32(out[32:36], h.DurationMS)
	binary.BigEndian.PutUint32(out[36:40], uint32(len(payload)))
	binary.BigEndian.PutUint32(out[40:44], checksum(payload))
	binary.BigEndian.PutUint32(out[44:48], checksum(out[:HeaderLength]))
	return append(out, payload...), nil
}

func ParseModule(module []byte) (Header, []byte, error) {
	var h Header
	if len(module) < HeaderLength {
		return h, nil, errShortHeader
	}
	if string(module[:4]) != Magic {
		return h, nil, errBadMagic
	}
	if module[4] != MajorVersion {
		return h, nil, fmt.Errorf("%w: %d", errBadVersion, module[4])
	}
	if got := binary.BigEndian.Uint16(module[12:14]); got != HeaderLength {
		return h, nil, fmt.Errorf("%w: %d", errBadHeaderLen, got)
	}
	var zeroed [HeaderLength]byte
	copy(zeroed[:], module[:HeaderLength])
	binary.BigEndian.PutUint32(zeroed[44:48], 0)
	if checksum(zeroed[:]) != binary.BigEndian.Uint32(module[44:48]) {
		return h, nil, errHeaderCRC
	}

	h = Header{
		Kind:       Kind(module[5]),
		Flags:      binary.BigEndian.Uint16(module[6:8]),
		EpochID:    binary.BigEndian.Uint32(module[8:12]),
		LogicalID:  binary.BigEndian.Uint64(module[16:24]),
		StartNTP:   binary.BigEndian.Uint64(module[24:32]),
		DurationMS: binary.BigEndian.Uint32(module[32:36]),
	}
	length := binary.BigEndian.Uint32(module[36:40])
	if uint64(HeaderLength)+uint64(length) != uint64(len(module)) {
		return h, nil, fmt.Errorf("%w: header says %d, module has %d", errPayloadLength, length, len(module)-HeaderLength)
	}
	payload := module[HeaderLength:]
	if checksum(payload) != binary.BigEndian.Uint32(module[40:44]) {
		return h, nil, errPayloadCRC
	}
	return h, payload, nil
}
