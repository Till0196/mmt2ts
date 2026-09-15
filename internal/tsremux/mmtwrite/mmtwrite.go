// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package mmtwrite はメディアとシグナリングをMMTPパケットへ組み立てる。
package mmtwrite

import "encoding/binary"

const (
	PayloadTypeMPU       = 0x00
	PayloadTypeSignaling = 0x02
)

type Header struct {
	PayloadType    byte
	PacketID       uint16
	Timestamp      uint32
	SequenceNumber uint32
	PacketCounter  uint32
	HasCounter     bool
	RAP            bool
	ExtensionType  uint16
	Extension      []byte
}

type Sequencer struct {
	next [1 << 16]uint32
}

func NewSequencer() *Sequencer {
	return &Sequencer{}
}

func (s *Sequencer) Next(pid uint16) uint32 {
	n := s.next[pid]
	s.next[pid] = n + 1
	return n
}

func (s *Sequencer) Skip(pid uint16, n uint32) { s.next[pid] += n }

func (s *Sequencer) ObserveRaw(pid uint16, sequence uint32) { s.next[pid] = sequence + 1 }

func TimestampFromNTP(ntp uint64) uint32 { return uint32(ntp >> 16) }

func BuildPacket(h Header, payload []byte) []byte {
	out := make([]byte, 0, 20+len(h.Extension)+len(payload))
	return append(AppendPacketHeader(out, h), payload...)
}

func AppendPacketHeader(dst []byte, h Header) []byte {
	b0 := byte(0x04)
	if h.HasCounter {
		b0 |= 0x20
	}
	if h.RAP {
		b0 |= 0x01
	}
	if len(h.Extension) != 0 {
		b0 |= 0x02
	}
	out := append(dst, b0, 0xc0|h.PayloadType&0x3f)
	out = binary.BigEndian.AppendUint16(out, h.PacketID)
	out = binary.BigEndian.AppendUint32(out, h.Timestamp)
	out = binary.BigEndian.AppendUint32(out, h.SequenceNumber)
	if h.HasCounter {
		out = binary.BigEndian.AppendUint32(out, h.PacketCounter)
	}
	if len(h.Extension) != 0 {
		out = binary.BigEndian.AppendUint16(out, h.ExtensionType)
		out = binary.BigEndian.AppendUint16(out, uint16(len(h.Extension)))
		out = append(out, h.Extension...)
	}
	return out
}

var ClearScrambleExtension = []byte{0x80, 0x01, 0x00, 0x01, 0xe0}

const (
	fragmentTypeMFU  = 2
	timedFlag        = 0x08
	mpuPayloadHeader = 8
	timedMFUHeader   = 14

	fragIndicatorComplete = 0
	fragIndicatorFirst    = 1
	fragIndicatorMiddle   = 2
	fragIndicatorLast     = 3

	MaxFragmentPayload = 1400
)

func BuildTimedMFU(mpuSequence, sampleNumber uint32, data []byte) []byte {
	return timedMFUPayload(mpuSequence, sampleNumber, fragIndicatorComplete, 0, data)
}

func BuildTimedMFUFragments(mpuSequence, sampleNumber uint32, data []byte) [][]byte {
	out := make([][]byte, 0, (len(data)+MaxFragmentPayload-1)/MaxFragmentPayload)
	ForEachTimedMFUFragment(data, func(f TimedMFUFragment) error {
		out = append(out, timedMFUPayload(mpuSequence, sampleNumber, f.Indicator, f.Offset, f.Data))
		return nil
	})
	return out
}

func timedMFUPayload(mpuSequence, sampleNumber uint32, indicator byte, offset uint32, data []byte) []byte {
	out := make([]byte, 0, mpuPayloadHeader+timedMFUHeader+len(data))
	out = AppendTimedMFUHeader(out, mpuSequence, sampleNumber, indicator, offset, len(data))
	return append(out, data...)
}

func AppendTimedMFUHeader(dst []byte, mpuSequence, sampleNumber uint32, indicator byte, offset uint32, dataLen int) []byte {
	flags := byte(fragmentTypeMFU<<4) | timedFlag | indicator<<1
	out := binary.BigEndian.AppendUint16(dst, uint16(mpuPayloadHeader-2+timedMFUHeader+dataLen))
	out = append(out, flags, 0)
	out = binary.BigEndian.AppendUint32(out, mpuSequence)
	out = binary.BigEndian.AppendUint32(out, 0)
	out = binary.BigEndian.AppendUint32(out, sampleNumber)
	out = binary.BigEndian.AppendUint32(out, offset)
	return append(out, 0, 0)
}

type TimedMFUFragment struct {
	Indicator byte
	Offset    uint32
	Data      []byte
}

func ForEachTimedMFUFragment(data []byte, fn func(f TimedMFUFragment) error) error {
	if len(data) <= MaxFragmentPayload {
		return fn(TimedMFUFragment{Indicator: fragIndicatorComplete, Data: data})
	}
	for offset := 0; offset < len(data); {
		n := min(MaxFragmentPayload, len(data)-offset)
		var indicator byte
		switch {
		case offset == 0:
			indicator = fragIndicatorFirst
		case offset+n == len(data):
			indicator = fragIndicatorLast
		default:
			indicator = fragIndicatorMiddle
		}
		if err := fn(TimedMFUFragment{Indicator: indicator, Offset: uint32(offset), Data: data[offset : offset+n]}); err != nil {
			return err
		}
		offset += n
	}
	return nil
}

func BuildNonTimedMFU(mpuSequence, itemID uint32, data []byte) []byte {
	flags := byte(fragmentTypeMFU << 4)
	rest := make([]byte, 0, mpuPayloadHeader-2+4+len(data))
	rest = append(rest, flags, 0)
	rest = binary.BigEndian.AppendUint32(rest, mpuSequence)
	rest = binary.BigEndian.AppendUint32(rest, itemID)
	rest = append(rest, data...)

	out := make([]byte, 0, 2+len(rest))
	out = binary.BigEndian.AppendUint16(out, uint16(len(rest)))
	return append(out, rest...)
}

func BuildNonTimedMFUFragments(mpuSequence, itemID uint32, data []byte) [][]byte {
	if len(data) <= MaxFragmentPayload {
		return [][]byte{BuildNonTimedMFU(mpuSequence, itemID, data)}
	}
	out := make([][]byte, 0, (len(data)+MaxFragmentPayload-1)/MaxFragmentPayload)
	for len(data) > 0 {
		n := min(MaxFragmentPayload, len(data))
		out = append(out, BuildNonTimedMFU(mpuSequence, itemID, data[:n]))
		data = data[n:]
	}
	return out
}

func WrapSignalling(message []byte) []byte {
	out := make([]byte, 0, 2+len(message))
	out = append(out, 0x3c, 0x00)
	return append(out, message...)
}
