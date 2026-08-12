// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type RecordKind byte

const (
	RecordRawSignalling    RecordKind = 0x01
	RecordCAData           RecordKind = 0x02
	RecordGenericTimedData RecordKind = 0x03
	RecordTimelineAnchor   RecordKind = 0x04
	RecordObjectActivation RecordKind = 0x05
	RecordLoss             RecordKind = 0x06
)

func (k RecordKind) String() string {
	switch k {
	case RecordRawSignalling:
		return "RAW_SIGNALLING"
	case RecordCAData:
		return "CA_DATA"
	case RecordGenericTimedData:
		return "GENERIC_TIMED_DATA"
	case RecordTimelineAnchor:
		return "TIMELINE_ANCHOR"
	case RecordObjectActivation:
		return "OBJECT_ACTIVATION"
	case RecordLoss:
		return "LOSS"
	}
	return fmt.Sprintf("record(%#02x)", byte(k))
}

func (k RecordKind) valid() bool {
	return k >= RecordRawSignalling && k <= RecordLoss
}

const (
	RecordRawExact   = 0x01
	RecordIncomplete = 0x02
	RecordRequired   = 0x04

	definedRecordFlags = RecordRawExact | RecordIncomplete | RecordRequired
)

const (
	ClockPresentation = 1
	ClockDecode       = 2
	ClockDelivery     = 3
)

const (
	ActionActivate   = 1
	ActionDeactivate = 2
	ActionReplace    = 3
)

const (
	segmentHeaderLength = 4
	recordHeaderLength  = 20
)

func (r Record) EncodedSize() int {
	return recordHeaderLength + r.Metadata.size() + len(r.Payload)
}

func SegmentSize(records []Record) int {
	n := segmentHeaderLength
	for _, r := range records {
		n += r.EncodedSize()
	}
	return n
}

type Record struct {
	Kind      RecordKind
	Flags     byte
	Order     uint32
	SourceNTP uint64
	Metadata  Metadata
	Payload   []byte
}

type TimelineAnchor struct {
	OutputPID uint16
	ClockKind byte
	PTS90k    uint64
	SourceNTP uint64
	EpochID   uint32
}

func (a TimelineAnchor) Encode() []byte {
	out := binary.BigEndian.AppendUint16(nil, a.OutputPID)
	out = append(out, a.ClockKind, 0)
	out = binary.BigEndian.AppendUint64(out, a.PTS90k)
	out = binary.BigEndian.AppendUint64(out, a.SourceNTP)
	return binary.BigEndian.AppendUint32(out, a.EpochID)
}

func ParseTimelineAnchor(b []byte) (TimelineAnchor, error) {
	r := &reader{b: b}
	a := TimelineAnchor{OutputPID: r.u16(), ClockKind: r.u8()}
	r.skip(1)
	a.PTS90k = r.u64()
	a.SourceNTP = r.u64()
	a.EpochID = r.u32()
	return a, r.done()
}

type ObjectActivation struct {
	ObjectID   uint64
	Generation uint32
	Action     byte
}

const (
	ObjectActivate   = 1
	ObjectDeactivate = 2
	ObjectReplace    = 3
)

func (a ObjectActivation) Encode() []byte {
	out := binary.BigEndian.AppendUint64(nil, a.ObjectID)
	out = binary.BigEndian.AppendUint32(out, a.Generation)
	return append(out, a.Action, 0, 0, 0)
}

func ParseObjectActivation(b []byte) (ObjectActivation, error) {
	r := &reader{b: b}
	a := ObjectActivation{ObjectID: r.u64(), Generation: r.u32(), Action: r.u8()}
	r.skip(3)
	return a, r.done()
}

func EncodeSegment(records []Record) ([]byte, error) {
	if len(records) > 0xffff {
		return nil, fmt.Errorf("%w: %d records in one segment", ErrCapacityExceeded, len(records))
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(records)))
	out = binary.BigEndian.AppendUint16(out, 0)
	for i, rec := range records {
		if !rec.Kind.valid() {
			return nil, fmt.Errorf("preservation: invalid record kind %#02x", byte(rec.Kind))
		}
		if rec.Flags&^definedRecordFlags != 0 {
			return nil, fmt.Errorf("preservation: undefined record flags %#02x", rec.Flags)
		}
		if rec.Order != uint32(i) {
			return nil, fmt.Errorf("preservation: record %d has order %d", i, rec.Order)
		}
		meta, err := rec.Metadata.encode()
		if err != nil {
			return nil, err
		}
		if len(meta) > 0xffff {
			return nil, fmt.Errorf("preservation: record %d has %d metadata bytes", i, len(meta))
		}
		out = append(out, byte(rec.Kind), rec.Flags)
		out = binary.BigEndian.AppendUint16(out, uint16(len(meta)))
		out = binary.BigEndian.AppendUint32(out, uint32(len(rec.Payload)))
		out = binary.BigEndian.AppendUint32(out, rec.Order)
		out = binary.BigEndian.AppendUint64(out, rec.SourceNTP)
		out = append(out, meta...)
		out = append(out, rec.Payload...)
	}
	return out, nil
}

func ParseSegment(payload []byte) ([]Record, error) {
	r := &reader{b: payload}
	count := int(r.u16())
	r.skip(2)
	if r.err != nil {
		return nil, r.err
	}
	out := make([]Record, 0, count)
	for i := range count {
		rec := Record{Kind: RecordKind(r.u8()), Flags: r.u8()}
		metaLen := int(r.u16())
		payloadLen := int64(r.u32())
		rec.Order = r.u32()
		rec.SourceNTP = r.u64()
		meta := r.take(metaLen)
		if payloadLen > int64(len(r.b)) {
			return nil, errTruncated
		}
		rec.Payload = r.bytes(int(payloadLen))
		if r.err != nil {
			return nil, r.err
		}
		m, err := ParseMetadata(meta)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		rec.Metadata = m
		if rec.Order != uint32(i) {
			return nil, errors.New("preservation: segment record order is not consecutive from zero")
		}
		out = append(out, rec)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return out, nil
}
