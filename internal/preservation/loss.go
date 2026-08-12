// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"encoding/binary"
	"fmt"
)

const (
	ScopeSegment    = 1
	ScopeSignalling = 2
	ScopeObject     = 3
	ScopeAVMPU      = 4
	ScopeCarousel   = 5
)

const (
	ReasonInputMissing        = 1
	ReasonInvalidSyntax       = 2
	ReasonEncrypted           = 3
	ReasonExternalUnavailable = 4
	ReasonCapacityExceeded    = 5
	ReasonReferenceUnresolved = 6
	ReasonConversionFailed    = 7
)

const (
	SeverityInformational = 1
	SeverityPartial       = 2
	SeverityUnrecoverable = 3
)

type LossEntry struct {
	Scope        byte
	Reason       byte
	Severity     byte
	Flags        byte
	EpochID      uint32
	LogicalID    uint64
	StartNTP     uint64
	EndNTP       uint64
	InputOffset  uint64
	ExpectedSize uint64
	ReceivedSize uint64
	Message      string
	Metadata     Metadata
}

func (e LossEntry) Encode() ([]byte, error) {
	if e.Scope < ScopeSegment || e.Scope > ScopeCarousel {
		return nil, fmt.Errorf("preservation: loss scope %d", e.Scope)
	}
	if e.Reason < ReasonInputMissing || e.Reason > ReasonConversionFailed {
		return nil, fmt.Errorf("preservation: loss reason %d", e.Reason)
	}
	if e.Severity < SeverityInformational || e.Severity > SeverityUnrecoverable {
		return nil, fmt.Errorf("preservation: loss severity %d", e.Severity)
	}
	if e.Flags != 0 {
		return nil, fmt.Errorf("preservation: version 1 loss flags must be 0, got %#02x", e.Flags)
	}
	meta, err := e.Metadata.encode()
	if err != nil {
		return nil, err
	}
	if len(e.Message) > 0xffff || len(meta) > 0xffff {
		return nil, fmt.Errorf("preservation: loss entry message or metadata does not fit its length")
	}
	out := []byte{e.Scope, e.Reason, e.Severity, e.Flags}
	out = binary.BigEndian.AppendUint32(out, e.EpochID)
	out = binary.BigEndian.AppendUint64(out, e.LogicalID)
	out = binary.BigEndian.AppendUint64(out, e.StartNTP)
	out = binary.BigEndian.AppendUint64(out, e.EndNTP)
	out = binary.BigEndian.AppendUint64(out, e.InputOffset)
	out = binary.BigEndian.AppendUint64(out, e.ExpectedSize)
	out = binary.BigEndian.AppendUint64(out, e.ReceivedSize)
	out = binary.BigEndian.AppendUint16(out, uint16(len(e.Message)))
	out = binary.BigEndian.AppendUint16(out, uint16(len(meta)))
	out = append(out, e.Message...)
	return append(out, meta...), nil
}

func (e *LossEntry) decode(r *reader) {
	e.Scope = r.u8()
	e.Reason = r.u8()
	e.Severity = r.u8()
	e.Flags = r.u8()
	e.EpochID = r.u32()
	e.LogicalID = r.u64()
	e.StartNTP = r.u64()
	e.EndNTP = r.u64()
	e.InputOffset = r.u64()
	e.ExpectedSize = r.u64()
	e.ReceivedSize = r.u64()
	msgLen := int(r.u16())
	metaLen := int(r.u16())
	e.Message = r.text(msgLen)
	meta := r.take(metaLen)
	if r.err != nil {
		return
	}
	m, err := ParseMetadata(meta)
	if err != nil {
		r.err = err
		return
	}
	e.Metadata = m
}

func ParseLossEntry(b []byte) (LossEntry, error) {
	r := &reader{b: b}
	var e LossEntry
	e.decode(r)
	return e, r.done()
}

func EncodeLossReport(entries []LossEntry) ([]byte, error) {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(entries)))
	for _, e := range entries {
		b, err := e.Encode()
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

func ParseLossReport(payload []byte) ([]LossEntry, error) {
	r := &reader{b: payload}
	count := int(r.u32())
	if r.err != nil {
		return nil, r.err
	}
	if count > len(payload) {
		return nil, errTruncated
	}
	out := make([]LossEntry, 0, count)
	for range count {
		var e LossEntry
		e.decode(r)
		if r.err != nil {
			return nil, r.err
		}
		out = append(out, e)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return out, nil
}
