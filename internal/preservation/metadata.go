// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"encoding/binary"
	"fmt"
)

type MetaType uint16

const (
	MetaPacketID         MetaType = 0x0001
	MetaPacketSequence   MetaType = 0x0002
	MetaPacketCounter    MetaType = 0x0003
	MetaAssetType        MetaType = 0x0004
	MetaAssetIDScheme    MetaType = 0x0005
	MetaAssetID          MetaType = 0x0006
	MetaComponentTag     MetaType = 0x0007
	MetaMPUSequence      MetaType = 0x0008
	MetaItemID           MetaType = 0x0009
	MetaSubtitleID       MetaType = 0x000a
	MetaSignallingKind   MetaType = 0x000b
	MetaTableIdentity    MetaType = 0x000c
	MetaDescriptorTag    MetaType = 0x000d
	MetaTLVPacketType    MetaType = 0x000e
	MetaInputOffset      MetaType = 0x000f
	MetaIPSource         MetaType = 0x0010
	MetaIPDestination    MetaType = 0x0011
	MetaIPProtocol       MetaType = 0x0012
	MetaUDPSourcePort    MetaType = 0x0013
	MetaUDPDestPort      MetaType = 0x0014
	MetaOutputPID        MetaType = 0x0015
	MetaOutputTag        MetaType = 0x0016
	MetaObjectSize       MetaType = 0x0017
	MetaObjectSHA256     MetaType = 0x0018
	MetaRelatedLogicalID MetaType = 0x0019
	MetaApplicationID    MetaType = 0x001a
	MetaPath             MetaType = 0x001b
	MetaMediaType        MetaType = 0x001c
	MetaCaptionHeader    MetaType = 0x001d
)

const (
	SignallingPA               = 1
	SignallingM2Section        = 2
	SignallingTLVSI            = 3
	SignallingCA               = 4
	SignallingDataTransmission = 5
	SignallingNTP              = 6
)

func metaLength(t MetaType) int {
	switch t {
	case MetaSignallingKind, MetaTLVPacketType, MetaIPProtocol, MetaOutputTag:
		return 1
	case MetaPacketID, MetaComponentTag, MetaDescriptorTag, MetaUDPSourcePort, MetaUDPDestPort, MetaOutputPID:
		return 2
	case MetaPacketSequence, MetaPacketCounter, MetaAssetType, MetaAssetIDScheme, MetaMPUSequence, MetaItemID:
		return 4
	case MetaSubtitleID:
		return 6
	case MetaInputOffset, MetaObjectSize, MetaRelatedLogicalID:
		return 8
	case MetaApplicationID:
		return 8
	case MetaTableIdentity:
		return 9
	case MetaObjectSHA256:
		return 32
	}
	return -1
}

func (t MetaType) repeatable() bool { return t == MetaRelatedLogicalID }

func (t MetaType) known() bool {
	return t >= MetaPacketID && t <= MetaCaptionHeader
}

type Meta struct {
	Type  MetaType
	Value []byte
}

type Metadata []Meta

func (m *Metadata) add(t MetaType, v []byte) { *m = append(*m, Meta{Type: t, Value: v}) }

func (m *Metadata) AddU8(t MetaType, v byte) { m.add(t, []byte{v}) }
func (m *Metadata) AddU16(t MetaType, v uint16) {
	m.add(t, binary.BigEndian.AppendUint16(nil, v))
}
func (m *Metadata) AddU32(t MetaType, v uint32) {
	m.add(t, binary.BigEndian.AppendUint32(nil, v))
}
func (m *Metadata) AddU64(t MetaType, v uint64) {
	m.add(t, binary.BigEndian.AppendUint64(nil, v))
}
func (m *Metadata) AddBytes(t MetaType, v []byte) { m.add(t, append([]byte(nil), v...)) }
func (m *Metadata) AddText(t MetaType, v string)  { m.add(t, []byte(v)) }

func (m *Metadata) AddIP(t MetaType, addr []byte) {
	if len(addr) == 4 || len(addr) == 16 {
		m.AddBytes(t, addr)
	}
}

func (m *Metadata) AddTableIdentity(messageID uint16, tableID byte, extension uint16, version byte, current bool, section, last byte) {
	v := binary.BigEndian.AppendUint16(nil, messageID)
	v = append(v, tableID)
	v = binary.BigEndian.AppendUint16(v, extension)
	v = append(v, version, boolByte(current), section, last)
	m.add(MetaTableIdentity, v)
}

func (m *Metadata) AddApplicationIdentity(kind uint16, organization uint32, application uint16) {
	v := binary.BigEndian.AppendUint16(nil, kind)
	v = binary.BigEndian.AppendUint32(v, organization)
	v = binary.BigEndian.AppendUint16(v, application)
	m.add(MetaApplicationID, v)
}

func (m Metadata) validate() error {
	seen := make(map[MetaType]bool, len(m))
	for _, e := range m {
		if !e.Type.known() {
			return fmt.Errorf("preservation: refusing to write unknown metadata type %#04x", uint16(e.Type))
		}
		if want := metaLength(e.Type); want >= 0 && len(e.Value) != want {
			return fmt.Errorf("preservation: metadata %#04x is %d bytes, want %d", uint16(e.Type), len(e.Value), want)
		}
		switch e.Type {
		case MetaIPSource, MetaIPDestination:
			if len(e.Value) != 4 && len(e.Value) != 16 {
				return fmt.Errorf("preservation: metadata %#04x is %d bytes, want 4 or 16", uint16(e.Type), len(e.Value))
			}
		}
		if len(e.Value) > 0xffff {
			return fmt.Errorf("preservation: metadata %#04x does not fit a 16-bit length", uint16(e.Type))
		}
		if seen[e.Type] && !e.Type.repeatable() {
			return fmt.Errorf("preservation: metadata %#04x repeats", uint16(e.Type))
		}
		seen[e.Type] = true
	}
	return nil
}

func (m Metadata) size() int {
	n := 0
	for _, e := range m {
		n += 4 + len(e.Value)
	}
	return n
}

func (m Metadata) encode() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 64)
	for _, e := range m {
		out = binary.BigEndian.AppendUint16(out, uint16(e.Type))
		out = binary.BigEndian.AppendUint16(out, uint16(len(e.Value)))
		out = append(out, e.Value...)
	}
	return out, nil
}

func ParseMetadata(b []byte) (Metadata, error) {
	r := &reader{b: b}
	var out Metadata
	seen := make(map[MetaType]bool)
	for len(r.b) > 0 && r.err == nil {
		t := MetaType(r.u16())
		n := int(r.u16())
		v := r.bytes(n)
		if r.err != nil {
			break
		}
		if t.known() {
			if want := metaLength(t); want >= 0 && n != want {
				return nil, fmt.Errorf("preservation: metadata %#04x is %d bytes, want %d", uint16(t), n, want)
			}
			if seen[t] && !t.repeatable() {
				return nil, fmt.Errorf("preservation: metadata %#04x repeats", uint16(t))
			}
			seen[t] = true
		}
		out = append(out, Meta{Type: t, Value: v})
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return out, nil
}
