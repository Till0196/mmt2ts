// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package signaling は分割されたPAメッセージを復元し、PLTとMPTを読み取る。
package signaling

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	MessageIDPA = 0x0000

	TableIDMPTSubsetFirst = 0x11
	TableIDMPTSubsetLast  = 0x1f
	TableIDMPTComplete    = 0x20
	TableIDPLT            = 0x80

	MessageIDData = 0x8003

	PacketIDPA = 0x0000

	maxSignalingBuffer = 4 << 20
)

var errShort = errors.New("signaling: truncated table")

type Location struct {
	Type     byte
	PacketID uint16
	Raw      []byte
}

type Asset struct {
	IdentifierType byte
	IDScheme       uint32
	ID             []byte
	Type           string
	ClockRelation  bool
	Locations      []Location
	Descriptors    []Descriptor

	ComponentTag      *uint16
	Video             *VideoComponent
	Audio             *AudioComponent
	Group             *AssetGroup
	Hierarchy         *Hierarchy
	Dependencies      []AssetReference
	DependencyInvalid bool
	MPUTimestamps     []MPUTimestamp
	Extended          *ExtendedTimestamp
}

func (a *Asset) Key() string {
	if len(a.ID) > 0 {
		return fmt.Sprintf("%d/%08x/%x", a.IdentifierType, a.IDScheme, a.ID)
	}
	return fmt.Sprintf("type/%s/%04x", a.Type, a.PrimaryPacketID())
}

func (a *Asset) PrimaryPacketID() uint16 {
	id, _ := a.LocalPacketID()
	return id
}

func (a *Asset) LocalPacketID() (uint16, bool) {
	for _, l := range a.Locations {
		if l.Type == 0x00 {
			return l.PacketID, true
		}
	}
	return 0, false
}

type MPT struct {
	TableID     byte
	Version     byte
	Mode        byte
	PackageID   []byte
	Descriptors []Descriptor
	Assets      []Asset
}

func (m *MPT) ServiceID() uint16 {
	if len(m.PackageID) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(m.PackageID[len(m.PackageID)-2:])
}

type PLTEntry struct {
	PackageID []byte
	Location  Location
}

type PLT struct {
	Version byte
	Entries []PLTEntry
}

type Table struct {
	ID      byte
	Version byte
	Raw     []byte
	MPT     *MPT
	PLT     *PLT
}

type Stats struct {
	Packets          uint64
	Messages         uint64
	Tables           uint64
	UnknownTables    map[byte]uint64
	MalformedTables  uint64
	DroppedFragments uint64
	Overflows        uint64
}

func (s Stats) Add(o Stats) Stats {
	sum := Stats{
		Packets:          s.Packets + o.Packets,
		Messages:         s.Messages + o.Messages,
		Tables:           s.Tables + o.Tables,
		MalformedTables:  s.MalformedTables + o.MalformedTables,
		DroppedFragments: s.DroppedFragments + o.DroppedFragments,
		Overflows:        s.Overflows + o.Overflows,
		UnknownTables:    make(map[byte]uint64, len(s.UnknownTables)+len(o.UnknownTables)),
	}
	for id, n := range s.UnknownTables {
		sum.UnknownTables[id] += n
	}
	for id, n := range o.UnknownTables {
		sum.UnknownTables[id] += n
	}
	return sum
}

type Reassembler struct {
	buffers map[uint16][]byte
	stats   Stats
}

func NewReassembler() *Reassembler {
	return &Reassembler{buffers: make(map[uint16][]byte), stats: Stats{UnknownTables: make(map[byte]uint64)}}
}

func (r *Reassembler) Stats() Stats { return r.stats }

type Message struct {
	ID      uint16
	Version byte
	Payload []byte
	Raw     []byte
	Tables  []Table
}

func (r *Reassembler) Push(packetID uint16, payload []byte) []Message {
	r.stats.Packets++
	if len(payload) < 2 {
		r.stats.DroppedFragments++
		return nil
	}
	fragmentation := payload[0] >> 6
	aggregation := payload[0]&0x01 != 0
	lengthExtension := payload[0]&0x02 != 0
	data := payload[2:]
	if aggregation {
		if fragmentation != 0 {
			r.stats.DroppedFragments++
			return nil
		}
		return r.parseAggregated(data, lengthExtension)
	}
	switch fragmentation {
	case 0:
		delete(r.buffers, packetID)
		return r.parseMessage(data)
	case 1:
		r.buffers[packetID] = append([]byte(nil), data...)
	case 2:
		if buf, ok := r.buffers[packetID]; ok {
			if len(buf)+len(data) > maxSignalingBuffer {
				r.stats.Overflows++
				delete(r.buffers, packetID)
				return nil
			}
			r.buffers[packetID] = append(buf, data...)
		} else {
			r.stats.DroppedFragments++
		}
	case 3:
		buf, ok := r.buffers[packetID]
		if !ok {
			r.stats.DroppedFragments++
			return nil
		}
		delete(r.buffers, packetID)
		return r.parseMessage(append(buf, data...))
	}
	return nil
}

func (r *Reassembler) parseAggregated(b []byte, lengthExtension bool) []Message {
	width := 2
	if lengthExtension {
		width = 4
	}
	var out []Message
	for len(b) > 0 {
		if len(b) < width {
			r.stats.MalformedTables++
			return out
		}
		var length int
		if width == 4 {
			length = int(binary.BigEndian.Uint32(b[:4]))
		} else {
			length = int(binary.BigEndian.Uint16(b[:2]))
		}
		b = b[width:]
		if length < 0 || len(b) < length {
			r.stats.MalformedTables++
			return out
		}
		out = append(out, r.parseMessage(b[:length])...)
		b = b[length:]
	}
	return out
}

func headerLength(id uint16) int {
	switch {
	case id == MessageIDPA, id == MessageIDData,
		id >= 0x7000 && id <= 0x7fff, id >= 0xf000:
		return 7
	default:
		return 5
	}
}

func (r *Reassembler) parseMessage(b []byte) []Message {
	if len(b) < 5 {
		r.stats.MalformedTables++
		return nil
	}
	id := binary.BigEndian.Uint16(b[:2])
	header := headerLength(id)
	if len(b) < header {
		r.stats.MalformedTables++
		return nil
	}
	var length int
	if header == 7 {
		length = int(binary.BigEndian.Uint32(b[3:7]))
	} else {
		length = int(binary.BigEndian.Uint16(b[3:5]))
	}
	if length < 0 || len(b)-header < length {
		r.stats.MalformedTables++
		return nil
	}
	r.stats.Messages++
	m := Message{
		ID:      id,
		Version: b[2],
		Payload: b[header : header+length],
		Raw:     b[:header+length],
	}
	if id != MessageIDPA {
		return []Message{m}
	}
	m.Tables = r.parsePATables(m.Payload)
	return []Message{m}
}

func (r *Reassembler) parsePATables(body []byte) []Table {
	if len(body) < 1 {
		r.stats.MalformedTables++
		return nil
	}
	p := 1 + 4*int(body[0])
	if p > len(body) {
		r.stats.MalformedTables++
		return nil
	}
	var out []Table
	for p < len(body) {
		if len(body)-p < 4 {
			r.stats.MalformedTables++
			return out
		}
		id, version := body[p], body[p+1]
		tableLen := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
		p += 4
		if len(body)-p < tableLen {
			r.stats.MalformedTables++
			return out
		}
		raw := body[p : p+tableLen]
		p += tableLen
		r.stats.Tables++
		out = append(out, r.decodeTable(id, version, raw))
	}
	return out
}

func (r *Reassembler) decodeTable(id, version byte, raw []byte) Table {
	t := Table{ID: id, Version: version, Raw: append([]byte(nil), raw...)}
	switch {
	case id == TableIDPLT:
		plt, err := ParsePLT(version, raw)
		if err != nil {
			r.stats.MalformedTables++
			return t
		}
		t.PLT = plt
	case id == TableIDMPTComplete:
		mpt, err := ParseMPT(id, version, raw)
		if err != nil {
			r.stats.MalformedTables++
			return t
		}
		t.MPT = mpt
	case id >= TableIDMPTSubsetFirst && id <= TableIDMPTSubsetLast:
		r.stats.UnknownTables[id]++
	default:
		r.stats.UnknownTables[id]++
	}
	return t
}

func ParsePLT(version byte, b []byte) (*PLT, error) {
	if len(b) < 1 {
		return nil, errShort
	}
	out := &PLT{Version: version}
	p := 1
	for range int(b[0]) {
		if len(b)-p < 1 {
			return nil, errShort
		}
		idLen := int(b[p])
		p++
		if len(b)-p < idLen {
			return nil, errShort
		}
		id := append([]byte(nil), b[p:p+idLen]...)
		p += idLen
		loc, n, err := parseLocation(b[p:])
		if err != nil {
			return nil, err
		}
		p += n
		out.Entries = append(out.Entries, PLTEntry{PackageID: id, Location: loc})
	}
	return out, nil
}

func ParseMPT(tableID, version byte, b []byte) (*MPT, error) {
	if len(b) < 2 {
		return nil, errShort
	}
	out := &MPT{TableID: tableID, Version: version, Mode: b[0] & 0x03}
	p := 1
	idLen := int(b[p])
	p++
	if len(b)-p < idLen+2 {
		return nil, errShort
	}
	out.PackageID = append([]byte(nil), b[p:p+idLen]...)
	p += idLen
	descLen := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if len(b)-p < descLen+1 {
		return nil, errShort
	}
	out.Descriptors = ParseDescriptors(b[p : p+descLen])
	p += descLen
	count := int(b[p])
	p++
	for range count {
		asset, n, err := parseAsset(b[p:])
		if err != nil {
			return nil, err
		}
		p += n
		out.Assets = append(out.Assets, asset)
	}
	return out, nil
}

func parseAsset(b []byte) (Asset, int, error) {
	var a Asset
	if len(b) < 6 {
		return a, 0, errShort
	}
	p := 0
	a.IdentifierType = b[p]
	p++
	a.IDScheme = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	idLen := int(b[p])
	p++
	if len(b)-p < idLen+6 {
		return a, 0, errShort
	}
	a.ID = append([]byte(nil), b[p:p+idLen]...)
	p += idLen
	a.Type = string(b[p : p+4])
	p += 4
	a.ClockRelation = b[p]&0x01 != 0
	p++
	if a.ClockRelation {
		if len(b)-p < 2 {
			return a, 0, errShort
		}
		flag := b[p+1]&0x01 != 0
		p += 2
		if flag {
			if len(b)-p < 4 {
				return a, 0, errShort
			}
			p += 4
		}
	}
	if len(b)-p < 1 {
		return a, 0, errShort
	}
	locationCount := int(b[p])
	p++
	for range locationCount {
		loc, n, err := parseLocation(b[p:])
		if err != nil {
			return a, 0, err
		}
		p += n
		a.Locations = append(a.Locations, loc)
	}
	if len(b)-p < 2 {
		return a, 0, errShort
	}
	descLen := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if len(b)-p < descLen {
		return a, 0, errShort
	}
	a.Descriptors = ParseDescriptors(b[p : p+descLen])
	p += descLen
	a.applyDescriptors()
	return a, p, nil
}

func (a *Asset) applyDescriptors() {
	for _, d := range a.Descriptors {
		switch d.Tag {
		case TagStreamIdentifier:
			if len(d.Data) >= 2 {
				tag := binary.BigEndian.Uint16(d.Data[:2])
				a.ComponentTag = &tag
			}
		case TagVideoComponent:
			a.Video = parseVideoComponent(d.Data)
		case TagAudioComponent:
			a.Audio = parseAudioComponent(d.Data)
		case TagAssetGroup:
			if len(d.Data) >= 2 {
				a.Group = &AssetGroup{Identification: d.Data[0], SelectionLevel: d.Data[1]}
			}
		case TagMHHierarchy:
			if len(d.Data) >= 4 {
				a.Hierarchy = &Hierarchy{
					TemporalScalabilityFlag: d.Data[0]&0x40 != 0,
					SpatialScalabilityFlag:  d.Data[0]&0x20 != 0,
					QualityScalabilityFlag:  d.Data[0]&0x10 != 0,
					Type:                    d.Data[0] & 0x0f,
					LayerIndex:              d.Data[1] & 0x3f,
					TREFPresent:             d.Data[2]&0x80 != 0,
					EmbeddedLayerIndex:      d.Data[2] & 0x3f,
					Channel:                 d.Data[3] & 0x3f,
				}
			}
		case TagDependency:
			refs, ok := parseDependencies(d.Data)
			if !ok {
				a.DependencyInvalid = true
			} else {
				a.Dependencies = append(a.Dependencies, refs...)
			}
		case TagMPUTimestamp:
			a.MPUTimestamps = append(a.MPUTimestamps, ParseMPUTimestamps(d.Data)...)
		case TagMPUExtendedTimestamp:
			a.Extended = ParseExtendedTimestamp(d.Data)
		}
	}
}

func parseLocation(b []byte) (Location, int, error) {
	if len(b) < 1 {
		return Location{}, 0, errShort
	}
	loc := Location{Type: b[0]}
	size := 0
	switch b[0] {
	case 0x00:
		size = 3
	case 0x01:
		size = 1 + 4 + 4 + 2 + 2
	case 0x02:
		size = 1 + 16 + 16 + 2 + 2
	case 0x03:
		size = 1 + 2 + 2 + 2
	case 0x04:
		size = 1 + 16 + 16 + 2 + 2
	case 0x05:
		if len(b) < 2 {
			return loc, 0, errShort
		}
		size = 2 + int(b[1])
	default:
		return loc, 0, fmt.Errorf("signaling: unknown location type %#02x", b[0])
	}
	if len(b) < size {
		return loc, 0, errShort
	}
	loc.Raw = append([]byte(nil), b[:size]...)
	switch b[0] {
	case 0x00:
		loc.PacketID = binary.BigEndian.Uint16(b[1:3])
	case 0x01, 0x02:
		loc.PacketID = binary.BigEndian.Uint16(b[size-2 : size])
	}
	return loc, size, nil
}
