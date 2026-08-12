// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package mpegts

import "encoding/binary"

const (
	PIDCAT = 0x0001
	PIDNIT = 0x0010
	PIDSDT = 0x0011
	PIDEIT = 0x0012
	PIDTOT = 0x0014
	PIDBIT = 0x0024
	PIDCDT = 0x0029
)

func IsFixedSIPID(pid uint16) bool {
	switch pid {
	case PIDPAT, PIDCAT, PIDNIT, PIDSDT, PIDEIT, PIDTOT, PIDBIT, PIDCDT, PIDNull:
		return true
	}
	return false
}

const (
	TableIDNITActual        = 0x40
	TableIDNITOther         = 0x41
	TableIDSDTActual        = 0x42
	TableIDSDTOther         = 0x46
	TableIDEITPFActual      = 0x4e
	TableIDEITPFOther       = 0x4f
	TableIDEITScheduleFirst = 0x50
	TableIDEITScheduleLast  = 0x5f
	TableIDTDT              = 0x70
	TableIDTOT              = 0x73
	TableIDBIT              = 0xc4
	TableIDCDT              = 0xc8
)

const maxLoopBytes = MaxSectionLength - 8 - 4

func longSection(tableID byte, flags, extension uint16, version, number, last byte, body []byte) []byte {
	s := make([]byte, 0, len(body)+12)
	s = append(s, tableID, 0, 0)
	s = binary.BigEndian.AppendUint16(s, extension)
	s = append(s, 0xc1|version<<1&0x3e, number, last)
	s = append(s, body...)
	return finishSection(s, flags)
}

func splitLoop(head []byte, entries [][]byte) [][]byte {
	var out [][]byte
	current := append([]byte(nil), head...)
	used := 0
	for _, e := range entries {
		if used > 0 && len(head)+used+len(e) > maxLoopBytes {
			out = append(out, current)
			current = append([]byte(nil), head...)
			used = 0
		}
		current = append(current, e...)
		used += len(e)
	}
	return append(out, current)
}

type NITStream struct {
	TransportStreamID uint16
	OriginalNetworkID uint16
	Descriptors       []byte
}

func BuildNIT(tableID byte, networkID uint16, version byte, networkDescriptors []byte, streams []NITStream) [][]byte {
	head := binary.BigEndian.AppendUint16(nil, 0xf000|uint16(len(networkDescriptors)&0x0fff))
	head = append(head, networkDescriptors...)
	entries := make([][]byte, 0, len(streams))
	for _, s := range streams {
		e := binary.BigEndian.AppendUint16(nil, s.TransportStreamID)
		e = binary.BigEndian.AppendUint16(e, s.OriginalNetworkID)
		e = binary.BigEndian.AppendUint16(e, 0xf000|uint16(len(s.Descriptors)&0x0fff))
		entries = append(entries, append(e, s.Descriptors...))
	}
	bodies := splitLoop(head, entries)
	out := make([][]byte, 0, len(bodies))
	last := byte(len(bodies) - 1)
	for i, body := range bodies {
		loopLen := len(body) - len(head)
		full := append(append([]byte(nil), body[:len(head)]...),
			byte(0xf0|loopLen>>8&0x0f), byte(loopLen))
		full = append(full, body[len(head):]...)
		out = append(out, longSection(tableID, sectionFlagsDVB, networkID, version, byte(i), last, full))
	}
	return out
}

type SDTService struct {
	ServiceID        uint16
	ScheduleFlag     bool
	PresentFollowing bool
	RunningStatus    byte
	FreeCA           bool
	Descriptors      []byte
}

func BuildSDT(tableID byte, tsID, originalNetworkID uint16, version byte, services []SDTService) [][]byte {
	head := binary.BigEndian.AppendUint16(nil, originalNetworkID)
	head = append(head, 0xff)
	entries := make([][]byte, 0, len(services))
	for _, s := range services {
		flags := byte(0xfc)
		if s.ScheduleFlag {
			flags |= 0x02
		} else {
			flags &^= 0x02
		}
		if s.PresentFollowing {
			flags |= 0x01
		} else {
			flags &^= 0x01
		}
		e := binary.BigEndian.AppendUint16(nil, s.ServiceID)
		e = append(e, flags)
		status := uint16(s.RunningStatus&0x07) << 13
		if s.FreeCA {
			status |= 0x1000
		}
		e = binary.BigEndian.AppendUint16(e, status|uint16(len(s.Descriptors)&0x0fff))
		entries = append(entries, append(e, s.Descriptors...))
	}
	bodies := splitLoop(head, entries)
	out := make([][]byte, 0, len(bodies))
	last := byte(len(bodies) - 1)
	for i, body := range bodies {
		out = append(out, longSection(tableID, sectionFlagsDVB, tsID, version, byte(i), last, body))
	}
	return out
}

type EITEvent struct {
	EventID       uint16
	StartTime     [5]byte
	Duration      [3]byte
	RunningStatus byte
	FreeCA        bool
	Descriptors   []byte
}

func (e EITEvent) encode() []byte {
	b := binary.BigEndian.AppendUint16(nil, e.EventID)
	b = append(b, e.StartTime[:]...)
	b = append(b, e.Duration[:]...)
	status := uint16(e.RunningStatus&0x07) << 13
	if e.FreeCA {
		status |= 0x1000
	}
	b = binary.BigEndian.AppendUint16(b, status|uint16(len(e.Descriptors)&0x0fff))
	return append(b, e.Descriptors...)
}

type EITSection struct {
	TableID           byte
	ServiceID         uint16
	TransportStreamID uint16
	OriginalNetworkID uint16
	Version           byte
	Number            byte
	LastNumber        byte
	SegmentLast       byte
	LastTableID       byte
	Events            []EITEvent
}

func BuildEIT(s EITSection) (section []byte, overflow []EITEvent) {
	head := binary.BigEndian.AppendUint16(nil, s.TransportStreamID)
	head = binary.BigEndian.AppendUint16(head, s.OriginalNetworkID)
	head = append(head, s.SegmentLast, s.LastTableID)
	body := append([]byte(nil), head...)
	used := 0
	for i, e := range s.Events {
		enc := e.encode()
		if len(head)+used+len(enc) > maxLoopBytes {
			overflow = s.Events[i:]
			break
		}
		body = append(body, enc...)
		used += len(enc)
	}
	return longSection(s.TableID, sectionFlagsDVB, s.ServiceID, s.Version, s.Number, s.LastNumber, body), overflow
}

func BuildTOT(jstTime [5]byte, descriptors []byte) []byte {
	s := make([]byte, 0, len(descriptors)+16)
	s = append(s, TableIDTOT, 0, 0)
	s = append(s, jstTime[:]...)
	s = binary.BigEndian.AppendUint16(s, 0xf000|uint16(len(descriptors)&0x0fff))
	s = append(s, descriptors...)
	return finishSection(s, 0x7000)
}

func BuildTDT(jstTime [5]byte) []byte {
	s := []byte{TableIDTDT, 0x70, 0x05}
	return append(s, jstTime[:]...)
}

type BITBroadcaster struct {
	BroadcasterID byte
	Descriptors   []byte
}

func BuildBIT(originalNetworkID uint16, version byte, viewPropriety bool, first []byte, broadcasters []BITBroadcaster) [][]byte {
	flags := uint16(0xe000)
	if viewPropriety {
		flags |= 0x1000
	}
	head := binary.BigEndian.AppendUint16(nil, flags|uint16(len(first)&0x0fff))
	head = append(head, first...)
	entries := make([][]byte, 0, len(broadcasters))
	for _, b := range broadcasters {
		e := []byte{b.BroadcasterID}
		e = binary.BigEndian.AppendUint16(e, 0xf000|uint16(len(b.Descriptors)&0x0fff))
		entries = append(entries, append(e, b.Descriptors...))
	}
	bodies := splitLoop(head, entries)
	out := make([][]byte, 0, len(bodies))
	last := byte(len(bodies) - 1)
	for i, body := range bodies {
		out = append(out, longSection(TableIDBIT, sectionFlagsDVB, originalNetworkID, version, byte(i), last, body))
	}
	return out
}

func BuildCDT(downloadDataID uint16, version byte, originalNetworkID uint16, dataType byte, descriptors, module []byte) [][]byte {
	head := binary.BigEndian.AppendUint16(nil, originalNetworkID)
	head = append(head, dataType)
	head = binary.BigEndian.AppendUint16(head, 0xf000|uint16(len(descriptors)&0x0fff))
	head = append(head, descriptors...)
	room := maxLoopBytes - len(head)
	if room <= 0 {
		return nil
	}
	var bodies [][]byte
	for len(module) > 0 {
		take := min(len(module), room)
		bodies = append(bodies, append(append([]byte(nil), head...), module[:take]...))
		module = module[take:]
	}
	if len(bodies) == 0 {
		bodies = [][]byte{head}
	}
	out := make([][]byte, 0, len(bodies))
	last := byte(len(bodies) - 1)
	for i, body := range bodies {
		out = append(out, longSection(TableIDCDT, sectionFlagsDVB, downloadDataID, version, byte(i), last, body))
	}
	return out
}
