// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package si

import "encoding/binary"

type NIT struct {
	TableID     byte
	NetworkID   uint16
	Version     byte
	Descriptors []Descriptor
	Streams     []NITStream
}

type NITStream struct {
	TLVStreamID       uint16
	OriginalNetworkID uint16
	Descriptors       []Descriptor
}

func (n *NIT) Actual() bool { return n.TableID == TableIDTLVNITActual }

func ParseNIT(s Section) (*NIT, bool) {
	b := s.Body
	if len(b) < 2 {
		return nil, false
	}
	out := &NIT{TableID: s.TableID, NetworkID: s.Extension, Version: s.Version}
	descLen := int(binary.BigEndian.Uint16(b[0:2]) & 0x0fff)
	p := 2
	if len(b)-p < descLen+2 {
		return nil, false
	}
	out.Descriptors = ParseTLVDescriptors(b[p : p+descLen])
	p += descLen
	loopLen := int(binary.BigEndian.Uint16(b[p:p+2]) & 0x0fff)
	p += 2
	if len(b)-p < loopLen {
		return nil, false
	}
	loop := b[p : p+loopLen]
	for len(loop) >= 6 {
		streamDescLen := int(binary.BigEndian.Uint16(loop[4:6]) & 0x0fff)
		if len(loop)-6 < streamDescLen {
			return nil, false
		}
		out.Streams = append(out.Streams, NITStream{
			TLVStreamID:       binary.BigEndian.Uint16(loop[0:2]),
			OriginalNetworkID: binary.BigEndian.Uint16(loop[2:4]),
			Descriptors:       ParseTLVDescriptors(loop[6 : 6+streamDescLen]),
		})
		loop = loop[6+streamDescLen:]
	}
	return out, true
}

type Event struct {
	EventID       uint16
	StartTime     [5]byte
	Duration      [3]byte
	RunningStatus byte
	FreeCA        bool
	Descriptors   []Descriptor
}

func (e *Event) StartDefined() bool {
	for _, b := range e.StartTime {
		if b != 0xff {
			return true
		}
	}
	return false
}

func (e *Event) DurationDefined() bool {
	for _, b := range e.Duration {
		if b != 0xff {
			return true
		}
	}
	return false
}

type EIT struct {
	TableID           byte
	ServiceID         uint16
	Version           byte
	SectionNumber     byte
	LastSectionNumber byte
	TLVStreamID       uint16
	OriginalNetworkID uint16
	SegmentLast       byte
	LastTableID       byte
	Events            []Event
}

func (e *EIT) Schedule() bool {
	return e.TableID >= TableIDMHEITScheduleFirst && e.TableID <= TableIDMHEITScheduleLast
}

func (e *EIT) Segment() byte { return e.SectionNumber >> 3 }

func ParseEIT(s Section) (*EIT, bool) {
	b := s.Body
	if len(b) < 6 {
		return nil, false
	}
	out := &EIT{
		TableID:           s.TableID,
		ServiceID:         s.Extension,
		Version:           s.Version,
		SectionNumber:     s.Number,
		LastSectionNumber: s.LastNumber,
		TLVStreamID:       binary.BigEndian.Uint16(b[0:2]),
		OriginalNetworkID: binary.BigEndian.Uint16(b[2:4]),
		SegmentLast:       b[4],
		LastTableID:       b[5],
	}
	p := 6
	for len(b)-p >= 12 {
		var e Event
		e.EventID = binary.BigEndian.Uint16(b[p : p+2])
		copy(e.StartTime[:], b[p+2:p+7])
		copy(e.Duration[:], b[p+7:p+10])
		e.RunningStatus = b[p+10] >> 5
		e.FreeCA = b[p+10]&0x10 != 0
		descLen := int(binary.BigEndian.Uint16(b[p+10:p+12]) & 0x0fff)
		p += 12
		if len(b)-p < descLen {
			return nil, false
		}
		e.Descriptors = ParseDescriptors(b[p : p+descLen])
		p += descLen
		out.Events = append(out.Events, e)
	}
	return out, true
}

type SDT struct {
	TableID           byte
	TLVStreamID       uint16
	Version           byte
	OriginalNetworkID uint16
	Services          []SDTService
}

type SDTService struct {
	ServiceID        uint16
	UserDefinedFlags byte
	ScheduleFlag     bool
	PresentFollowing bool
	RunningStatus    byte
	FreeCA           bool
	Descriptors      []Descriptor
}

func (s *SDT) Actual() bool { return s.TableID == TableIDMHSDTActual }

func ParseSDT(s Section) (*SDT, bool) {
	b := s.Body
	if len(b) < 3 {
		return nil, false
	}
	out := &SDT{
		TableID:           s.TableID,
		TLVStreamID:       s.Extension,
		Version:           s.Version,
		OriginalNetworkID: binary.BigEndian.Uint16(b[0:2]),
	}
	p := 3
	for len(b)-p >= 5 {
		svc := SDTService{
			ServiceID:        binary.BigEndian.Uint16(b[p : p+2]),
			UserDefinedFlags: b[p+2] >> 2 & 0x07,
			ScheduleFlag:     b[p+2]&0x02 != 0,
			PresentFollowing: b[p+2]&0x01 != 0,
			RunningStatus:    b[p+3] >> 5,
			FreeCA:           b[p+3]&0x10 != 0,
		}
		descLen := int(binary.BigEndian.Uint16(b[p+3:p+5]) & 0x0fff)
		p += 5
		if len(b)-p < descLen {
			return nil, false
		}
		svc.Descriptors = ParseDescriptors(b[p : p+descLen])
		p += descLen
		out.Services = append(out.Services, svc)
	}
	return out, true
}

type TOT struct {
	JSTTime     [5]byte
	Descriptors []Descriptor
}

func ParseTOT(s Section) (*TOT, bool) {
	b := s.Body
	if len(b) < 7 {
		return nil, false
	}
	out := &TOT{}
	copy(out.JSTTime[:], b[0:5])
	descLen := int(binary.BigEndian.Uint16(b[5:7]) & 0x0fff)
	if len(b)-7 < descLen {
		return nil, false
	}
	out.Descriptors = ParseDescriptors(b[7 : 7+descLen])
	return out, true
}

type BIT struct {
	OriginalNetworkID uint16
	Version           byte
	ViewPropriety     bool
	Descriptors       []Descriptor
	Broadcasters      []BITBroadcaster
}

type BITBroadcaster struct {
	BroadcasterID byte
	Descriptors   []Descriptor
}

func ParseBIT(s Section) (*BIT, bool) {
	b := s.Body
	if len(b) < 2 {
		return nil, false
	}
	out := &BIT{
		OriginalNetworkID: s.Extension,
		Version:           s.Version,
		ViewPropriety:     b[0]&0x10 != 0,
	}
	descLen := int(binary.BigEndian.Uint16(b[0:2]) & 0x0fff)
	p := 2
	if len(b)-p < descLen {
		return nil, false
	}
	out.Descriptors = ParseDescriptors(b[p : p+descLen])
	p += descLen
	for len(b)-p >= 3 {
		loopLen := int(binary.BigEndian.Uint16(b[p+1:p+3]) & 0x0fff)
		if len(b)-p-3 < loopLen {
			return nil, false
		}
		out.Broadcasters = append(out.Broadcasters, BITBroadcaster{
			BroadcasterID: b[p],
			Descriptors:   ParseDescriptors(b[p+3 : p+3+loopLen]),
		})
		p += 3 + loopLen
	}
	return out, true
}

type CDT struct {
	DownloadDataID    uint16
	Version           byte
	OriginalNetworkID uint16
	DataType          byte
	Descriptors       []Descriptor
	Module            []byte
}

func ParseCDT(s Section) (*CDT, bool) {
	b := s.Body
	if len(b) < 5 {
		return nil, false
	}
	out := &CDT{
		DownloadDataID:    s.Extension,
		Version:           s.Version,
		OriginalNetworkID: binary.BigEndian.Uint16(b[0:2]),
		DataType:          b[2],
	}
	descLen := int(binary.BigEndian.Uint16(b[3:5]) & 0x0fff)
	p := 5
	if len(b)-p < descLen {
		return nil, false
	}
	out.Descriptors = ParseDescriptors(b[p : p+descLen])
	p += descLen
	out.Module = append([]byte(nil), b[p:]...)
	return out, true
}

type SIT struct {
	Version          byte
	TransmissionInfo []Descriptor
	Services         []SITService
}

type SITService struct {
	ServiceID     uint16
	RunningStatus byte
	Descriptors   []Descriptor
}

func ParseSIT(s Section) (*SIT, bool) {
	b := s.Body
	if len(b) < 2 {
		return nil, false
	}
	out := &SIT{Version: s.Version}
	infoLen := int(binary.BigEndian.Uint16(b[0:2]) & 0x0fff)
	p := 2
	if len(b)-p < infoLen {
		return nil, false
	}
	out.TransmissionInfo = ParseDescriptors(b[p : p+infoLen])
	p += infoLen
	for len(b)-p >= 4 {
		loopLen := int(binary.BigEndian.Uint16(b[p+2:p+4]) & 0x0fff)
		if len(b)-p-4 < loopLen {
			return nil, false
		}
		out.Services = append(out.Services, SITService{
			ServiceID:     binary.BigEndian.Uint16(b[p : p+2]),
			RunningStatus: b[p+2] >> 4 & 0x07,
			Descriptors:   ParseDescriptors(b[p+4 : p+4+loopLen]),
		})
		p += 4 + loopLen
	}
	return out, true
}

type DIT struct {
	Transition bool
}

func ParseDIT(s Section) (*DIT, bool) {
	if len(s.Body) < 1 {
		return nil, false
	}
	return &DIT{Transition: s.Body[0]&0x80 != 0}, true
}

type AIT struct {
	ApplicationType   uint16
	Version           byte
	CommonDescriptors []Descriptor
	Applications      []Application
}

type Application struct {
	OrganizationID uint32
	ApplicationID  uint16
	ControlCode    byte
	Descriptors    []Descriptor
}

func ParseAIT(s Section) (*AIT, bool) {
	b := s.Body
	if len(b) < 2 {
		return nil, false
	}
	out := &AIT{ApplicationType: s.Extension, Version: s.Version}
	commonLen := int(binary.BigEndian.Uint16(b[0:2]) & 0x0fff)
	p := 2
	if len(b)-p < commonLen+2 {
		return nil, false
	}
	out.CommonDescriptors = ParseDescriptors(b[p : p+commonLen])
	p += commonLen
	loopLen := int(binary.BigEndian.Uint16(b[p:p+2]) & 0x0fff)
	p += 2
	if len(b)-p < loopLen {
		return nil, false
	}
	loop := b[p : p+loopLen]
	for len(loop) >= 9 {
		descLen := int(binary.BigEndian.Uint16(loop[7:9]) & 0x0fff)
		if len(loop)-9 < descLen {
			return nil, false
		}
		out.Applications = append(out.Applications, Application{
			OrganizationID: binary.BigEndian.Uint32(loop[0:4]),
			ApplicationID:  binary.BigEndian.Uint16(loop[4:6]),
			ControlCode:    loop[6],
			Descriptors:    ParseDescriptors(loop[9 : 9+descLen]),
		})
		loop = loop[9+descLen:]
	}
	return out, true
}
