// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package si

import (
	"encoding/binary"

	"mmt2ts/internal/signaling"
)

const (
	TagMHEmergencyInformation  = 0x8007
	TagMHMPEG4Audio            = 0x8008
	TagMHMPEG4AudioExtension   = 0x8009
	TagMHHEVCVideo             = 0x800a
	TagMHEventGroup            = 0x800c
	TagMHServiceList           = 0x800d
	TagVideoComponent          = 0x8010
	TagMHStreamIdentifier      = 0x8011
	TagMHContent               = 0x8012
	TagMHParentalRating        = 0x8013
	TagMHAudioComponent        = 0x8014
	TagMHSeries                = 0x8016
	TagMHSIParameter           = 0x8017
	TagMHBroadcasterName       = 0x8018
	TagMHService               = 0x8019
	TagMHDataComponent         = 0x8020
	TagUTCNPTReference         = 0x8021
	TagMHLocalTimeOffset       = 0x8023
	TagMHComponentGroup        = 0x8024
	TagMHLogoTransmission      = 0x8025
	TagApplicationService      = 0x8034
	TagContentCopyControl      = 0x8038
	TagContentUsageControl     = 0x8039
	TagRelatedBroadcaster      = 0x803e
	TagMultimediaService       = 0x803f
	TagEmergencyNews           = 0x8040
	TagMHLink                  = 0xf000
	TagMHShortEvent            = 0xf001
	TagMHExtendedEvent         = 0xf002
	TagEventMessage            = 0xf003
	TagMHStuffing              = 0xf004
	TagMHBroadcastID           = 0xf005
	TagMHNetworkIdentification = 0xf006
)

const (
	TagTLVNetworkName      = 0x40
	TagTLVServiceList      = 0x41
	TagTLVSatelliteSystem  = 0x43
	TagTLVCableSystem      = 0x44
	TagTLVRemoteControlKey = 0xcd
	TagTLVSystemManagement = 0xfe
)

type Descriptor = signaling.Descriptor

func ParseDescriptors(b []byte) []Descriptor { return signaling.ParseDescriptors(b) }

func ParseTLVDescriptors(b []byte) []Descriptor {
	var out []Descriptor
	for len(b) >= 2 {
		length := int(b[1])
		if len(b)-2 < length {
			break
		}
		out = append(out, Descriptor{Tag: uint16(b[0]), Data: append([]byte(nil), b[2:2+length]...)})
		b = b[2+length:]
	}
	return out
}

func Find(list []Descriptor, tag uint16) (Descriptor, bool) {
	for _, d := range list {
		if d.Tag == tag {
			return d, true
		}
	}
	return Descriptor{}, false
}

type ShortEvent struct {
	Language string
	Name     string
	Text     string
}

func ParseShortEvent(d []byte) (*ShortEvent, bool) {
	if len(d) < 4 {
		return nil, false
	}
	out := &ShortEvent{Language: string(d[0:3])}
	nameLen := int(d[3])
	if len(d)-4 < nameLen+2 {
		return nil, false
	}
	out.Name = string(d[4 : 4+nameLen])
	p := 4 + nameLen
	textLen := int(binary.BigEndian.Uint16(d[p : p+2]))
	p += 2
	if len(d)-p < textLen {
		return nil, false
	}
	out.Text = string(d[p : p+textLen])
	return out, true
}

type ExtendedEvent struct {
	Number     byte
	LastNumber byte
	Language   string
	Items      []ExtendedItem
	Text       string
	Partial    bool
}

type ExtendedItem struct {
	Description string
	Item        string
}

func ParseExtendedEvent(d []byte) (*ExtendedEvent, bool) {
	if len(d) < 6 {
		return nil, false
	}
	out := &ExtendedEvent{
		Number:     d[0] >> 4,
		LastNumber: d[0] & 0x0f,
		Language:   string(d[1:4]),
	}
	itemsLen := int(binary.BigEndian.Uint16(d[4:6]))
	p := 6
	if len(d)-p < itemsLen+2 {
		return nil, false
	}
	items := d[p : p+itemsLen]
	p += itemsLen
	for len(items) > 0 {
		descLen := int(items[0])
		if len(items)-1 < descLen+2 {
			out.Partial = true
			out.Items = append(out.Items, ExtendedItem{Description: string(items[min(1, len(items)):])})
			break
		}
		item := ExtendedItem{Description: string(items[1 : 1+descLen])}
		items = items[1+descLen:]
		valueLen := int(binary.BigEndian.Uint16(items[0:2]))
		if len(items)-2 < valueLen {
			out.Partial = true
			item.Item = string(items[2:])
			out.Items = append(out.Items, item)
			break
		}
		item.Item = string(items[2 : 2+valueLen])
		items = items[2+valueLen:]
		out.Items = append(out.Items, item)
	}
	textLen := int(binary.BigEndian.Uint16(d[p : p+2]))
	p += 2
	if len(d)-p < textLen {
		return nil, false
	}
	out.Text = string(d[p : p+textLen])
	return out, true
}

type VideoComponent = signaling.VideoComponent

func ParseVideoComponent(d []byte) (*VideoComponent, bool) { return signaling.ParseVideoComponent(d) }

type ComponentGroupCAUnit struct {
	ID   byte
	Tags []uint16
}

type ComponentGroupEntry struct {
	ID           byte
	CAUnits      []ComponentGroupCAUnit
	TotalBitRate byte
	Text         string
}

type ComponentGroup struct {
	Type            byte
	HasTotalBitRate bool
	Groups          []ComponentGroupEntry
}

func ParseComponentGroup(d []byte) (*ComponentGroup, bool) {
	if len(d) < 1 {
		return nil, false
	}
	g := &ComponentGroup{Type: d[0] >> 5, HasTotalBitRate: d[0]&0x10 != 0}
	count := int(d[0] & 0x0f)
	p := 1
	for range count {
		if p >= len(d) {
			return nil, false
		}
		e := ComponentGroupEntry{ID: d[p] >> 4}
		units := int(d[p] & 0x0f)
		p++
		for range units {
			if p >= len(d) {
				return nil, false
			}
			u := ComponentGroupCAUnit{ID: d[p] >> 4}
			components := int(d[p] & 0x0f)
			p++
			if p+2*components > len(d) {
				return nil, false
			}
			for range components {
				u.Tags = append(u.Tags, binary.BigEndian.Uint16(d[p:p+2]))
				p += 2
			}
			e.CAUnits = append(e.CAUnits, u)
		}
		if g.HasTotalBitRate {
			if p >= len(d) {
				return nil, false
			}
			e.TotalBitRate = d[p]
			p++
		}
		if p >= len(d) {
			return nil, false
		}
		textLen := int(d[p])
		p++
		if p+textLen > len(d) {
			return nil, false
		}
		e.Text = string(d[p : p+textLen])
		p += textLen
		g.Groups = append(g.Groups, e)
	}
	if p != len(d) {
		return nil, false
	}
	return g, true
}

type AudioComponent = signaling.AudioComponent

func ParseAudioComponent(d []byte) (*AudioComponent, bool) {
	a := signaling.ParseAudioComponent(d)
	return a, a != nil
}

type ContentNibble struct {
	Level1, Level2 byte
	User1, User2   byte
}

func ParseContent(d []byte) []ContentNibble {
	var out []ContentNibble
	for len(d) >= 2 {
		out = append(out, ContentNibble{
			Level1: d[0] >> 4, Level2: d[0] & 0x0f,
			User1: d[1] >> 4, User2: d[1] & 0x0f,
		})
		d = d[2:]
	}
	return out
}

type ParentalRating struct {
	Country string
	Rating  byte
}

func ParseParentalRating(d []byte) []ParentalRating {
	var out []ParentalRating
	for len(d) >= 4 {
		out = append(out, ParentalRating{Country: string(d[0:3]), Rating: d[3]})
		d = d[4:]
	}
	return out
}

type Series struct {
	SeriesID          uint16
	RepeatLabel       byte
	ProgramPattern    byte
	ExpireDateValid   bool
	ExpireDate        uint16
	EpisodeNumber     uint16
	LastEpisodeNumber uint16
	Name              string
}

func ParseSeries(d []byte) (*Series, bool) {
	if len(d) < 8 {
		return nil, false
	}
	return &Series{
		SeriesID:          binary.BigEndian.Uint16(d[0:2]),
		RepeatLabel:       d[2] >> 4,
		ProgramPattern:    d[2] >> 1 & 0x07,
		ExpireDateValid:   d[2]&0x01 != 0,
		ExpireDate:        binary.BigEndian.Uint16(d[3:5]),
		EpisodeNumber:     binary.BigEndian.Uint16(d[5:7]) >> 4,
		LastEpisodeNumber: binary.BigEndian.Uint16(d[6:8]) & 0x0fff,
		Name:              string(d[8:]),
	}, true
}

type EventGroup struct {
	GroupType byte
	Events    []GroupEvent
	Others    []OtherNetworkEvent
	Private   []byte
}

type GroupEvent struct {
	ServiceID uint16
	EventID   uint16
}

type OtherNetworkEvent struct {
	OriginalNetworkID uint16
	TLVStreamID       uint16
	ServiceID         uint16
	EventID           uint16
}

func ParseEventGroup(d []byte) (*EventGroup, bool) {
	if len(d) < 1 {
		return nil, false
	}
	out := &EventGroup{GroupType: d[0] >> 4}
	count := int(d[0] & 0x0f)
	p := 1
	for range count {
		if len(d)-p < 4 {
			return nil, false
		}
		out.Events = append(out.Events, GroupEvent{
			ServiceID: binary.BigEndian.Uint16(d[p : p+2]),
			EventID:   binary.BigEndian.Uint16(d[p+2 : p+4]),
		})
		p += 4
	}
	if out.GroupType == 4 || out.GroupType == 5 {
		for len(d)-p >= 8 {
			out.Others = append(out.Others, OtherNetworkEvent{
				OriginalNetworkID: binary.BigEndian.Uint16(d[p : p+2]),
				TLVStreamID:       binary.BigEndian.Uint16(d[p+2 : p+4]),
				ServiceID:         binary.BigEndian.Uint16(d[p+4 : p+6]),
				EventID:           binary.BigEndian.Uint16(d[p+6 : p+8]),
			})
			p += 8
		}
	} else {
		out.Private = append([]byte(nil), d[p:]...)
	}
	return out, true
}

type Service struct {
	Type     byte
	Provider string
	Name     string
}

func ParseService(d []byte) (*Service, bool) {
	if len(d) < 3 {
		return nil, false
	}
	out := &Service{Type: d[0]}
	providerLen := int(d[1])
	if len(d)-2 < providerLen+1 {
		return nil, false
	}
	out.Provider = string(d[2 : 2+providerLen])
	p := 2 + providerLen
	nameLen := int(d[p])
	p++
	if len(d)-p < nameLen {
		return nil, false
	}
	out.Name = string(d[p : p+nameLen])
	return out, true
}

type ServiceListEntry struct {
	ServiceID uint16
	Type      byte
}

func ParseServiceList(d []byte) []ServiceListEntry {
	var out []ServiceListEntry
	for len(d) >= 3 {
		out = append(out, ServiceListEntry{ServiceID: binary.BigEndian.Uint16(d[0:2]), Type: d[2]})
		d = d[3:]
	}
	return out
}

const (
	DataComponentCaption    = 0x0020
	DataComponentMultimedia = 0x0021
)

type DataComponent struct {
	ComponentID    uint16
	AdditionalInfo []byte
}

func ParseDataComponent(d []byte) (*DataComponent, bool) {
	if len(d) < 2 {
		return nil, false
	}
	return &DataComponent{
		ComponentID:    binary.BigEndian.Uint16(d[0:2]),
		AdditionalInfo: append([]byte(nil), d[2:]...),
	}, true
}

type LogoTransmission struct {
	Type           byte
	LogoID         uint16
	LogoVersion    uint16
	DownloadDataID uint16
	Text           string
}

func ParseLogoTransmission(d []byte) (*LogoTransmission, bool) {
	if len(d) < 1 {
		return nil, false
	}
	out := &LogoTransmission{Type: d[0]}
	switch d[0] {
	case 0x01:
		if len(d) < 7 {
			return nil, false
		}
		out.LogoID = binary.BigEndian.Uint16(d[1:3]) & 0x01ff
		out.LogoVersion = binary.BigEndian.Uint16(d[3:5]) & 0x0fff
		out.DownloadDataID = binary.BigEndian.Uint16(d[5:7])
	case 0x02:
		if len(d) < 3 {
			return nil, false
		}
		out.LogoID = binary.BigEndian.Uint16(d[1:3]) & 0x01ff
	case 0x03:
		out.Text = string(d[1:])
	}
	return out, true
}

type CopyControl struct {
	RecordingControl byte
	MaximumBitrate   byte
	HasBitrate       bool
	Components       []CopyControlComponent
}

type CopyControlComponent struct {
	ComponentTag     uint16
	RecordingControl byte
	MaximumBitrate   byte
	HasBitrate       bool
}

func ParseCopyControl(d []byte) (*CopyControl, bool) {
	if len(d) < 1 {
		return nil, false
	}
	out := &CopyControl{RecordingControl: d[0] >> 6}
	bitrateFlag := d[0]&0x20 != 0
	componentFlag := d[0]&0x10 != 0
	p := 2
	if len(d) < p {
		return nil, false
	}
	if bitrateFlag {
		if len(d)-p < 1 {
			return nil, false
		}
		out.MaximumBitrate, out.HasBitrate = d[p], true
		p++
	}
	if !componentFlag {
		return out, true
	}
	if len(d)-p < 1 {
		return nil, false
	}
	loopLen := int(d[p])
	p++
	if len(d)-p < loopLen {
		return nil, false
	}
	loop := d[p : p+loopLen]
	for len(loop) >= 4 {
		c := CopyControlComponent{
			ComponentTag:     binary.BigEndian.Uint16(loop[0:2]),
			RecordingControl: loop[2] >> 6,
		}
		hasBitrate := loop[2]&0x20 != 0
		loop = loop[4:]
		if hasBitrate {
			if len(loop) < 1 {
				return nil, false
			}
			c.MaximumBitrate, c.HasBitrate = loop[0], true
			loop = loop[1:]
		}
		out.Components = append(out.Components, c)
	}
	return out, true
}

type LocalTimeOffset struct {
	Country       string
	RegionID      byte
	Negative      bool
	OffsetBCD     uint16
	TimeOfChange  [5]byte
	NextOffsetBCD uint16
}

func ParseLocalTimeOffset(d []byte) []LocalTimeOffset {
	var out []LocalTimeOffset
	for len(d) >= 13 {
		e := LocalTimeOffset{
			Country:       string(d[0:3]),
			RegionID:      d[3] >> 2,
			Negative:      d[3]&0x01 != 0,
			OffsetBCD:     binary.BigEndian.Uint16(d[4:6]),
			NextOffsetBCD: binary.BigEndian.Uint16(d[11:13]),
		}
		copy(e.TimeOfChange[:], d[6:11])
		out = append(out, e)
		d = d[13:]
	}
	return out
}

type BroadcastID struct {
	OriginalNetworkID uint16
	TLVStreamID       uint16
	EventID           uint16
	BroadcasterID     byte
}

func ParseBroadcastID(d []byte) (*BroadcastID, bool) {
	if len(d) < 7 {
		return nil, false
	}
	return &BroadcastID{
		OriginalNetworkID: binary.BigEndian.Uint16(d[0:2]),
		TLVStreamID:       binary.BigEndian.Uint16(d[2:4]),
		EventID:           binary.BigEndian.Uint16(d[4:6]),
		BroadcasterID:     d[6],
	}, true
}

type NetworkIdentification struct {
	Country   string
	MediaType string
	NetworkID uint16
	Private   []byte
}

func ParseNetworkIdentification(d []byte) (*NetworkIdentification, bool) {
	if len(d) < 7 {
		return nil, false
	}
	return &NetworkIdentification{
		Country:   string(d[0:3]),
		MediaType: string(d[3:5]),
		NetworkID: binary.BigEndian.Uint16(d[5:7]),
		Private:   append([]byte(nil), d[7:]...),
	}, true
}

type SIParameter struct {
	Version    byte
	UpdateTime uint16
	Tables     []SIParameterTable
}

type SIParameterTable struct {
	TableID     byte
	Description []byte
}

func ParseSIParameter(d []byte) (*SIParameter, bool) {
	if len(d) < 3 {
		return nil, false
	}
	out := &SIParameter{Version: d[0], UpdateTime: binary.BigEndian.Uint16(d[1:3])}
	p := 3
	for len(d)-p >= 2 {
		length := int(d[p+1])
		if len(d)-p-2 < length {
			return nil, false
		}
		out.Tables = append(out.Tables, SIParameterTable{
			TableID:     d[p],
			Description: append([]byte(nil), d[p+2:p+2+length]...),
		})
		p += 2 + length
	}
	return out, true
}

type SystemManagement struct {
	SystemManagementID uint16
	Additional         []byte
}

func ParseSystemManagement(d []byte) (*SystemManagement, bool) {
	if len(d) < 2 {
		return nil, false
	}
	return &SystemManagement{
		SystemManagementID: binary.BigEndian.Uint16(d[0:2]),
		Additional:         append([]byte(nil), d[2:]...),
	}, true
}

type RemoteControlKey struct {
	Entries []RemoteControlKeyEntry
}

type RemoteControlKeyEntry struct {
	KeyID     byte
	ServiceID uint16
}

func ParseRemoteControlKey(d []byte) (*RemoteControlKey, bool) {
	if len(d) < 1 {
		return nil, false
	}
	out := &RemoteControlKey{}
	count := int(d[0])
	p := 1
	for range count {
		if len(d)-p < 5 {
			return nil, false
		}
		out.Entries = append(out.Entries, RemoteControlKeyEntry{
			KeyID:     d[p],
			ServiceID: binary.BigEndian.Uint16(d[p+1 : p+3]),
		})
		p += 5
	}
	return out, true
}
