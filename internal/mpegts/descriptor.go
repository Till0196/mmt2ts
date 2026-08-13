// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package mpegts

import "encoding/binary"

const (
	DescNetworkName         = 0x40
	DescServiceList         = 0x41
	DescService             = 0x48
	DescLinkage             = 0x4a
	DescShortEvent          = 0x4d
	DescExtendedEvent       = 0x4e
	DescComponent           = 0x50
	DescContent             = 0x54
	DescParentalRating      = 0x55
	DescLocalTimeOffset     = 0x58
	DescHierarchicalTx      = 0xc0
	DescDigitalCopyControl  = 0xc1
	DescDataContents        = 0xc7
	DescExtendedBroadcaster = 0xce
	DescTSInformation       = 0xcd
	DescLogoTransmission    = 0xcf
	DescSeries              = 0xd5
	DescEventGroup          = 0xd6
	DescSIParameter         = 0xd7
	DescBroadcasterName     = 0xd8
	DescComponentGroup      = 0xd9
	DescContentAvailability = 0xde
	DescEmergencyInfo       = 0xfc
	DescDataComponent       = 0xfd
	DescSystemManagement    = 0xfe

	MaxDescriptorBody = 0xff
)

func Descriptor(tag byte, body []byte) ([]byte, bool) {
	if len(body) > MaxDescriptorBody {
		return nil, false
	}
	d := make([]byte, 0, len(body)+2)
	d = append(d, tag, byte(len(body)))
	return append(d, body...), true
}

func ServiceDescriptor(serviceType byte, provider, name []byte) ([]byte, bool) {
	if len(provider) > 0xff || len(name) > 0xff {
		return nil, false
	}
	body := make([]byte, 0, len(provider)+len(name)+3)
	body = append(body, serviceType, byte(len(provider)))
	body = append(body, provider...)
	body = append(body, byte(len(name)))
	body = append(body, name...)
	return Descriptor(DescService, body)
}

func ShortEventDescriptor(language string, name, text []byte) ([]byte, bool) {
	if len(language) != 3 || len(name) > 0xff || len(text) > 0xff {
		return nil, false
	}
	body := make([]byte, 0, len(name)+len(text)+5)
	body = append(body, language...)
	body = append(body, byte(len(name)))
	body = append(body, name...)
	body = append(body, byte(len(text)))
	body = append(body, text...)
	return Descriptor(DescShortEvent, body)
}

type ExtendedEventItem struct {
	Description []byte
	Item        []byte
}

func ExtendedEventDescriptor(number, last byte, language string, items []ExtendedEventItem, text []byte) ([]byte, bool) {
	if len(language) != 3 || len(text) > 0xff {
		return nil, false
	}
	var loop []byte
	for _, it := range items {
		if len(it.Description) > 0xff || len(it.Item) > 0xff {
			return nil, false
		}
		loop = append(loop, byte(len(it.Description)))
		loop = append(loop, it.Description...)
		loop = append(loop, byte(len(it.Item)))
		loop = append(loop, it.Item...)
	}
	if len(loop) > 0xff {
		return nil, false
	}
	body := make([]byte, 0, len(loop)+len(text)+6)
	body = append(body, number<<4|last&0x0f)
	body = append(body, language...)
	body = append(body, byte(len(loop)))
	body = append(body, loop...)
	body = append(body, byte(len(text)))
	body = append(body, text...)
	return Descriptor(DescExtendedEvent, body)
}

func ComponentDescriptor(streamContent, componentType, componentTag byte, language string, text []byte) ([]byte, bool) {
	if len(language) != 3 {
		return nil, false
	}
	body := make([]byte, 0, len(text)+6)
	body = append(body, 0xf0|streamContent&0x0f, componentType, componentTag)
	body = append(body, language...)
	body = append(body, text...)
	return Descriptor(DescComponent, body)
}

func AudioComponentDescriptor(streamContent, componentType, componentTag, streamType, simulcastGroup, flags byte, language, language2 string, text []byte) ([]byte, bool) {
	if len(language) != 3 {
		return nil, false
	}
	body := make([]byte, 0, len(text)+12)
	body = append(body, 0xf0|streamContent&0x0f, componentType, componentTag, streamType, simulcastGroup, flags)
	body = append(body, language...)
	if flags&0x80 != 0 {
		if len(language2) != 3 {
			return nil, false
		}
		body = append(body, language2...)
	}
	body = append(body, text...)
	return Descriptor(DescAudioComponent, body)
}

type ContentNibble struct {
	Level1, Level2 byte
	User1, User2   byte
}

func ContentDescriptor(nibbles []ContentNibble) ([]byte, bool) {
	body := make([]byte, 0, len(nibbles)*2)
	for _, n := range nibbles {
		body = append(body, n.Level1<<4|n.Level2&0x0f, n.User1<<4|n.User2&0x0f)
	}
	return Descriptor(DescContent, body)
}

type ParentalRatingEntry struct {
	Country string
	Rating  byte
}

func ParentalRatingDescriptor(entries []ParentalRatingEntry) ([]byte, bool) {
	body := make([]byte, 0, len(entries)*4)
	for _, e := range entries {
		if len(e.Country) != 3 {
			return nil, false
		}
		body = append(body, e.Country...)
		body = append(body, e.Rating)
	}
	return Descriptor(DescParentalRating, body)
}

func SeriesDescriptor(seriesID uint16, repeatLabel, programPattern byte, expireValid bool, expireDate uint16, episode, lastEpisode uint16, name []byte) ([]byte, bool) {
	body := make([]byte, 0, len(name)+8)
	body = binary.BigEndian.AppendUint16(body, seriesID)
	flags := repeatLabel<<4 | programPattern<<1&0x0e
	if expireValid {
		flags |= 0x01
	}
	body = append(body, flags)
	body = binary.BigEndian.AppendUint16(body, expireDate)
	body = append(body, byte(episode>>4), byte(episode<<4)|byte(lastEpisode>>8)&0x0f, byte(lastEpisode))
	body = append(body, name...)
	return Descriptor(DescSeries, body)
}

type EventGroupEntry struct {
	ServiceID uint16
	EventID   uint16
}

func EventGroupDescriptor(groupType byte, events []EventGroupEntry, private []byte) ([]byte, bool) {
	if len(events) > 0x0f {
		return nil, false
	}
	body := make([]byte, 0, len(events)*4+len(private)+1)
	body = append(body, groupType<<4|byte(len(events))&0x0f)
	for _, e := range events {
		body = binary.BigEndian.AppendUint16(body, e.ServiceID)
		body = binary.BigEndian.AppendUint16(body, e.EventID)
	}
	body = append(body, private...)
	return Descriptor(DescEventGroup, body)
}

type DigitalCopyControlComponent struct {
	ComponentTag     byte
	RecordingControl byte
	MaximumBitrate   byte
	HasBitrate       bool
}

func DigitalCopyControlDescriptor(recordingControl byte, maximumBitrate byte, hasBitrate bool, components []DigitalCopyControlComponent) ([]byte, bool) {
	flags := recordingControl << 6
	if hasBitrate {
		flags |= 0x20
	}
	if len(components) > 0 {
		flags |= 0x10
	}
	body := []byte{flags}
	if hasBitrate {
		body = append(body, maximumBitrate)
	}
	if len(components) > 0 {
		var loop []byte
		for _, c := range components {
			f := c.RecordingControl << 6
			if c.HasBitrate {
				f |= 0x20
			}
			loop = append(loop, c.ComponentTag, f|0x1f)
			if c.HasBitrate {
				loop = append(loop, c.MaximumBitrate)
			}
		}
		if len(loop) > 0xff {
			return nil, false
		}
		body = append(body, byte(len(loop)))
		body = append(body, loop...)
	}
	return Descriptor(DescDigitalCopyControl, body)
}

func DataComponentDescriptor(componentID uint16, additional []byte) ([]byte, bool) {
	body := binary.BigEndian.AppendUint16(nil, componentID)
	body = append(body, additional...)
	return Descriptor(DescDataComponent, body)
}

func DataContentsDescriptor(componentID uint16, entryComponent byte, selector []byte, refs []byte, language string, text []byte) ([]byte, bool) {
	if len(language) != 3 || len(selector) > 0xff || len(refs) > 0xff || len(text) > 0xff {
		return nil, false
	}
	body := binary.BigEndian.AppendUint16(nil, componentID)
	body = append(body, entryComponent, byte(len(selector)))
	body = append(body, selector...)
	body = append(body, byte(len(refs)))
	body = append(body, refs...)
	body = append(body, language...)
	body = append(body, byte(len(text)))
	body = append(body, text...)
	return Descriptor(DescDataContents, body)
}

func LogoTransmissionDescriptor(logoType byte, logoID, logoVersion, downloadDataID uint16, text []byte) ([]byte, bool) {
	var body []byte
	switch logoType {
	case 0x01:
		body = []byte{logoType}
		body = binary.BigEndian.AppendUint16(body, 0xfe00|logoID&0x01ff)
		body = binary.BigEndian.AppendUint16(body, 0xf000|logoVersion&0x0fff)
		body = binary.BigEndian.AppendUint16(body, downloadDataID)
	case 0x02:
		body = []byte{logoType}
		body = binary.BigEndian.AppendUint16(body, 0xfe00|logoID&0x01ff)
	case 0x03:
		body = append([]byte{logoType}, text...)
	default:
		return nil, false
	}
	return Descriptor(DescLogoTransmission, body)
}

func NetworkNameDescriptor(name []byte) ([]byte, bool) { return Descriptor(DescNetworkName, name) }

func BroadcasterNameDescriptor(name []byte) ([]byte, bool) {
	return Descriptor(DescBroadcasterName, name)
}

type ServiceListEntry struct {
	ServiceID uint16
	Type      byte
}

func ServiceListDescriptor(entries []ServiceListEntry) ([]byte, bool) {
	body := make([]byte, 0, len(entries)*3)
	for _, e := range entries {
		body = binary.BigEndian.AppendUint16(body, e.ServiceID)
		body = append(body, e.Type)
	}
	return Descriptor(DescServiceList, body)
}

// TSInformationDescriptor returns the minimum TS information descriptor.
// The transmission-type loop describes hierarchical transmission and cannot be
// derived from a TLV remote-control-key descriptor, so it is left empty.
func TSInformationDescriptor(remoteControlKeyID byte) ([]byte, bool) {
	return Descriptor(DescTSInformation, []byte{remoteControlKeyID, 0x00})
}

func SystemManagementDescriptor(id uint16, additional []byte) ([]byte, bool) {
	body := binary.BigEndian.AppendUint16(nil, id)
	body = append(body, additional...)
	return Descriptor(DescSystemManagement, body)
}

type LocalTimeOffsetEntry struct {
	Country      string
	RegionID     byte
	Negative     bool
	OffsetBCD    uint16
	TimeOfChange [5]byte
	NextBCD      uint16
}

func LocalTimeOffsetDescriptor(entries []LocalTimeOffsetEntry) ([]byte, bool) {
	body := make([]byte, 0, len(entries)*13)
	for _, e := range entries {
		if len(e.Country) != 3 {
			return nil, false
		}
		body = append(body, e.Country...)
		flags := e.RegionID<<2 | 0x02
		if e.Negative {
			flags |= 0x01
		}
		body = append(body, flags)
		body = binary.BigEndian.AppendUint16(body, e.OffsetBCD)
		body = append(body, e.TimeOfChange[:]...)
		body = binary.BigEndian.AppendUint16(body, e.NextBCD)
	}
	return Descriptor(DescLocalTimeOffset, body)
}

type SIParameterTable struct {
	TableID     byte
	Description []byte
}

func SIParameterDescriptor(version byte, updateTime uint16, tables []SIParameterTable) ([]byte, bool) {
	body := []byte{version}
	body = binary.BigEndian.AppendUint16(body, updateTime)
	for _, t := range tables {
		if len(t.Description) > 0xff {
			return nil, false
		}
		body = append(body, t.TableID, byte(len(t.Description)))
		body = append(body, t.Description...)
	}
	return Descriptor(DescSIParameter, body)
}

func HierarchicalTransmissionDescriptor(highQuality bool, referencePID uint16) ([]byte, bool) {
	quality := byte(0)
	if highQuality {
		quality = 1
	}
	body := []byte{0xfe | quality}
	body = binary.BigEndian.AppendUint16(body, 0xe000|referencePID&0x1fff)
	return Descriptor(DescHierarchicalTx, body)
}

type ComponentCAUnit struct {
	ID   byte
	Tags []byte
}

type ComponentGroup struct {
	ID           byte
	CAUnits      []ComponentCAUnit
	TotalBitRate byte
	Text         []byte
}

func ComponentGroupDescriptor(groupType byte, hasTotalBitRate bool, groups []ComponentGroup) ([]byte, bool) {
	if len(groups) == 0 || len(groups) > 0x0f {
		return nil, false
	}
	flag := byte(0)
	if hasTotalBitRate {
		flag = 0x10
	}
	body := []byte{groupType<<5 | flag | byte(len(groups))&0x0f}
	for _, g := range groups {
		if len(g.CAUnits) == 0 || len(g.CAUnits) > 0x0f {
			return nil, false
		}
		body = append(body, g.ID<<4|byte(len(g.CAUnits))&0x0f)
		for _, u := range g.CAUnits {
			if len(u.Tags) == 0 || len(u.Tags) > 0x0f {
				return nil, false
			}
			body = append(body, u.ID<<4|byte(len(u.Tags))&0x0f)
			body = append(body, u.Tags...)
		}
		if hasTotalBitRate {
			body = append(body, g.TotalBitRate)
		}
		if len(g.Text) > 0xff {
			return nil, false
		}
		body = append(body, byte(len(g.Text)))
		body = append(body, g.Text...)
	}
	return Descriptor(DescComponentGroup, body)
}
