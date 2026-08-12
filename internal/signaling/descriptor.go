// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package signaling

import "encoding/binary"

const (
	TagMPUTimestamp         = 0x0001
	TagDependency           = 0x0002
	TagAssetGroup           = 0x8000
	TagMPEG4AudioExtension  = 0x8009
	TagMHHEVCVideo          = 0x800a
	TagStreamIdentifier     = 0x8011
	TagVideoComponent       = 0x8010
	TagAudioComponent       = 0x8014
	TagMPUExtendedTimestamp = 0x8026
	TagMHHierarchy          = 0x8037
)

type Descriptor struct {
	Tag  uint16
	Data []byte
}

func ParseDescriptors(data []byte) []Descriptor {
	var out []Descriptor
	for len(data) >= 3 {
		tag := binary.BigEndian.Uint16(data[:2])
		p, lengthBytes := 2, DescriptorLengthBytes(tag)
		if len(data)-p < lengthBytes {
			break
		}
		length := 0
		for range lengthBytes {
			length = length<<8 | int(data[p])
			p++
		}
		if len(data)-p < length {
			break
		}
		out = append(out, Descriptor{Tag: tag, Data: append([]byte(nil), data[p:p+length]...)})
		data = data[p+length:]
	}
	return out
}

func DescriptorLengthBytes(tag uint16) int {
	switch {
	case tag >= 0x4000 && tag <= 0x6fff:
		return 2
	case tag >= 0x7000 && tag <= 0x7fff:
		return 4
	case tag >= 0xf000:
		return 2
	default:
		return 1
	}
}

type AssetGroup struct {
	Identification byte
	SelectionLevel byte
}

type AssetReference struct {
	Scheme uint32
	ID     []byte
}

func parseDependencies(d []byte) ([]AssetReference, bool) {
	if len(d) < 1 {
		return nil, false
	}
	n, p := int(d[0]), 1
	out := make([]AssetReference, 0, n)
	for range n {
		if len(d)-p < 5 {
			return nil, false
		}
		scheme := binary.BigEndian.Uint32(d[p : p+4])
		length := int(d[p+4])
		p += 5
		if len(d)-p < length {
			return nil, false
		}
		out = append(out, AssetReference{Scheme: scheme, ID: append([]byte(nil), d[p:p+length]...)})
		p += length
	}
	return out, p == len(d)
}

type Hierarchy struct {
	TemporalScalabilityFlag bool
	SpatialScalabilityFlag  bool
	QualityScalabilityFlag  bool
	Type                    byte
	LayerIndex              byte
	TREFPresent             bool
	EmbeddedLayerIndex      byte
	Channel                 byte
}

type AudioComponent struct {
	StreamContent     byte
	ComponentType     byte
	ComponentTag      uint16
	StreamType        byte
	SimulcastGroupTag byte
	Flags             byte
	Language          string
	Language2         string
	Text              []byte
}

func (a *AudioComponent) MultiLingual() bool  { return a.Flags&0x80 != 0 }
func (a *AudioComponent) MainComponent() bool { return a.Flags&0x40 != 0 }
func (a *AudioComponent) Quality() byte       { return (a.Flags >> 4) & 0x03 }
func (a *AudioComponent) SamplingRate() byte  { return (a.Flags >> 1) & 0x07 }

type VideoComponent struct {
	Resolution   byte
	AspectRatio  byte
	ScanFlag     bool
	FrameRate    byte
	ComponentTag uint16
	Transfer     byte
	Language     string
	Text         string
}

func parseVideoComponent(d []byte) *VideoComponent {
	if len(d) < 8 {
		return nil
	}
	return &VideoComponent{
		Resolution:   d[0] >> 4,
		AspectRatio:  d[0] & 0x0f,
		ScanFlag:     d[1]&0x80 != 0,
		FrameRate:    d[1] & 0x1f,
		ComponentTag: binary.BigEndian.Uint16(d[2:4]),
		Transfer:     d[4] >> 4,
		Language:     string(d[5:8]),
		Text:         string(d[8:]),
	}
}

func ParseVideoComponent(d []byte) (*VideoComponent, bool) {
	v := parseVideoComponent(d)
	return v, v != nil
}

func parseAudioComponent(d []byte) *AudioComponent {
	if len(d) < 10 {
		return nil
	}
	a := &AudioComponent{
		StreamContent:     d[0] & 0x0f,
		ComponentType:     d[1],
		ComponentTag:      binary.BigEndian.Uint16(d[2:4]),
		StreamType:        d[4],
		SimulcastGroupTag: d[5],
		Flags:             d[6],
		Language:          string(d[7:10]),
	}
	p := 10
	if a.MultiLingual() {
		if len(d)-p < 3 {
			return a
		}
		a.Language2 = string(d[p : p+3])
		p += 3
	}
	a.Text = append([]byte(nil), d[p:]...)
	return a
}

type MPUTimestamp struct {
	Sequence uint32
	NTP      uint64
}

func ParseMPUTimestamps(d []byte) []MPUTimestamp {
	var out []MPUTimestamp
	for len(d) >= 12 {
		out = append(out, MPUTimestamp{
			Sequence: binary.BigEndian.Uint32(d[:4]),
			NTP:      binary.BigEndian.Uint64(d[4:12]),
		})
		d = d[12:]
	}
	return out
}

type AUTiming struct {
	DTSPTSOffset uint16
	PTSOffset    uint16
}

type ExtendedEntry struct {
	Sequence           uint32
	Leap               byte
	DecodingTimeOffset uint16
	AUs                []AUTiming
}

type ExtendedTimestamp struct {
	PTSOffsetType    byte
	Timescale        uint32
	HasTimescale     bool
	DefaultPTSOffset uint16
	Entries          []ExtendedEntry
	Invalid          bool
}

func ParseExtendedTimestamp(d []byte) *ExtendedTimestamp {
	if len(d) < 1 {
		return &ExtendedTimestamp{Invalid: true}
	}
	out := &ExtendedTimestamp{PTSOffsetType: (d[0] >> 1) & 0x03}
	p := 1
	if d[0]&0x01 != 0 {
		if len(d)-p < 4 {
			out.Invalid = true
			return out
		}
		out.Timescale = binary.BigEndian.Uint32(d[p : p+4])
		if out.Timescale == 0 {
			out.Invalid = true
			return out
		}
		out.HasTimescale = true
		p += 4
	}
	if out.PTSOffsetType == 1 {
		if len(d)-p < 2 {
			out.Invalid = true
			return out
		}
		out.DefaultPTSOffset = binary.BigEndian.Uint16(d[p : p+2])
		p += 2
	}
	for p < len(d) {
		if len(d)-p < 8 {
			out.Invalid = true
			return out
		}
		entry := ExtendedEntry{Sequence: binary.BigEndian.Uint32(d[p : p+4])}
		p += 4
		entry.Leap = d[p] >> 6
		p++
		entry.DecodingTimeOffset = binary.BigEndian.Uint16(d[p : p+2])
		p += 2
		numAU := int(d[p])
		p++
		perAU := 2
		if out.PTSOffsetType == 2 {
			perAU = 4
		}
		if len(d)-p < numAU*perAU {
			out.Invalid = true
			return out
		}
		entry.AUs = make([]AUTiming, numAU)
		for i := range numAU {
			entry.AUs[i].DTSPTSOffset = binary.BigEndian.Uint16(d[p : p+2])
			p += 2
			if out.PTSOffsetType == 2 {
				entry.AUs[i].PTSOffset = binary.BigEndian.Uint16(d[p : p+2])
				p += 2
			} else {
				entry.AUs[i].PTSOffset = out.DefaultPTSOffset
			}
		}
		out.Entries = append(out.Entries, entry)
	}
	return out
}

func ParseAudioComponent(d []byte) *AudioComponent { return parseAudioComponent(d) }
