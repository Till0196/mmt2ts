// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package caption はARIB-TTML字幕をデータグループと字幕PESへ組み立てる。
package caption

import (
	"encoding/binary"
	"errors"
)

const (
	DataTypeTTML     = 0x0
	DataTypePNG      = 0x1
	DataTypeSVG      = 0x2
	DataTypePCM      = 0x3
	DataTypeMP3      = 0x4
	DataTypeAAC      = 0x5
	DataTypeSVGFont  = 0x6
	DataTypeWOFFFont = 0x7
)

func DataTypeName(t byte) string {
	switch t {
	case DataTypeTTML:
		return "TTML"
	case DataTypePNG:
		return "PNG"
	case DataTypeSVG:
		return "SVG"
	case DataTypePCM:
		return "AIFF-C PCM"
	case DataTypeMP3:
		return "MP3"
	case DataTypeAAC:
		return "MPEG-4 AAC"
	case DataTypeSVGFont:
		return "SVG font"
	case DataTypeWOFFFont:
		return "WOFF font"
	default:
		return "reserved"
	}
}

var errShortMFU = errors.New("caption: MFU shorter than its header")

type Hint struct {
	DataType byte
	Size     uint32
}

type MFU struct {
	SubtitleTag    byte
	SequenceNumber byte
	Number         byte
	LastNumber     byte
	DataType       byte
	DeclaredSize   uint32
	Hints          []Hint
	Header         []byte
	Data           []byte
	Trailing       int
}

func ParseMFU(b []byte) (*MFU, error) {
	if len(b) < 6 {
		return nil, errShortMFU
	}
	m := &MFU{
		SubtitleTag:    b[0],
		SequenceNumber: b[1],
		Number:         b[2],
		LastNumber:     b[3],
		DataType:       b[4] >> 4,
	}
	extended := b[4]&0x08 != 0
	hasHints := b[4]&0x04 != 0
	p := 5
	width := 2
	if extended {
		width = 4
	}
	if len(b)-p < width {
		return nil, errShortMFU
	}
	if extended {
		m.DeclaredSize = binary.BigEndian.Uint32(b[p : p+4])
	} else {
		m.DeclaredSize = uint32(binary.BigEndian.Uint16(b[p : p+2]))
	}
	p += width
	if m.Number == 0 && m.LastNumber > 0 && hasHints {
		for range int(m.LastNumber) {
			if len(b)-p < 1+width {
				return nil, errShortMFU
			}
			h := Hint{DataType: b[p] >> 4}
			p++
			if extended {
				h.Size = binary.BigEndian.Uint32(b[p : p+4])
			} else {
				h.Size = uint32(binary.BigEndian.Uint16(b[p : p+2]))
			}
			p += width
			m.Hints = append(m.Hints, h)
		}
	}
	if len(b)-p < int(m.DeclaredSize) {
		return nil, errShortMFU
	}
	m.Header = append([]byte(nil), b[:p]...)
	m.Data = b[p : p+int(m.DeclaredSize)]
	m.Trailing = len(b) - p - int(m.DeclaredSize)
	return m, nil
}

const (
	TypeClosedCaption   = 0x0
	TypeSuperimposition = 0x1
)

const (
	TMDUTC       = 0x0
	TMDEITStart  = 0x1
	TMDReference = 0x2
	TMDMPUTime   = 0x3
	TMDNPT       = 0x4
	TMDMPUOnly   = 0x8
	TMDNone      = 0xf
)

type AdditionalInfo struct {
	SubtitleTag   byte
	InfoVersion   byte
	Language      string
	Type          byte
	Format        byte
	OPM           byte
	TMD           byte
	DMF           byte
	Resolution    byte
	Compression   byte
	StartMPU      uint32
	HasStartMPU   bool
	ReferenceTime uint64
	HasReference  bool
	LeapIndicator byte
}

func ParseAdditionalInfo(b []byte) (*AdditionalInfo, bool) {
	if len(b) < 8 {
		return nil, false
	}
	a := &AdditionalInfo{
		SubtitleTag: b[0],
		InfoVersion: b[1] >> 4,
		Language:    string(b[2:5]),
		Type:        b[5] >> 6,
		Format:      b[5] >> 2 & 0x0f,
		OPM:         b[5] & 0x03,
		TMD:         b[6] >> 4,
		DMF:         b[6] & 0x0f,
		Resolution:  b[7] >> 4,
		Compression: b[7] & 0x0f,
	}
	hasStart := b[1]&0x08 != 0
	p := 8
	if hasStart {
		if len(b)-p < 4 {
			return nil, false
		}
		a.StartMPU, a.HasStartMPU = binary.BigEndian.Uint32(b[p:p+4]), true
		p += 4
	}
	if a.TMD == TMDReference {
		if len(b)-p < 9 {
			return nil, false
		}
		a.ReferenceTime, a.HasReference = binary.BigEndian.Uint64(b[p:p+8]), true
		a.LeapIndicator = b[p+8] >> 6
	}
	return a, true
}

func (a *AdditionalInfo) DisplaySize() (width, height int, ok bool) {
	switch a.Resolution {
	case 0x0:
		return 1920, 1080, true
	case 0x1:
		return 3840, 2160, true
	case 0x2:
		return 7680, 4320, true
	default:
		return 0, 0, false
	}
}

func (a *AdditionalInfo) Superimposition() bool { return a.Type == TypeSuperimposition }
