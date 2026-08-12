// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package arib

import "encoding/binary"

const (
	UnitStatementBody = 0x20
	UnitGeometric     = 0x28
	UnitSynthesised   = 0x2c
	UnitDRCS1Byte     = 0x30
	UnitDRCS2Byte     = 0x31
	UnitColourMap     = 0x34
	UnitBitmap        = 0x35

	UnitSeparator = 0x1f
)

func DataUnit(parameter byte, body []byte) []byte {
	u := make([]byte, 0, len(body)+5)
	u = append(u, UnitSeparator, parameter)
	u = append(u, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(u, body...)
}

type LanguageEntry struct {
	Tag      byte
	DMF      byte
	DC       byte
	HasDC    bool
	Language string
	Format   byte
	TCS      byte
	Rollup   byte
}

func Management(tmd byte, otm []byte, languages []LanguageEntry, units []byte) []byte {
	b := []byte{tmd<<6 | 0x3f}
	if tmd == 0x02 {
		b = append(b, otm...)
	}
	b = append(b, byte(len(languages)))
	for _, l := range languages {
		b = append(b, l.Tag<<5|0x10|l.DMF&0x0f)
		if l.HasDC {
			b = append(b, l.DC)
		}
		lang := l.Language
		if len(lang) != 3 {
			lang = "und"
		}
		b = append(b, lang...)
		b = append(b, l.Format<<4|l.TCS<<2|l.Rollup&0x03)
	}
	b = append(b, byte(len(units)>>16), byte(len(units)>>8), byte(len(units)))
	return append(b, units...)
}

func Statement(tmd byte, stm []byte, units []byte) []byte {
	b := []byte{tmd<<6 | 0x3f}
	if tmd == 0x01 || tmd == 0x02 {
		b = append(b, stm...)
	}
	b = append(b, byte(len(units)>>16), byte(len(units)>>8), byte(len(units)))
	return append(b, units...)
}

const (
	GroupManagementA = 0x00
	GroupManagementB = 0x20
	GroupStatementA  = 0x01
	GroupStatementB  = 0x21
)

func DataGroup(id, version, link, lastLink byte, body []byte) ([]byte, bool) {
	if len(body) > 0xffff {
		return nil, false
	}
	g := make([]byte, 0, len(body)+7)
	g = append(g, id<<2|version&0x03, link, lastLink)
	g = binary.BigEndian.AppendUint16(g, uint16(len(body)))
	g = append(g, body...)
	return binary.BigEndian.AppendUint16(g, CRC16(g)), true
}

var crc16Table = func() [256]uint16 {
	var t [256]uint16
	for i := range 256 {
		crc := uint16(i) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
		t[i] = crc
	}
	return t
}()

func CRC16(b []byte) uint16 {
	crc := uint16(0)
	for _, c := range b {
		crc = crc<<8 ^ crc16Table[byte(crc>>8)^c]
	}
	return crc
}

const (
	DataIdentifierSynchronised = 0x80
	DataIdentifierAsynchronous = 0x81

	privateStreamID = 0xff
)

func PESPayload(dataIdentifier byte, header, group []byte) ([]byte, bool) {
	if len(header) > 0x0f {
		return nil, false
	}
	p := make([]byte, 0, len(group)+len(header)+3)
	p = append(p, dataIdentifier, privateStreamID, 0xf0|byte(len(header)))
	p = append(p, header...)
	return append(p, group...), true
}
