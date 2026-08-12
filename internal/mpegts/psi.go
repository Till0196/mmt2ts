// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package mpegts

import "encoding/binary"

const (
	TableIDPAT = 0x00
	TableIDPMT = 0x02

	StreamTypeHEVC    = 0x24
	StreamTypeADTSAAC = 0x0f
	StreamTypeLATMAAC = 0x11
	StreamTypePES     = 0x06
	StreamTypeDSMCC   = 0x0b
)

func CarriesDSMCCSections(streamType byte) bool {
	return streamType >= 0x0a && streamType <= 0x0d
}

const (
	TableIDDII = 0x3b
	TableIDDDB = 0x3c

	DescStreamIdentifier = 0x52
	DescAudioComponent   = 0xc4

	MaxSectionLength = 4093
)

var crcTables = buildCRCTables()

func buildCRCTables() [8][256]uint32 {
	var t [8][256]uint32
	for i := range 256 {
		crc := uint32(i) << 24
		for range 8 {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04c11db7
			} else {
				crc <<= 1
			}
		}
		t[0][i] = crc
	}
	for k := 1; k < 8; k++ {
		for i := range 256 {
			prev := t[k-1][i]
			t[k][i] = prev<<8 ^ t[0][prev>>24]
		}
	}
	return t
}

func CRC32(b []byte) uint32 {
	crc := uint32(0xffffffff)
	for len(b) >= 8 {
		crc ^= uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		crc = crcTables[7][crc>>24] ^
			crcTables[6][crc>>16&0xff] ^
			crcTables[5][crc>>8&0xff] ^
			crcTables[4][crc&0xff] ^
			crcTables[3][b[4]] ^
			crcTables[2][b[5]] ^
			crcTables[1][b[6]] ^
			crcTables[0][b[7]]
		b = b[8:]
	}
	for _, c := range b {
		crc = crc<<8 ^ crcTables[0][byte(crc>>24)^c]
	}
	return crc
}

const (
	sectionFlagsPSI = 0xb000
	sectionFlagsDVB = 0xf000
)

func finishSection(body []byte, flags uint16) []byte {
	length := len(body) - 3 + 4
	binary.BigEndian.PutUint16(body[1:3], flags|uint16(length&0x0fff))
	crc := CRC32(body)
	return binary.BigEndian.AppendUint32(body, crc)
}

func LongSection(tableID byte, extension uint16, version, number, last byte, body []byte) []byte {
	return longSection(tableID, sectionFlagsPSI, extension, version, number, last, body)
}

const LongSectionOverhead = 8 + 4

func AppendLongSectionHeader(dst []byte, tableID byte, extension uint16, version, number, last byte) []byte {
	dst = append(dst, tableID, 0, 0)
	dst = binary.BigEndian.AppendUint16(dst, extension)
	return append(dst, 0xc1|version<<1&0x3e, number, last)
}

func FinishSection(section []byte) []byte {
	return finishSection(section, sectionFlagsPSI)
}

type Program struct {
	Number uint16
	PID    uint16
}

func BuildPAT(tsID uint16, version byte, programs []Program, networkPID uint16) []byte {
	body := make([]byte, 0, 64)
	body = append(body, TableIDPAT, 0, 0)
	body = binary.BigEndian.AppendUint16(body, tsID)
	body = append(body, 0xc1|version<<1&0x3e, 0x00, 0x00)
	if networkPID != 0 {
		body = binary.BigEndian.AppendUint16(body, 0)
		body = binary.BigEndian.AppendUint16(body, 0xe000|networkPID)
	}
	for _, p := range programs {
		body = binary.BigEndian.AppendUint16(body, p.Number)
		body = binary.BigEndian.AppendUint16(body, 0xe000|p.PID)
	}
	return finishSection(body, sectionFlagsPSI)
}

type ElementaryStream struct {
	StreamType  byte
	PID         uint16
	Descriptors []byte
}

func BuildPMT(programNumber uint16, version byte, pcrPID uint16, programInfo []byte, streams []ElementaryStream) []byte {
	body := make([]byte, 0, 256)
	body = append(body, TableIDPMT, 0, 0)
	body = binary.BigEndian.AppendUint16(body, programNumber)
	body = append(body, 0xc1|version<<1&0x3e, 0x00, 0x00)
	body = binary.BigEndian.AppendUint16(body, 0xe000|pcrPID)
	body = binary.BigEndian.AppendUint16(body, 0xf000|uint16(len(programInfo)&0x0fff))
	body = append(body, programInfo...)
	for _, s := range streams {
		body = append(body, s.StreamType)
		body = binary.BigEndian.AppendUint16(body, 0xe000|s.PID)
		body = binary.BigEndian.AppendUint16(body, 0xf000|uint16(len(s.Descriptors)&0x0fff))
		body = append(body, s.Descriptors...)
	}
	return finishSection(body, sectionFlagsPSI)
}

func StreamIdentifierDescriptor(tag byte) []byte {
	return []byte{DescStreamIdentifier, 0x01, tag}
}
