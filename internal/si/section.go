// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package si はM2メッセージからMMT-SIを収集し、現在の状態を保つ。
package si

import (
	"encoding/binary"
	"errors"

	"mmt2ts/internal/mpegts"
)

const (
	MessageIDM2Section      = 0x8000
	MessageIDCA             = 0x8001
	MessageIDM2ShortSection = 0x8002
	MessageIDData           = 0x8003
)

const (
	TableIDMHEITPF            = 0x8b
	TableIDMHEITScheduleFirst = 0x8c
	TableIDMHEITScheduleLast  = 0x9b
	TableIDMHAIT              = 0x9c
	TableIDMHBIT              = 0x9d
	TableIDMHSDTActual        = 0x9f
	TableIDMHSDTOther         = 0xa0
	TableIDMHTOT              = 0xa1
	TableIDMHCDT              = 0xa2
	TableIDDDMT               = 0xa3
	TableIDDAMT               = 0xa4
	TableIDDCCT               = 0xa5
	TableIDEMT                = 0xa6
	TableIDMHDIT              = 0xa7
	TableIDMHSIT              = 0xa8

	TableIDTLVNITActual = 0x40
	TableIDTLVNITOther  = 0x41
	TableIDAMT          = 0xfe
)

var (
	ErrShort = errors.New("si: truncated")
	ErrCRC   = errors.New("si: CRC mismatch")
)

type Section struct {
	TableID        byte
	Syntax         bool
	Extension      uint16
	Version        byte
	Current        bool
	Number         byte
	LastNumber     byte
	Body           []byte
	Raw            []byte
	CRCChecked     bool
	MessageID      uint16
	MessageVersion byte
}

func hasCRC(tableID byte, syntax bool) bool {
	if syntax {
		return true
	}
	return tableID == TableIDMHTOT
}

func ParseSection(b []byte) (Section, int, error) {
	if len(b) < 3 {
		return Section{}, 0, ErrShort
	}
	s := Section{TableID: b[0], Syntax: b[1]&0x80 != 0}
	length := int(binary.BigEndian.Uint16(b[1:3]) & 0x0fff)
	total := 3 + length
	if length > mpegts.MaxSectionLength || len(b) < total {
		return Section{}, 0, ErrShort
	}
	s.Raw = append([]byte(nil), b[:total]...)
	body := s.Raw[3:]
	if hasCRC(s.TableID, s.Syntax) {
		if len(body) < 4 {
			return Section{}, 0, ErrShort
		}
		if mpegts.CRC32(s.Raw) != 0 {
			return Section{}, total, ErrCRC
		}
		s.CRCChecked = true
		body = body[:len(body)-4]
	}
	if s.Syntax {
		if len(body) < 5 {
			return Section{}, total, ErrShort
		}
		s.Extension = binary.BigEndian.Uint16(body[0:2])
		s.Version = body[2] >> 1 & 0x1f
		s.Current = body[2]&0x01 != 0
		s.Number = body[3]
		s.LastNumber = body[4]
		body = body[5:]
	}
	s.Body = body
	return s, total, nil
}

type Stats struct {
	Messages          uint64
	Sections          uint64
	ShortSections     uint64
	CRCErrors         uint64
	Truncated         uint64
	UnknownMessages   map[uint16]uint64
	UnknownTables     map[byte]uint64
	NotCurrent        uint64
	VersionChanges    uint64
	CompletedTables   uint64
	IncompleteTables  uint64
	DuplicateMismatch uint64
}

func newStats() Stats {
	return Stats{
		UnknownMessages: make(map[uint16]uint64),
		UnknownTables:   make(map[byte]uint64),
	}
}

type Message struct {
	ID        uint16
	Version   byte
	Sections  []Section
	CRCErrors int
	Trailing  int
}

func ParseMessage(b []byte) (Message, error) {
	if len(b) < 5 {
		return Message{}, ErrShort
	}
	m := Message{ID: binary.BigEndian.Uint16(b[0:2]), Version: b[2]}
	length := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b)-5 < length {
		return m, ErrShort
	}
	payload := b[5 : 5+length]
	for len(payload) > 0 {
		s, n, err := ParseSection(payload)
		switch {
		case errors.Is(err, ErrCRC):
			m.CRCErrors++
			payload = payload[n:]
			continue
		case err != nil:
			m.Trailing = len(payload)
			return m, nil
		}
		s.MessageID, s.MessageVersion = m.ID, m.Version
		m.Sections = append(m.Sections, s)
		payload = payload[n:]
	}
	return m, nil
}

const (
	PacketIDCA     = 0x0001
	PacketIDMHEIT  = 0x8000
	PacketIDMHAIT  = 0x8001
	PacketIDMHBIT  = 0x8002
	PacketIDMHSDTT = 0x8003
	PacketIDMHSDT  = 0x8004
	PacketIDMHTOT  = 0x8005
	PacketIDMHCDT  = 0x8006
	PacketIDData   = 0x8007
	PacketIDMHDIT  = 0x8008
	PacketIDMHSIT  = 0x8009
)

func SignalingPacketIDs() []uint16 {
	return []uint16{
		PacketIDMHEIT, PacketIDMHAIT, PacketIDMHBIT, PacketIDMHSDTT, PacketIDMHSDT,
		PacketIDMHTOT, PacketIDMHCDT, PacketIDData, PacketIDMHDIT, PacketIDMHSIT,
	}
}
