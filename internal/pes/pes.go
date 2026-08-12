// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package pes はアクセスユニットを時刻付きのPESへ格納する。
package pes

const (
	StreamIDVideo    = 0xe0
	StreamIDAudio    = 0xc0
	StreamIDPrivate1 = 0xbd

	HeaderOverhead = 9 + 10
)

type Packet struct {
	StreamID    byte
	PTS         int64
	DTS         int64
	HasPTS      bool
	HasDTS      bool
	Aligned     bool
	PrivateData []byte
	Stuffing    int
	Payload     []byte
}

func Build(p Packet) []byte {
	header := AppendHeader(nil, p)
	return append(header, p.Payload...)
}

func AppendHeader(dst []byte, p Packet) []byte {
	ptsBytes := 0
	flags := byte(0)
	switch {
	case p.HasPTS && p.HasDTS:
		flags, ptsBytes = 0xc0, 10
	case p.HasPTS:
		flags, ptsBytes = 0x80, 5
	}
	extBytes := 0
	if len(p.PrivateData) == 16 {
		extBytes = 17
		flags |= 0x01
	}
	stuffing := p.Stuffing
	if stuffing < 0 {
		stuffing = 0
	}
	headerBytes := ptsBytes + extBytes + stuffing
	out := dst
	if cap(out)-len(out) < 9+headerBytes {
		out = make([]byte, 0, 9+headerBytes)
	}
	out = append(out, 0x00, 0x00, 0x01, p.StreamID)
	length := 3 + headerBytes + len(p.Payload)
	if length > 0xffff {
		length = 0
	}
	out = append(out, byte(length>>8), byte(length))
	marker := byte(0x80)
	if p.Aligned {
		marker |= 0x04
	}
	out = append(out, marker, flags, byte(headerBytes))
	if p.HasPTS && p.HasDTS {
		out = appendTimestamp(out, 0x30, p.PTS)
		out = appendTimestamp(out, 0x10, p.DTS)
	} else if p.HasPTS {
		out = appendTimestamp(out, 0x20, p.PTS)
	}
	if extBytes != 0 {
		out = append(out, 0x8e)
		out = append(out, p.PrivateData...)
	}
	for range stuffing {
		out = append(out, 0xff)
	}
	return out
}

func appendTimestamp(out []byte, prefix byte, v int64) []byte {
	u := uint64(v) & 0x1ffffffff
	return append(out,
		prefix|byte(u>>29)&0x0e|0x01,
		byte(u>>22),
		byte(u>>14)|0x01,
		byte(u>>7),
		byte(u<<1)|0x01,
	)
}
