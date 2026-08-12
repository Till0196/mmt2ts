// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package codec はHEVCをAnnex Bへ、LATMのAACをADTSまたはLOASへ変換する。
package codec

import "errors"

var (
	ErrLATMSyntax       = errors.New("codec: unsupported or malformed LATM AudioMuxElement")
	ErrADTSFrameTooLong = errors.New("codec: AAC access unit exceeds ADTS frame length")
)

const loasSyncword = 0x2b7

func LOASFrame(dst, ame []byte) ([]byte, error) {
	if len(ame) == 0 {
		return dst, ErrEmptySample
	}
	if len(ame) > 0x1fff {
		return dst, ErrADTSFrameTooLong
	}
	n := uint16(len(ame))
	dst = append(dst, byte(loasSyncword>>3), byte(loasSyncword<<5&0xff)|byte(n>>8)&0x1f, byte(n))
	return append(dst, ame...), nil
}

type ADTSConverter struct {
	configured bool
	objectType byte
	sampleRate byte
	channels   byte
}

func (c *ADTSConverter) Convert(dst, ame []byte) ([]byte, error) {
	if len(ame) == 0 {
		return dst, ErrEmptySample
	}
	r := bitReader{b: ame}
	same, ok := r.bits(1)
	if !ok {
		return dst, ErrLATMSyntax
	}
	if same == 0 {
		if !c.readConfig(&r) {
			return dst, ErrLATMSyntax
		}
	} else if !c.configured {
		return dst, ErrLATMSyntax
	}

	length := 0
	for {
		n, ok := r.bits(8)
		if !ok {
			return dst, ErrLATMSyntax
		}
		length += int(n)
		if n != 255 {
			break
		}
	}
	if length <= 0 || length+7 > 0x1fff || r.remaining() < length*8 {
		if length+7 > 0x1fff {
			return dst, ErrADTSFrameTooLong
		}
		return dst, ErrLATMSyntax
	}
	raw := make([]byte, length)
	for i := range raw {
		v, _ := r.bits(8)
		raw[i] = byte(v)
	}
	frameLength := length + 7
	profile := c.objectType - 1
	fullness := 0x7ff
	dst = append(dst,
		0xff,
		0xf1,
		profile<<6|c.sampleRate<<2|c.channels>>2,
		(c.channels&3)<<6|byte(frameLength>>11),
		byte(frameLength>>3),
		byte(frameLength&7)<<5|byte(fullness>>6),
		byte(fullness&0x3f)<<2,
	)
	return append(dst, raw...), nil
}

func (c *ADTSConverter) readConfig(r *bitReader) bool {
	version, ok := r.bits(1)
	if !ok || version != 0 {
		return false
	}
	allSame, ok := r.bits(1)
	if !ok || allSame == 0 {
		return false
	}
	subframes, ok := r.bits(6)
	if !ok || subframes != 0 {
		return false
	}
	programs, ok := r.bits(4)
	if !ok || programs != 0 {
		return false
	}
	layers, ok := r.bits(3)
	if !ok || layers != 0 {
		return false
	}
	aot, ok := r.bits(5)
	if !ok || aot < 1 || aot > 4 {
		return false
	}
	rate, ok := r.bits(4)
	if !ok || rate == 0x0f {
		return false
	}
	channels, ok := r.bits(4)
	if !ok || channels == 0 || channels > 7 {
		return false
	}
	frameLengthFlag, ok := r.bits(1)
	if !ok || frameLengthFlag != 0 {
		return false
	}
	depends, ok := r.bits(1)
	if !ok || depends != 0 {
		return false
	}
	extension, ok := r.bits(1)
	if !ok || extension != 0 {
		return false
	}
	frameLengthType, ok := r.bits(3)
	if !ok || frameLengthType != 0 {
		return false
	}
	if _, ok = r.bits(8); !ok {
		return false
	}
	other, ok := r.bits(1)
	if !ok || other != 0 {
		return false
	}
	crc, ok := r.bits(1)
	if !ok {
		return false
	}
	if crc != 0 {
		if _, ok = r.bits(8); !ok {
			return false
		}
	}
	c.objectType, c.sampleRate, c.channels = byte(aot), byte(rate), byte(channels)
	c.configured = true
	return true
}

type bitReader struct {
	b   []byte
	pos int
}

func (r *bitReader) bits(n int) (uint32, bool) {
	if n < 0 || n > 32 || r.remaining() < n {
		return 0, false
	}
	var v uint32
	for range n {
		v = v<<1 | uint32(r.b[r.pos>>3]>>(7-(r.pos&7))&1)
		r.pos++
	}
	return v, true
}

func (r *bitReader) remaining() int { return len(r.b)*8 - r.pos }
