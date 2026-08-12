// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package codecrev はAnnex BとAACフレームをMMTのサンプル形式へ戻す。
package codecrev

import (
	"encoding/binary"
	"errors"
)

var (
	ErrNoStartCode = errors.New("codecrev: no Annex B start code found")
	ErrBadADTS     = errors.New("codecrev: malformed ADTS header")
	ErrBadLOAS     = errors.New("codecrev: malformed AudioSyncStream header")
	ErrEmptyFrame  = errors.New("codecrev: empty AAC frame")
	ErrBadConfig   = errors.New("codecrev: unsupported audio object type")
)

func AnnexBToSample(annexB []byte) ([]byte, error) {
	samples, err := AnnexBToNALSamples(annexB)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(annexB))
	for _, sample := range samples {
		out = append(out, sample...)
	}
	return out, nil
}

func AnnexBToNALSamples(annexB []byte) ([][]byte, error) {
	nals, err := splitAnnexB(annexB)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(nals))
	for _, nal := range nals {
		sample := make([]byte, 4, 4+len(nal))
		binary.BigEndian.PutUint32(sample, uint32(len(nal)))
		sample = append(sample, nal...)
		out = append(out, sample)
	}
	return out, nil
}

func splitAnnexB(b []byte) ([][]byte, error) {
	type startCode struct{ offset, length int }
	var starts []startCode
	for i := 0; i+2 < len(b); {
		switch {
		case i+3 < len(b) && b[i] == 0 && b[i+1] == 0 && b[i+2] == 0 && b[i+3] == 1:
			starts = append(starts, startCode{i, 4})
			i += 4
		case b[i] == 0 && b[i+1] == 0 && b[i+2] == 1:
			starts = append(starts, startCode{i, 3})
			i += 3
		default:
			i++
		}
	}
	if len(starts) == 0 {
		return nil, ErrNoStartCode
	}
	nals := make([][]byte, 0, len(starts))
	for i, s := range starts {
		nalStart := s.offset + s.length
		nalEnd := len(b)
		if i+1 < len(starts) {
			nalEnd = starts[i+1].offset
		}
		if nalStart > nalEnd {
			continue
		}
		nals = append(nals, b[nalStart:nalEnd])
	}
	return nals, nil
}

type ADTSInfo struct {
	ObjectType      byte
	SampleRateIndex byte
	ChannelConfig   byte
}

func SplitADTS(b []byte) ([]ADTSInfo, [][]byte, error) {
	var infos []ADTSInfo
	var raws [][]byte
	for len(b) > 0 {
		if len(b) < 7 || b[0] != 0xff || b[1]&0xf6 != 0xf0 {
			return nil, nil, ErrBadADTS
		}
		info := ADTSInfo{
			ObjectType:      (b[2] >> 6) + 1,
			SampleRateIndex: (b[2] >> 2) & 0x0f,
			ChannelConfig:   (b[2]&0x01)<<2 | b[3]>>6,
		}
		frameLength := int(b[3]&0x03)<<11 | int(b[4])<<3 | int(b[5]>>5)
		headerLength := 7
		if b[1]&0x01 == 0 {
			headerLength = 9
		}
		if frameLength < headerLength || frameLength > len(b) {
			return nil, nil, ErrBadADTS
		}
		infos = append(infos, info)
		raws = append(raws, b[headerLength:frameLength])
		b = b[frameLength:]
	}
	return infos, raws, nil
}

func CompleteADTSPrefix(b []byte) int {
	n := 0
	for n < len(b) {
		rest := b[n:]
		if len(rest) < 7 || rest[0] != 0xff || rest[1]&0xf6 != 0xf0 {
			break
		}
		frameLength := int(rest[3]&0x03)<<11 | int(rest[4])<<3 | int(rest[5]>>5)
		headerLength := 7
		if rest[1]&0x01 == 0 {
			headerLength = 9
		}
		if frameLength < headerLength || frameLength > len(rest) {
			break
		}
		n += frameLength
	}
	return n
}

func ADTSFrames(b []byte) ([][]byte, byte) {
	var out [][]byte
	var rate byte
	for n := 0; n < len(b); {
		rest := b[n:]
		if len(rest) < 7 || rest[0] != 0xff || rest[1]&0xf6 != 0xf0 {
			break
		}
		frameLength := int(rest[3]&0x03)<<11 | int(rest[4])<<3 | int(rest[5]>>5)
		headerLength := 7
		if rest[1]&0x01 == 0 {
			headerLength = 9
		}
		if frameLength < headerLength || frameLength > len(rest) {
			break
		}
		if len(out) == 0 {
			rate = (rest[2] >> 2) & 0x0f
		}
		out = append(out, rest[:frameLength])
		n += frameLength
	}
	return out, rate
}

func ADTSSampleRate(index byte) int {
	rates := [...]int{96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350}
	if int(index) >= len(rates) {
		return 0
	}
	return rates[index]
}

func BuildAudioMuxElement(cfg ADTSInfo, rawAAC []byte) ([]byte, error) {
	if len(rawAAC) == 0 {
		return nil, ErrEmptyFrame
	}
	if cfg.ObjectType < 1 || cfg.ObjectType > 4 {
		return nil, ErrBadConfig
	}
	var w bitWriter
	w.writeBits(0, 1)
	w.writeBits(0, 1)
	w.writeBits(1, 1)
	w.writeBits(0, 6)
	w.writeBits(0, 4)
	w.writeBits(0, 3)
	w.writeBits(uint32(cfg.ObjectType), 5)
	w.writeBits(uint32(cfg.SampleRateIndex), 4)
	w.writeBits(uint32(cfg.ChannelConfig), 4)
	w.writeBits(0, 1)
	w.writeBits(0, 1)
	w.writeBits(0, 1)
	w.writeBits(0, 3)
	w.writeBits(0, 8)
	w.writeBits(0, 1)
	w.writeBits(1, 1)
	w.writeBits(0, 8)

	n := len(rawAAC)
	for n >= 255 {
		w.writeBits(255, 8)
		n -= 255
	}
	w.writeBits(uint32(n), 8)
	for _, b := range rawAAC {
		w.writeBits(uint32(b), 8)
	}
	return w.buf, nil
}

func StripLOAS(b []byte) ([]byte, error) {
	if len(b) < 3 || b[0] != 0x56 || b[1]&0xe0 != 0xe0 {
		return nil, ErrBadLOAS
	}
	n := int(b[1]&0x1f)<<8 | int(b[2])
	if 3+n > len(b) {
		return nil, ErrBadLOAS
	}
	return b[3 : 3+n], nil
}

type bitWriter struct {
	buf []byte
	pos int
}

func (w *bitWriter) writeBits(v uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		bit := byte(v>>uint(i)) & 1
		idx := w.pos >> 3
		for idx >= len(w.buf) {
			w.buf = append(w.buf, 0)
		}
		w.buf[idx] |= bit << (7 - uint(w.pos&7))
		w.pos++
	}
}
