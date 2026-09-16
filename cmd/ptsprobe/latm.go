// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

// latmReader は AudioMuxElement を先頭から読むためのビット列。
type latmReader struct {
	b   []byte
	pos int
}

func (r *latmReader) bits(n int) uint32 {
	var v uint32
	for range n {
		if r.pos >= len(r.b)*8 {
			return v << 1
		}
		bit := (r.b[r.pos/8] >> (7 - r.pos%8)) & 1
		v = v<<1 | uint32(bit)
		r.pos++
	}
	return v
}

// latmValue は LatmGetValue()。1バイト単位の可変長。
func (r *latmReader) latmValue() uint32 {
	n := int(r.bits(2))
	var v uint32
	for range n + 1 {
		v = v<<8 | r.bits(8)
	}
	return v
}

var sampleRates = [...]int{
	96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
	16000, 12000, 11025, 8000, 7350, 0, 0, 0,
}

// 14496-3 の channelConfiguration。13 が 22.2ch。
var channelConfigs = map[uint32]string{
	0: "PCE参照", 1: "1/0 モノラル", 2: "2/0 ステレオ", 3: "3/0", 4: "3/1",
	5: "3/2 (5.0)", 6: "3/2.1 (5.1)", 7: "5/2.1 (7.1)",
	11: "6.1", 12: "7.1", 13: "22.2", 14: "7.1 top",
}

// audioConfig は LATM の AudioMuxElement から AudioSpecificConfig を取り出す。
func audioConfig(au []byte) string {
	r := &latmReader{b: au}
	_ = au
	if r.bits(1) == 1 { // useSameStreamMux
		return "useSameStreamMux (設定は前のフレーム)"
	}
	muxVersion := r.bits(1)
	_ = muxVersion
	var versionA uint32
	if muxVersion == 1 {
		versionA = r.bits(1)
	}
	if versionA != 0 {
		return "audioMuxVersionA=1 (未対応)"
	}
	if muxVersion == 1 {
		r.latmValue() // taraBufferFullness
	}
	sameTime := r.bits(1)
	subFrames := r.bits(6)
	programs := r.bits(4)
	layers := r.bits(3)
	if muxVersion == 1 {
		r.latmValue() // ascLen
	}
	objectType := r.bits(5)
	if objectType == 31 {
		objectType = 32 + r.bits(6)
	}
	freqIndex := r.bits(4)
	rate := 0
	if freqIndex == 0x0f {
		rate = int(r.bits(24))
	} else {
		rate = sampleRates[freqIndex]
	}
	channels := r.bits(4)
	name, ok := channelConfigs[channels]
	if !ok {
		name = "予約"
	}
	note := ""
	if programs > 0 || layers > 0 {
		// 複数プログラムの LATM は、最初のプログラムの
		// AudioSpecificConfig しか読めていない。
		note = "  ※複数プログラム。以下は先頭プログラムのみ"
	}
	_ = sameTime
	return fmt.Sprintf(
		"programs=%d layers=%d subFrames=%d%s\n      AOT=%d %s / %d Hz / channelConfiguration=%d (%s)",
		programs+1, layers+1, subFrames+1, note,
		objectType, objectTypeName(objectType), rate, channels, name)
}

func objectTypeName(t uint32) string {
	switch t {
	case 2:
		return "AAC LC"
	case 5:
		return "SBR"
	case 29:
		return "PS"
	case 17:
		return "ER AAC LC"
	case 42:
		return "USAC"
	default:
		return "?"
	}
}
