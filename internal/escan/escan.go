// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package escan は映像の基本ストリームを読み、アクセスユニット1つごとにピクチャの構造を返す。
//
// 見るのは符号化の申告であって、映像の中身ではない。
// 日本の放送では picture coding extension の progressive_frame や repeat_first_field が内容を反映しないので、
// これらを見て表示方法を切り替える設計は成立しない（coax-notes/interlace.md）。
// それでも、フレームかフィールドかという符号化そのものの区別は復号側が必ず要る情報なので、ここで取り出す。
//
// 入れ物からの取り出し方は2通りある。
// TS からは PES のペイロードを Annex B のバイト列として Push に渡し、
// MMT/TLV からは組み立て済みのアクセスユニットを NAL 単位で PushUnits に渡す。
package escan

// Codec は基本ストリームの符号化方式。
type Codec byte

const (
	MPEG2 Codec = iota
	H264
	HEVC
)

func (c Codec) String() string {
	switch c {
	case MPEG2:
		return "mpeg2"
	case H264:
		return "h264"
	}
	return "hevc"
}

// CodecOfStreamType は PMT の stream_type を符号化方式に直す。
func CodecOfStreamType(streamType byte) (Codec, bool) {
	switch streamType {
	case 0x01, 0x02:
		return MPEG2, true
	case 0x1b:
		return H264, true
	case 0x24:
		return HEVC, true
	}
	return 0, false
}

// CodecOfAssetType は MPT のアセット種別を符号化方式に直す。
func CodecOfAssetType(kind string) (Codec, bool) {
	switch kind {
	case "hev1", "hvc1":
		return HEVC, true
	case "avc1", "avc3":
		return H264, true
	}
	return 0, false
}

// Format はシーケンス全体の申告。
//
// 申告が読めなかった項目は0のままで、比は 0/1 になる。
type Format struct {
	Width, Height        int
	Depth, Chroma        int
	RateNum, RateDen     int
	Progressive          int
	AspectNum, AspectDen int
}

// ピクチャの構造。フィールドピクチャかどうかは復号側の作りを分ける。
const (
	Frame  = "frame"
	Top    = "top"
	Bottom = "bottom"
)

// Picture はアクセスユニット1つ。
type Picture struct {
	Format    Format
	Coding    byte // 'i' / 'p' / 'b'、読めなければ 0
	Structure string
	TFF       int
	RFF       int
	Prog      int
	RAP       bool
	Size      int
}

// Scanner は1つの基本ストリームを追う。
//
// シーケンスの申告は次の申告が来るまで持ち越すので、ストリームごとに1つ作って使い回す。
type Scanner struct {
	codec Codec
	mpeg2 mpeg2State
	avc   avcState
	hevc  hevcState
}

func New(codec Codec) *Scanner { return &Scanner{codec: codec} }

func (s *Scanner) Codec() Codec { return s.codec }

// Push は Annex B のバイト列を1つ食わせ、その中のアクセスユニットを順に返す。
//
// PES のペイロードにピクチャがちょうど1枚だけ入っている保証は無いので、見つかった数だけ返す。
// ペイロードの末尾は必ずアクセスユニットの末尾として扱う。
// 映像の PES は必ずアクセスユニットの先頭で始まるため、跨ぎを持ち越すよりも入れ物の切れ目を信じる方が実装間で揃う。
func (s *Scanner) Push(payload []byte) []Picture {
	if s.codec == MPEG2 {
		return s.pushMPEG2(payload)
	}
	units, bounds := s.splitAnnexB(payload)
	out := make([]Picture, 0, 4)
	for i, at := range bounds {
		end := len(payload)
		if i+1 < len(bounds) {
			end = units[bounds[i+1]].at
		}
		start := units[at].at
		last := len(units)
		if i+1 < len(bounds) {
			last = bounds[i+1]
		}
		if picture, ok := s.unitsPicture(units[at:last], end-start); ok {
			out = append(out, picture)
		}
	}
	return out
}

// PushUnits は組み立て済みのアクセスユニットを、開始符号を剥がした NAL の並びとして食わせる。
//
// MMT/TLV ではデータユニットが NAL 1つにあたるので、入れ物の側で既に切れている。
func (s *Scanner) PushUnits(nalus [][]byte, size int) (Picture, bool) {
	if s.codec == MPEG2 {
		return Picture{}, false
	}
	units := make([]nalu, 0, len(nalus))
	for _, body := range nalus {
		units = append(units, nalu{body: body})
	}
	return s.unitsPicture(units, size)
}

func (s *Scanner) unitsPicture(units []nalu, size int) (Picture, bool) {
	if s.codec == H264 {
		return s.avcPicture(units, size)
	}
	return s.hevcPicture(units, size)
}

// nalu は1つの NAL と、それが Annex B のどこから始まっていたか。
type nalu struct {
	at   int // 開始符号の先頭。PushUnits から来たものでは意味を持たない
	body []byte
}

func (n nalu) kind(codec Codec) int {
	if len(n.body) == 0 {
		return -1
	}
	if codec == H264 {
		return int(n.body[0] & 0x1f)
	}
	if len(n.body) < 2 {
		return -1
	}
	return int(n.body[0]>>1) & 0x3f
}

// rbspOf は NAL ヘッダーを落とした中身を返す。H.264 は1バイト、HEVC は2バイト。
func (n nalu) rbspOf(codec Codec) []byte {
	skip := 1
	if codec != H264 {
		skip = 2
	}
	if len(n.body) < skip {
		return nil
	}
	return rbsp(n.body[skip:])
}

// splitAnnexB は開始符号で区切り、アクセスユニットの先頭にあたる NAL の位置も返す。
//
// 区切りは、ピクチャの先頭スライスと、その前に立つパラメータ集合や SEI で決める。
// 放送はアクセスユニット区切り NAL を必ず入れてくるとは限らないので、それだけに頼らない。
func (s *Scanner) splitAnnexB(payload []byte) ([]nalu, []int) {
	var units []nalu
	for i := 0; i+3 < len(payload); {
		if payload[i] != 0 || payload[i+1] != 0 || payload[i+2] != 1 {
			i++
			continue
		}
		at := i
		if at > 0 && payload[at-1] == 0 {
			at--
		}
		start := i + 3
		end := start
		for end+3 <= len(payload) && !(payload[end] == 0 && payload[end+1] == 0 && payload[end+2] == 1) {
			end++
		}
		if end+3 > len(payload) {
			end = len(payload)
		}
		body := payload[start:end]
		for len(body) > 0 && body[len(body)-1] == 0 {
			body = body[:len(body)-1]
		}
		units = append(units, nalu{at: at, body: body})
		i = end
	}

	var bounds []int
	sawSlice := false
	for i, unit := range units {
		kind := unit.kind(s.codec)
		switch {
		case s.leading(kind):
			if sawSlice || len(bounds) == 0 {
				bounds = append(bounds, i)
				sawSlice = false
			}
		case s.firstSlice(kind, unit):
			if sawSlice || len(bounds) == 0 {
				bounds = append(bounds, i)
			}
			sawSlice = true
		}
	}
	return units, bounds
}

// leading はアクセスユニットの先頭に立ちうる NAL かどうか。
// スライスの後に来る SEI や詰め物をここに入れると、1枚のピクチャが2つに割れる。
func (s *Scanner) leading(kind int) bool {
	if s.codec == H264 {
		switch kind {
		case 6, 7, 8, 9, 13, 14, 15:
			return true
		}
		return false
	}
	switch kind {
	case 32, 33, 34, 35, 39:
		return true
	}
	return false
}

// firstSlice はピクチャの最初のスライスかどうか。2枚目以降のスライスで区切ると1枚のピクチャを数え過ぎる。
func (s *Scanner) firstSlice(kind int, unit nalu) bool {
	if s.codec == H264 {
		if kind < 1 || kind > 5 {
			return false
		}
		b := &bits{buf: unit.rbspOf(H264)}
		return b.ue() == 0
	}
	if kind < 0 || kind > 31 {
		return false
	}
	b := &bits{buf: unit.rbspOf(HEVC)}
	return b.flag()
}
