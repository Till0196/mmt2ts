// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package escan

// MPEG-2 のインタレース関連の申告は picture header ではなく picture coding extension にある。
// picture header から読めるのは符号化種別だけで、フレームかフィールドかは拡張を読むまで分からない。

// frameRates は frame_rate_code の表。0 と 9 以降は予約で、申告が無いものとして扱う。
var frameRates = [16][2]int{
	1: {24000, 1001},
	2: {24, 1},
	3: {25, 1},
	4: {30000, 1001},
	5: {30, 1},
	6: {50, 1},
	7: {60000, 1001},
	8: {60, 1},
}

type mpeg2State struct {
	valid  bool
	format Format

	width, height int
	aspectCode    int
	rateCode      int
}

// pushMPEG2 は開始符号を辿り、アクセスユニットごとに1枚のピクチャを返す。
//
// アクセスユニットの切れ目は sequence header、GOP header、picture header のうち、
// ピクチャを1枚読み終えた後に最初に現れたものに置く。
// こうするとシーケンスヘッダーは後続のピクチャ側に付き、ランダムアクセス点の判定が1つのアクセスユニットで完結する。
func (s *Scanner) pushMPEG2(payload []byte) []Picture {
	type span struct {
		start int
		codes []int // 開始符号の位置
	}
	var spans []span
	sawPicture := false
	for i := 0; i+3 < len(payload); i++ {
		if payload[i] != 0 || payload[i+1] != 0 || payload[i+2] != 1 {
			continue
		}
		code := payload[i+3]
		if code == 0xb3 || code == 0xb8 || code == 0x00 {
			if sawPicture || len(spans) == 0 {
				spans = append(spans, span{start: codeStart(payload, i)})
				sawPicture = false
			}
		}
		if len(spans) == 0 {
			continue
		}
		if code == 0x00 {
			sawPicture = true
		}
		last := &spans[len(spans)-1]
		last.codes = append(last.codes, i)
	}

	out := make([]Picture, 0, 4)
	for i, sp := range spans {
		end := len(payload)
		if i+1 < len(spans) {
			end = spans[i+1].start
		}
		if picture, ok := s.mpeg2Picture(payload, sp.codes, end-sp.start); ok {
			out = append(out, picture)
		}
	}
	return out
}

func (s *Scanner) mpeg2Picture(payload []byte, codes []int, size int) (Picture, bool) {
	st := &s.mpeg2
	picture := Picture{Structure: Frame, Size: size}
	sequence, coding, found := false, 0, false

	for _, i := range codes {
		switch payload[i+3] {
		case 0xb3: // sequence_header
			if i+11 >= len(payload) {
				continue
			}
			st.width = int(payload[i+4])<<4 | int(payload[i+5]>>4)
			st.height = int(payload[i+5]&0x0f)<<8 | int(payload[i+6])
			st.aspectCode = int(payload[i+7] >> 4)
			st.rateCode = int(payload[i+7] & 0x0f)
			st.valid = true
			sequence = true
		case 0x00: // picture_header
			if i+5 >= len(payload) {
				continue
			}
			coding = int(payload[i+5]>>3) & 0x07
		case 0xb5: // extension_start_code
			if i+4 >= len(payload) {
				continue
			}
			switch payload[i+4] >> 4 {
			case 1: // sequence extension
				st.readSequenceExtension(payload[i+4:])
			case 8: // picture coding extension
				if i+8 >= len(payload) {
					continue
				}
				b2, b3, b4 := payload[i+6], payload[i+7], payload[i+8]
				switch b2 & 0x03 {
				case 1:
					picture.Structure = Top
				case 2:
					picture.Structure = Bottom
				}
				picture.TFF = int(b3>>7) & 1
				picture.RFF = int(b3>>1) & 1
				picture.Prog = int(b4>>7) & 1
				found = true
			}
		}
	}
	if !found || !st.valid {
		return Picture{}, false
	}
	switch coding {
	case 1:
		picture.Coding = 'i'
	case 2:
		picture.Coding = 'p'
	case 3:
		picture.Coding = 'b'
	}
	// 復号を始められるのは sequence header の付いた I ピクチャだけ。
	// フィールドピクチャの I は相方の P が揃うまで一枚の絵にならないが、その判断は投入側の仕事なのでここでは申告どおりに出す。
	picture.RAP = sequence && coding == 1
	picture.Format = st.finish()
	return picture, true
}

// readSequenceExtension は拡張識別子の4ビットから続きを読む。
func (st *mpeg2State) readSequenceExtension(b []byte) {
	r := &bits{buf: b}
	r.u(4) // extension_start_code_identifier
	r.u(8) // profile_and_level_indication
	progressive := int(r.u(1))
	chroma := int(r.u(2))
	horizontal := int(r.u(2))
	vertical := int(r.u(2))
	r.u(12) // bit_rate_extension
	r.u(1)  // marker_bit
	r.u(8)  // vbv_buffer_size_extension
	r.u(1)  // low_delay
	rateN := int(r.u(2))
	rateD := int(r.u(5))

	st.format.Progressive = progressive
	st.format.Chroma = chroma
	st.format.Depth = 8
	st.width |= horizontal << 12
	st.height |= vertical << 12
	base := frameRates[st.rateCode]
	st.format.RateNum, st.format.RateDen = ratio(base[0]*(rateN+1), base[1]*(rateD+1))
}

func (st *mpeg2State) finish() Format {
	f := st.format
	f.Width, f.Height = st.width, st.height
	if f.Depth == 0 {
		f.Depth = 8
	}
	if f.RateNum == 0 {
		base := frameRates[st.rateCode]
		f.RateNum, f.RateDen = ratio(base[0], base[1])
	}
	// aspect_ratio_information は標本の比ではなく画面全体の比を申告する。
	// 1 だけが例外で、標本が正方形であることを言うので、比は解像度から出す。
	switch st.aspectCode {
	case 1:
		f.AspectNum, f.AspectDen = ratio(st.width, st.height)
	case 2:
		f.AspectNum, f.AspectDen = 4, 3
	case 3:
		f.AspectNum, f.AspectDen = 16, 9
	case 4:
		f.AspectNum, f.AspectDen = 221, 100
	default:
		f.AspectNum, f.AspectDen = 0, 1
	}
	return f
}
