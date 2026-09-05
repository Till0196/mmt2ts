// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package escan

// H.264 はインタレースの情報を三箇所に分けて持つ。
// シーケンスパラメータ集合がフィールドを使ってよいかを言い、
// スライスヘッダーがそのピクチャがフィールドかどうかを言い、
// picture timing SEI が表示のしかたを言う。
// 三つは一致しなくてもよい決まりなので、それぞれ別に読む。

// sarTable は aspect_ratio_idc から標本の縦横比への表。0 と 255 は表に無い。
var sarTable = [17][2]int{
	1: {1, 1}, 2: {12, 11}, 3: {10, 11}, 4: {16, 11}, 5: {40, 33}, 6: {24, 11},
	7: {20, 11}, 8: {32, 11}, 9: {80, 33}, 10: {18, 11}, 11: {15, 11}, 12: {64, 33},
	13: {160, 99}, 14: {4, 3}, 15: {3, 2}, 16: {2, 1},
}

type avcSPS struct {
	format Format

	separatePlane bool
	frameNumBits  int
	frameMBsOnly  bool

	picStructPresent bool
	cpbDelays        bool
	cpbRemovalBits   int
	dpbOutputBits    int
}

type avcState struct {
	sps map[uint]*avcSPS
	pps map[uint]uint
}

func (st *avcState) put(id uint, sps *avcSPS) {
	if st.sps == nil {
		st.sps = map[uint]*avcSPS{}
	}
	st.sps[id] = sps
}

func (st *avcState) link(pps, sps uint) {
	if st.pps == nil {
		st.pps = map[uint]uint{}
	}
	st.pps[pps] = sps
}

func (st *avcState) lookup(pps uint) *avcSPS {
	id, ok := st.pps[pps]
	if !ok {
		return nil
	}
	return st.sps[id]
}

// avcPicture は1つのアクセスユニットを読む。
//
// パラメータ集合が来る前のピクチャは読めないので落とす。
// 途中から拾ったストリームでは最初の何枚かがこれにあたるが、推測で埋めると実装ごとに違う値になる。
func (s *Scanner) avcPicture(units []nalu, size int) (Picture, bool) {
	st := &s.avc
	picture := Picture{Structure: Frame, Size: size}
	picStruct := -1
	var sps *avcSPS

	for _, unit := range units {
		switch unit.kind(H264) {
		case 7: // sequence parameter set
			id, parsed := parseAVCSPS(unit.rbspOf(H264))
			if parsed != nil {
				st.put(id, parsed)
			}
		case 8: // picture parameter set
			b := &bits{buf: unit.rbspOf(H264)}
			pps := b.ue()
			st.link(pps, b.ue())
		case 6: // supplemental enhancement information
			if sps == nil {
				sps = st.anySPS()
			}
			if sps == nil || !sps.picStructPresent {
				continue
			}
			if v, ok := avcPicStruct(unit.rbspOf(H264), sps); ok {
				picStruct = v
			}
		case 1, 5:
			if picture.Coding != 0 {
				continue // 2枚目以降のスライス。ピクチャの申告は先頭のものを採る
			}
			b := &bits{buf: unit.rbspOf(H264)}
			if b.ue() != 0 { // first_mb_in_slice
				continue
			}
			sliceType := b.ue() % 5
			active := st.lookup(b.ue())
			if active == nil {
				continue
			}
			sps = active
			if active.separatePlane {
				b.u(2)
			}
			b.u(active.frameNumBits)
			if !active.frameMBsOnly && b.flag() { // field_pic_flag
				picture.Structure = Top
				if b.flag() { // bottom_field_flag
					picture.Structure = Bottom
				}
			}
			switch sliceType {
			case 0, 3:
				picture.Coding = 'p'
			case 1:
				picture.Coding = 'b'
			default:
				picture.Coding = 'i'
			}
			// 復号を始められるのは IDR だけ。
			// 放送は recovery point SEI でしか入口を示さないことが多いが、その扱いは投入側の判断なのでここでは規格どおりに出す。
			picture.RAP = unit.kind(H264) == 5
		}
	}
	if picture.Coding == 0 || sps == nil {
		return Picture{}, false
	}
	picture.Format = sps.format
	picture.TFF, picture.RFF = picStructDisplay(picStruct)
	// H.264 のピクチャは progressive の申告を持たない。
	// シーケンスがフィールドを禁じているときだけ、progressive と言い切れる。
	if sps.frameMBsOnly {
		picture.Prog = 1
	}
	return picture, true
}

// anySPS は識別子の一番若いものを返す。SEI は参照する集合を指さないので、こうするしかない。
func (st *avcState) anySPS() *avcSPS {
	var out *avcSPS
	var best uint
	for id, sps := range st.sps {
		if out == nil || id < best {
			out, best = sps, id
		}
	}
	return out
}

// picStructDisplay は pic_struct から top_field_first と repeat_first_field にあたる値を導く。
// MPEG-2 と違い H.264 と HEVC はこの二つを持たないので、表示の指示から読み替える。
func picStructDisplay(picStruct int) (tff, rff int) {
	switch picStruct {
	case 3, 5:
		tff = 1
	}
	switch picStruct {
	case 5, 6:
		rff = 1
	}
	return tff, rff
}

func parseAVCSPS(payload []byte) (uint, *avcSPS) {
	var s avcSPS
	b := &bits{buf: payload}
	profile := int(b.u(8))
	b.u(8) // constraint flags and reserved
	b.u(8) // level_idc
	id := b.ue()

	chroma := uint(1)
	depth := 8
	switch profile {
	case 100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135:
		chroma = b.ue()
		if chroma == 3 {
			s.separatePlane = b.flag()
		}
		depth = int(b.ue()) + 8
		b.ue()   // bit_depth_chroma_minus8
		b.flag() // qpprime_y_zero_transform_bypass_flag
		if b.flag() {
			lists := 8
			if chroma == 3 {
				lists = 12
			}
			for i := 0; i < lists; i++ {
				if !b.flag() {
					continue
				}
				size := 16
				if i >= 6 {
					size = 64
				}
				last, next := 8, 8
				for j := 0; j < size; j++ {
					if next != 0 {
						next = (last + b.se() + 256) % 256
					}
					if next != 0 {
						last = next
					}
				}
			}
		}
	}
	s.format.Chroma, s.format.Depth = int(chroma), depth

	s.frameNumBits = int(b.ue()) + 4
	switch b.ue() { // pic_order_cnt_type
	case 0:
		b.ue()
	case 1:
		b.flag()
		b.se()
		b.se()
		n := b.ue()
		for i := uint(0); i < n && i < 256; i++ {
			b.se()
		}
	}
	b.ue()   // max_num_ref_frames
	b.flag() // gaps_in_frame_num_value_allowed_flag
	width := (int(b.ue()) + 1) * 16
	height := (int(b.ue()) + 1) * 16
	s.frameMBsOnly = b.flag()
	if !s.frameMBsOnly {
		b.flag() // mb_adaptive_frame_field_flag
		height *= 2
	}
	b.flag() // direct_8x8_inference_flag
	if b.flag() {
		// 切り出しの単位は色差の間引きとフィールド符号化の有無で変わる。
		// 1440x1088 が 1080 になるのはここで、申告された解像度をそのまま出すと8ライン多い。
		subWidth, subHeight := 1, 1
		if chroma == 1 || chroma == 2 {
			subWidth = 2
		}
		if chroma == 1 {
			subHeight = 2
		}
		if chroma == 0 || s.separatePlane {
			subWidth, subHeight = 1, 1
		}
		unitY := subHeight
		if !s.frameMBsOnly {
			unitY *= 2
		}
		left, right := int(b.ue()), int(b.ue())
		top, bottom := int(b.ue()), int(b.ue())
		width -= (left + right) * subWidth
		height -= (top + bottom) * unitY
	}
	s.format.Width, s.format.Height = width, height
	s.format.RateDen = 1
	s.format.AspectDen = 1
	sarNum, sarDen := 0, 0
	if b.flag() { // vui_parameters_present_flag
		sarNum, sarDen = parseAVCVUI(b, &s)
	}
	if s.frameMBsOnly {
		s.format.Progressive = 1
	}
	s.format.AspectNum, s.format.AspectDen = displayAspect(width, height, sarNum, sarDen)
	return id, &s
}

// displayAspect は標本の比から画面全体の比を出す。申告が無ければ 0/1 にする。
func displayAspect(width, height, sarNum, sarDen int) (int, int) {
	if sarNum <= 0 || sarDen <= 0 {
		return 0, 1
	}
	return ratio(width*sarNum, height*sarDen)
}

func parseAVCVUI(b *bits, s *avcSPS) (int, int) {
	sarNum, sarDen := 0, 0
	if b.flag() { // aspect_ratio_info_present_flag
		idc := b.u(8)
		switch {
		case idc == 255:
			sarNum, sarDen = int(b.u(16)), int(b.u(16))
		case idc < uint(len(sarTable)):
			sarNum, sarDen = sarTable[idc][0], sarTable[idc][1]
		}
	}
	if b.flag() { // overscan_info_present_flag
		b.flag()
	}
	if b.flag() { // video_signal_type_present_flag
		b.u(3)
		b.flag()
		if b.flag() {
			b.u(24)
		}
	}
	if b.flag() { // chroma_loc_info_present_flag
		b.ue()
		b.ue()
	}
	if b.flag() { // timing_info_present_flag
		units := int(b.u(32))
		scale := int(b.u(32))
		b.flag() // fixed_frame_rate_flag
		// time_scale はフィールドの数え方なので、框率にするには2で割る。
		s.format.RateNum, s.format.RateDen = ratio(scale, units*2)
	}
	nal := b.flag()
	if nal {
		parseAVCHRD(b, s)
	}
	vcl := b.flag()
	if vcl {
		parseAVCHRD(b, s)
	}
	if nal || vcl {
		s.cpbDelays = true
		b.flag() // low_delay_hrd_flag
	}
	s.picStructPresent = b.flag()
	return sarNum, sarDen
}

// parseAVCHRD は遅延の桁数だけを取る。picture timing SEI で pic_struct の前に何ビット立つかがこれで決まる。
func parseAVCHRD(b *bits, s *avcSPS) {
	n := b.ue() + 1
	b.u(4)
	b.u(4)
	for i := uint(0); i < n && i < 32; i++ {
		b.ue()
		b.ue()
		b.flag()
	}
	b.u(5) // initial_cpb_removal_delay_length_minus1
	s.cpbRemovalBits = int(b.u(5)) + 1
	s.dpbOutputBits = int(b.u(5)) + 1
	b.u(5) // time_offset_length
}

func avcPicStruct(payload []byte, sps *avcSPS) (int, bool) {
	value, found := -1, false
	forEachSEI(payload, func(kind int, body []byte) {
		if kind != 1 || found {
			return
		}
		b := &bits{buf: body}
		if sps.cpbDelays {
			b.u(sps.cpbRemovalBits)
			b.u(sps.dpbOutputBits)
		}
		value, found = int(b.u(4)), true
	})
	return value, found
}

// forEachSEI は SEI の NAL に並ぶメッセージを順に渡す。
func forEachSEI(payload []byte, visit func(kind int, body []byte)) {
	i := 0
	for i < len(payload) {
		kind := 0
		for i < len(payload) && payload[i] == 0xff {
			kind += 255
			i++
		}
		if i >= len(payload) {
			return
		}
		kind += int(payload[i])
		i++
		size := 0
		for i < len(payload) && payload[i] == 0xff {
			size += 255
			i++
		}
		if i >= len(payload) {
			return
		}
		size += int(payload[i])
		i++
		if i+size > len(payload) {
			return
		}
		visit(kind, payload[i:i+size])
		i += size
	}
}
