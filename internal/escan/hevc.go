// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package escan

// HEVC には MPEG-2 や H.264 のようなフィールドピクチャが無い。
// 符号化されたピクチャは常に1枚のピクチャで、インタレースはその中身についての申告になる。
// したがって structure と prog は profile_tier_level と VUI ではなく、picture timing SEI の pic_struct と
// source_scan_type から導く。申告が無ければフレームとして出す。

const (
	nalHEVCSPS       = 33
	nalHEVCPPS       = 34
	nalHEVCPrefixSEI = 39
)

type hevcSPS struct {
	format Format
}

type hevcState struct {
	sps map[uint]*hevcSPS
	pps map[uint]hevcPPSInfo
}

type hevcPPSInfo struct {
	sps   uint
	extra int
}

// hevcPicture は1つのアクセスユニットを読む。
func (s *Scanner) hevcPicture(units []nalu, size int) (Picture, bool) {
	st := &s.hevc
	picture := Picture{Structure: Frame, Size: size}
	picStruct, scanType := -1, -1
	var sps *hevcSPS
	found := false

	for _, unit := range units {
		kind := unit.kind(HEVC)
		switch {
		case kind == nalHEVCSPS:
			id, parsed := parseHEVCSPS(unit.rbspOf(HEVC))
			if parsed != nil {
				if st.sps == nil {
					st.sps = map[uint]*hevcSPS{}
				}
				st.sps[id] = parsed
			}
		case kind == nalHEVCPPS:
			b := &bits{buf: unit.rbspOf(HEVC)}
			pps := b.ue()
			info := hevcPPSInfo{sps: b.ue()}
			b.flag() // dependent_slice_segments_enabled_flag
			b.flag() // output_flag_present_flag
			info.extra = int(b.u(3))
			if st.pps == nil {
				st.pps = map[uint]hevcPPSInfo{}
			}
			st.pps[pps] = info
		case kind == nalHEVCPrefixSEI:
			if v, scan, ok := hevcPicStruct(unit.rbspOf(HEVC)); ok {
				picStruct, scanType = v, scan
			}
		case kind <= 31:
			if found {
				continue
			}
			b := &bits{buf: unit.rbspOf(HEVC)}
			if !b.flag() { // first_slice_segment_in_pic_flag
				continue
			}
			// IRAP は 16 から 23 まで。BLA と CRA を含むので、IDR だけを待つ実装より入口が広い。
			irap := kind >= 16 && kind <= 23
			if irap {
				b.flag() // no_output_of_prior_pics_flag
			}
			info, ok := st.pps[b.ue()]
			if !ok {
				continue
			}
			active := st.sps[info.sps]
			if active == nil {
				continue
			}
			sps = active
			for i := 0; i < info.extra; i++ {
				b.flag()
			}
			switch b.ue() { // slice_type
			case 0:
				picture.Coding = 'b'
			case 1:
				picture.Coding = 'p'
			default:
				picture.Coding = 'i'
			}
			picture.RAP = irap
			found = true
		}
	}
	if !found || sps == nil {
		return Picture{}, false
	}
	picture.Format = sps.format
	switch picStruct {
	case 1, 9, 11:
		picture.Structure = Top
	case 2, 10, 12:
		picture.Structure = Bottom
	}
	picture.TFF, picture.RFF = picStructDisplay(picStruct)
	switch {
	case scanType >= 0:
		// source_scan_type は 0 がインタレース、1 がプログレッシブ、2 が不明。
		if scanType == 1 {
			picture.Prog = 1
		}
	default:
		picture.Prog = sps.format.Progressive
	}
	return picture, true
}

func parseHEVCSPS(payload []byte) (uint, *hevcSPS) {
	var s hevcSPS
	b := &bits{buf: payload}
	b.u(4) // sps_video_parameter_set_id
	maxSubLayers := int(b.u(3))
	b.flag() // sps_temporal_id_nesting_flag
	progressive := parseProfileTierLevel(b, maxSubLayers)
	s.format.Progressive = progressive

	id := b.ue()
	chroma := int(b.ue())
	separate := false
	if chroma == 3 {
		separate = b.flag()
	}
	width := int(b.ue())
	height := int(b.ue())
	if b.flag() { // conformance_window_flag
		subWidth, subHeight := 1, 1
		if chroma == 1 || chroma == 2 {
			subWidth = 2
		}
		if chroma == 1 {
			subHeight = 2
		}
		if separate {
			subWidth, subHeight = 1, 1
		}
		left, right := int(b.ue()), int(b.ue())
		top, bottom := int(b.ue()), int(b.ue())
		width -= (left + right) * subWidth
		height -= (top + bottom) * subHeight
	}
	s.format.Width, s.format.Height = width, height
	s.format.Chroma = chroma
	s.format.Depth = int(b.ue()) + 8
	b.ue() // bit_depth_chroma_minus8
	pocBits := int(b.ue()) + 4
	first := maxSubLayers
	if b.flag() { // sps_sub_layer_ordering_info_present_flag
		first = 0
	}
	for i := first; i <= maxSubLayers; i++ {
		b.ue()
		b.ue()
		b.ue()
	}
	b.ue() // log2_min_luma_coding_block_size_minus3
	b.ue() // log2_diff_max_min_luma_coding_block_size
	b.ue() // log2_min_luma_transform_block_size_minus2
	b.ue() // log2_diff_max_min_luma_transform_block_size
	b.ue() // max_transform_hierarchy_depth_inter
	b.ue() // max_transform_hierarchy_depth_intra
	if b.flag() && b.flag() {
		parseHEVCScalingList(b)
	}
	b.flag()      // amp_enabled_flag
	b.flag()      // sample_adaptive_offset_enabled_flag
	if b.flag() { // pcm_enabled_flag
		b.u(4)
		b.u(4)
		b.ue()
		b.ue()
		b.flag()
	}
	sets := int(b.ue())
	deltas := make([]int, sets+1)
	for i := 0; i < sets && i < 65; i++ {
		parseShortTermRefPicSet(b, i, sets, deltas)
	}
	if b.flag() { // long_term_ref_pics_present_flag
		n := int(b.ue())
		for i := 0; i < n && i < 33; i++ {
			b.u(pocBits)
			b.flag()
		}
	}
	b.flag() // sps_temporal_mvp_enabled_flag
	b.flag() // strong_intra_smoothing_enabled_flag
	s.format.RateDen, s.format.AspectDen = 1, 1
	if b.flag() { // vui_parameters_present_flag
		parseHEVCVUI(b, &s)
	}
	return id, &s
}

// parseProfileTierLevel は general_progressive_source_flag だけを返す。
// 残りは VUI へ辿り着くために読み飛ばす必要があるので、値は使わなくても読む。
func parseProfileTierLevel(b *bits, maxSubLayers int) int {
	b.u(2) // general_profile_space
	b.u(1) // general_tier_flag
	b.u(5) // general_profile_idc
	b.u(32)
	progressive := int(b.u(1))
	b.u(1) // general_interlaced_source_flag
	b.u(1) // general_non_packed_constraint_flag
	b.u(1) // general_frame_only_constraint_flag
	b.u(43)
	b.u(1)
	b.u(8) // general_level_idc

	profilePresent := make([]bool, maxSubLayers)
	levelPresent := make([]bool, maxSubLayers)
	for i := 0; i < maxSubLayers; i++ {
		profilePresent[i] = b.flag()
		levelPresent[i] = b.flag()
	}
	if maxSubLayers > 0 {
		for i := maxSubLayers; i < 8; i++ {
			b.u(2)
		}
	}
	for i := 0; i < maxSubLayers; i++ {
		if profilePresent[i] {
			b.u(32)
			b.u(32)
			b.u(24)
		}
		if levelPresent[i] {
			b.u(8)
		}
	}
	return progressive
}

func parseHEVCScalingList(b *bits) {
	for sizeID := 0; sizeID < 4; sizeID++ {
		step := 1
		if sizeID == 3 {
			step = 3
		}
		for matrixID := 0; matrixID < 6; matrixID += step {
			if !b.flag() { // scaling_list_pred_mode_flag
				b.ue()
				continue
			}
			coefficients := 64
			if n := 1 << uint(4+(sizeID<<1)); n < 64 {
				coefficients = n
			}
			if sizeID > 1 {
				b.se()
			}
			for i := 0; i < coefficients; i++ {
				b.se()
			}
		}
	}
}

// parseShortTermRefPicSet はここでは何も要らないが、VUI がこの後ろに立つので読み飛ばすために辿る。
func parseShortTermRefPicSet(b *bits, idx, count int, deltas []int) {
	predict := false
	if idx != 0 {
		predict = b.flag()
	}
	if predict {
		ref := idx - 1
		if idx == count {
			ref = idx - 1 - int(b.ue())
		}
		b.flag() // delta_rps_sign
		b.ue()   // abs_delta_rps_minus1
		n := 0
		if ref >= 0 && ref < len(deltas) {
			n = deltas[ref]
		}
		used := 0
		for j := 0; j <= n; j++ {
			if b.flag() {
				used++
				continue
			}
			if b.flag() {
				used++
			}
		}
		deltas[idx] = used
		return
	}
	negative := int(b.ue())
	positive := int(b.ue())
	if negative > 64 {
		negative = 64
	}
	if positive > 64 {
		positive = 64
	}
	for i := 0; i < negative; i++ {
		b.ue()
		b.flag()
	}
	for i := 0; i < positive; i++ {
		b.ue()
		b.flag()
	}
	deltas[idx] = negative + positive
}

func parseHEVCVUI(b *bits, s *hevcSPS) {
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
	s.format.AspectNum, s.format.AspectDen = displayAspect(s.format.Width, s.format.Height, sarNum, sarDen)
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
	b.flag()      // neutral_chroma_indication_flag
	b.flag()      // field_seq_flag
	b.flag()      // frame_field_info_present_flag
	if b.flag() { // default_display_window_flag
		b.ue()
		b.ue()
		b.ue()
		b.ue()
	}
	if b.flag() { // vui_timing_info_present_flag
		units := int(b.u(32))
		scale := int(b.u(32))
		// H.264 と違い、HEVC の time_scale はそのまま框率の分子になる。
		s.format.RateNum, s.format.RateDen = ratio(scale, units)
	}
}

// hevcPicStruct は pic_struct と source_scan_type を返す。H.264 と違い、どちらも picture timing の先頭に立つ。
func hevcPicStruct(payload []byte) (int, int, bool) {
	value, scan, found := -1, -1, false
	forEachSEI(payload, func(kind int, body []byte) {
		if kind != 1 || found {
			return
		}
		b := &bits{buf: body}
		value, scan, found = int(b.u(4)), int(b.u(2)), true
	})
	return value, scan, found
}
