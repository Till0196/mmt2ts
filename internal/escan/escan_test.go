// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package escan

import "testing"

// startCode は開始符号と種別だけを置く。中身は呼ぶ側が足す。
func startCode(kind byte, body ...byte) []byte {
	return append([]byte{0x00, 0x00, 0x01, kind}, body...)
}

// mpeg2Payload は sequence header から始まり、フレームの I とボトムフィールドの P が続く並びを作る。
func mpeg2Payload() []byte {
	var b []byte
	// 1440x1080、aspect_ratio_information=3（16:9）、frame_rate_code=4（30000/1001）。
	b = append(b, startCode(0xb3, 0x5a, 0x04, 0x38, 0x34, 0x00, 0x00, 0x00, 0x00)...)
	// sequence extension。progressive_sequence=0、chroma_format=1。
	b = append(b, startCode(0xb5, 0x10, 0x02, 0x00, 0x01, 0x00, 0x00)...)
	b = append(b, startCode(0x00, 0x00, 0x08, 0x00, 0x00)...)             // picture_coding_type=1
	b = append(b, startCode(0xb5, 0x8f, 0xff, 0xf3, 0x80, 0x00, 0x00)...) // frame、top_field_first=1
	b = append(b, startCode(0x01, 0x11, 0x22, 0x33)...)                   // slice
	b = append(b, startCode(0x00, 0x00, 0x10, 0x00, 0x00)...)             // picture_coding_type=2
	b = append(b, startCode(0xb5, 0x8f, 0xff, 0xf2, 0x00, 0x00, 0x00)...) // bottom field
	b = append(b, startCode(0x01, 0x44, 0x55)...)                         // slice
	return b
}

func TestMPEG2(t *testing.T) {
	s := New(MPEG2)
	pictures := s.Push(mpeg2Payload())
	if len(pictures) != 2 {
		t.Fatalf("ピクチャの数が %d、期待は 2", len(pictures))
	}
	want := Format{Width: 1440, Height: 1080, Depth: 8, Chroma: 1,
		RateNum: 30000, RateDen: 1001, Progressive: 0, AspectNum: 16, AspectDen: 9}
	if pictures[0].Format != want {
		t.Errorf("format が %+v、期待は %+v", pictures[0].Format, want)
	}
	if pictures[0].Coding != 'i' || pictures[0].Structure != Frame || pictures[0].TFF != 1 {
		t.Errorf("1枚目が %+v", pictures[0])
	}
	if !pictures[0].RAP {
		t.Error("sequence header の付いた I なのでランダムアクセス点のはず")
	}
	if pictures[1].Coding != 'p' || pictures[1].Structure != Bottom || pictures[1].RAP {
		t.Errorf("2枚目が %+v", pictures[1])
	}
	if total := pictures[0].Size + pictures[1].Size; total != len(mpeg2Payload()) {
		t.Errorf("大きさの合計が %d、ペイロードは %d", total, len(mpeg2Payload()))
	}
}

// TestMPEG2WithoutSequenceHeader は、申告が読めないうちのピクチャを出さないことを確かめる。
// 途中から拾ったストリームの先頭がこれにあたる。
func TestMPEG2WithoutSequenceHeader(t *testing.T) {
	s := New(MPEG2)
	var b []byte
	b = append(b, startCode(0x00, 0x00, 0x08, 0x00, 0x00)...)
	b = append(b, startCode(0xb5, 0x8f, 0xff, 0xf3, 0x80, 0x00, 0x00)...)
	b = append(b, startCode(0x01, 0x11)...)
	if pictures := s.Push(b); len(pictures) != 0 {
		t.Fatalf("%d 枚出た。sequence header より前は出さない", len(pictures))
	}
}

// TestSplitAnnexB は、アクセスユニットの切れ目がピクチャの先頭スライスに付くことを確かめる。
// 2枚目以降のスライスやスライスの後ろに立つ SEI で切ると、1枚のピクチャを2つに数える。
func TestSplitAnnexB(t *testing.T) {
	firstSlice := []byte{0x01, 0x80} // first_mb_in_slice=0
	laterSlice := []byte{0x01, 0x40} // first_mb_in_slice=1
	var b []byte
	b = append(b, startCode(0x09, 0x10)...) // access unit delimiter
	b = append(b, startCode(0x67, 0x42)...) // sequence parameter set
	b = append(b, startCode(0x68, 0xce)...) // picture parameter set
	b = append(b, startCode(0x06, 0x01)...) // supplemental enhancement information
	b = append(b, startCode(firstSlice[0], firstSlice[1])...)
	b = append(b, startCode(laterSlice[0], laterSlice[1])...)
	b = append(b, startCode(0x09, 0x10)...)
	b = append(b, startCode(firstSlice[0], firstSlice[1])...)

	s := New(H264)
	_, bounds := s.splitAnnexB(b)
	if len(bounds) != 2 {
		t.Fatalf("アクセスユニットが %d 個、期待は 2", len(bounds))
	}
	if bounds[0] != 0 || bounds[1] != 6 {
		t.Errorf("切れ目が %v", bounds)
	}
}

func TestSplitAnnexBHEVC(t *testing.T) {
	var b []byte
	b = append(b, startCode(0x46, 0x01, 0x50)...) // access unit delimiter（型 35）
	b = append(b, startCode(0x02, 0x01, 0x80)...) // 先頭スライス
	b = append(b, startCode(0x02, 0x01, 0x40)...) // 続きのスライス
	b = append(b, startCode(0x46, 0x01, 0x50)...)
	b = append(b, startCode(0x02, 0x01, 0x80)...)

	s := New(HEVC)
	_, bounds := s.splitAnnexB(b)
	if len(bounds) != 2 {
		t.Fatalf("アクセスユニットが %d 個、期待は 2", len(bounds))
	}
}

func TestDisplayAspect(t *testing.T) {
	// 1440x1080 は標本が 4:3 なので、画面全体では 16:9 になる。
	if n, d := displayAspect(1440, 1080, 4, 3); n != 16 || d != 9 {
		t.Errorf("%d/%d、期待は 16/9", n, d)
	}
	if n, d := displayAspect(1920, 1080, 0, 0); n != 0 || d != 1 {
		t.Errorf("%d/%d、申告が無ければ 0/1", n, d)
	}
}

func TestPicStructDisplay(t *testing.T) {
	for _, c := range []struct {
		picStruct int
		tff, rff  int
	}{{-1, 0, 0}, {0, 0, 0}, {3, 1, 0}, {4, 0, 0}, {5, 1, 1}, {6, 0, 1}} {
		tff, rff := picStructDisplay(c.picStruct)
		if tff != c.tff || rff != c.rff {
			t.Errorf("pic_struct=%d で tff=%d rff=%d、期待は %d と %d", c.picStruct, tff, rff, c.tff, c.rff)
		}
	}
}
