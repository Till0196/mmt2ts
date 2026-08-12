// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package codecrev

import (
	"bytes"
	"encoding/binary"
	"testing"

	"mmt2ts/internal/codec"
)

func sampleFromNALs(nals ...[]byte) []byte {
	var out []byte
	for _, n := range nals {
		out = binary.BigEndian.AppendUint32(out, uint32(len(n)))
		out = append(out, n...)
	}
	return out
}

func TestAnnexBRoundTrip(t *testing.T) {
	vps := []byte{0x40, 0x01, 0xaa, 0xbb}
	sps := []byte{0x42, 0x01, 0xcc}
	slice := []byte{0x26, 0x01, 0x00, 0x00, 0x11, 0x22}
	sample := sampleFromNALs(vps, sps, slice)

	annexB, info, err := codec.HEVCAnnexB(nil, sample)
	if err != nil {
		t.Fatalf("HEVCAnnexB: %v", err)
	}
	if info.NALCount != 3 {
		t.Fatalf("NALCount = %d, want 3", info.NALCount)
	}

	got, err := AnnexBToSample(annexB)
	if err != nil {
		t.Fatalf("AnnexBToSample: %v", err)
	}
	if !bytes.Equal(got, sample) {
		t.Fatalf("round trip = %x, want %x", got, sample)
	}
}

func TestAnnexBMixedStartCodes(t *testing.T) {
	annexB := []byte{
		0, 0, 0, 1, 0x46, 0x01, 0xaa,
		0, 0, 1, 0x02, 0x01, 0xbb, 0xcc,
		0, 0, 0, 1, 0x28, 0x01, 0xdd,
	}
	want := sampleFromNALs(
		[]byte{0x46, 0x01, 0xaa},
		[]byte{0x02, 0x01, 0xbb, 0xcc},
		[]byte{0x28, 0x01, 0xdd},
	)
	got, err := AnnexBToSample(annexB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("mixed-prefix sample = %x, want %x", got, want)
	}
}

func TestAudioMuxElementRoundTrip(t *testing.T) {
	cfg := ADTSInfo{ObjectType: 2, SampleRateIndex: 3, ChannelConfig: 2}
	rawAAC := bytes.Repeat([]byte{0x12, 0x34, 0x56, 0x78}, 40)

	ame, err := BuildAudioMuxElement(cfg, rawAAC)
	if err != nil {
		t.Fatalf("BuildAudioMuxElement: %v", err)
	}
	if len(ame) < 7 || ame[5]&0x08 == 0 {
		t.Fatalf("ARIB LATM crcCheckPresent is not set: %x", ame)
	}

	var conv codec.ADTSConverter
	adts, err := conv.Convert(nil, ame)
	if err != nil {
		t.Fatalf("ADTSConverter.Convert: %v", err)
	}

	infos, raws, err := SplitADTS(adts)
	if err != nil {
		t.Fatalf("SplitADTS: %v", err)
	}
	if len(infos) != 1 || infos[0] != cfg {
		t.Fatalf("ADTS config = %+v, want %+v", infos, cfg)
	}
	if !bytes.Equal(raws[0], rawAAC) {
		t.Fatalf("raw AAC = %x, want %x", raws[0], rawAAC)
	}
}

func TestAudioMuxElementRoundTripLongFrame(t *testing.T) {
	cfg := ADTSInfo{ObjectType: 2, SampleRateIndex: 3, ChannelConfig: 2}
	rawAAC := bytes.Repeat([]byte{0xAB}, 600)

	ame, err := BuildAudioMuxElement(cfg, rawAAC)
	if err != nil {
		t.Fatalf("BuildAudioMuxElement: %v", err)
	}
	var conv codec.ADTSConverter
	adts, err := conv.Convert(nil, ame)
	if err != nil {
		t.Fatalf("ADTSConverter.Convert: %v", err)
	}
	_, raws, err := SplitADTS(adts)
	if err != nil {
		t.Fatalf("SplitADTS: %v", err)
	}
	if !bytes.Equal(raws[0], rawAAC) {
		t.Fatalf("raw AAC length %d, want %d", len(raws[0]), len(rawAAC))
	}
}

func TestSplitADTSWithCRC(t *testing.T) {
	raw := []byte{0x21, 0x1a, 0x94, 0xa5}
	frameLength := 9 + len(raw)
	frame := []byte{0xff, 0xf8, 0x4c, byte(frameLength >> 11), byte(frameLength >> 3), byte(frameLength<<5) | 0x1f, 0xfc, 0xb2, 0xe4}
	frame = append(frame, raw...)
	_, got, err := SplitADTS(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], raw) {
		t.Fatalf("raw AAC = %x, want %x", got, raw)
	}
}

func TestStripLOASRoundTrip(t *testing.T) {
	ame := []byte{0x00, 0x11, 0x22, 0x33, 0x44}
	loas, err := codec.LOASFrame(nil, ame)
	if err != nil {
		t.Fatalf("LOASFrame: %v", err)
	}
	got, err := StripLOAS(loas)
	if err != nil {
		t.Fatalf("StripLOAS: %v", err)
	}
	if !bytes.Equal(got, ame) {
		t.Fatalf("StripLOAS = %x, want %x", got, ame)
	}
}

func TestCompleteADTSPrefix(t *testing.T) {
	frame := func(n int) []byte {
		b := make([]byte, n)
		b[0], b[1], b[2] = 0xff, 0xf1, 0x4c
		b[3] = byte(0x80 | n>>11&0x03)
		b[4] = byte(n >> 3)
		b[5] = byte(n<<5) | 0x1f
		b[6] = 0xfc
		return b
	}
	whole := append(frame(64), frame(48)...)
	if got := CompleteADTSPrefix(whole); got != len(whole) {
		t.Errorf("intact stream: prefix %d, want %d", got, len(whole))
	}
	cut := whole[:len(whole)-10]
	if got := CompleteADTSPrefix(cut); got != 64 {
		t.Errorf("truncated last frame: prefix %d, want 64", got)
	}
	if got := CompleteADTSPrefix(frame(64)[:20]); got != 0 {
		t.Errorf("only a partial frame: prefix %d, want 0", got)
	}
}

func TestADTSFramesSplitsAPackedPES(t *testing.T) {
	frame := func(n int, rateIndex byte) []byte {
		b := make([]byte, n)
		b[0], b[1] = 0xff, 0xf1
		b[2] = 0x40 | rateIndex<<2
		b[3] = byte(0x80 | n>>11&0x03)
		b[4] = byte(n >> 3)
		b[5] = byte(n<<5) | 0x1f
		b[6] = 0xfc
		return b
	}
	packed := append(frame(64, 3), frame(48, 3)...)
	packed = append(packed, frame(70, 3)...)

	frames, rateIndex := ADTSFrames(packed)
	if len(frames) != 3 {
		t.Fatalf("got %d frames, want 3", len(frames))
	}
	for i, want := range []int{64, 48, 70} {
		if len(frames[i]) != want {
			t.Errorf("frame %d is %d bytes, want %d", i, len(frames[i]), want)
		}
	}
	if got := ADTSSampleRate(rateIndex); got != 48000 {
		t.Errorf("sample rate = %d, want 48000", got)
	}
	if got := ADTSSampleRate(0x0f); got != 0 {
		t.Errorf("reserved index gave %d, want 0", got)
	}
	if frames, _ := ADTSFrames(packed[:len(packed)-10]); len(frames) != 2 {
		t.Errorf("truncated packet gave %d frames, want 2", len(frames))
	}
}
