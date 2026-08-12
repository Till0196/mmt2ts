// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"bytes"
	"encoding/binary"
	"testing"

	"mmt2ts/internal/codec"
	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/tlv"
	"mmt2ts/internal/tsdemux"
	"mmt2ts/internal/tsremux/mmtwrite"
)

func sampleFromNALs(nals ...[]byte) []byte {
	var out []byte
	for _, n := range nals {
		out = binary.BigEndian.AppendUint32(out, uint32(len(n)))
		out = append(out, n...)
	}
	return out
}

func readMPUSamples(t *testing.T, buf []byte) [][]byte {
	t.Helper()
	r := tlv.NewReader(bytes.NewReader(buf))
	var out [][]byte
	for {
		pkt, err := r.Next()
		if err != nil {
			break
		}
		d, ok := r.Datagram(pkt)
		if !ok {
			continue
		}
		m, err := mmtp.Parse(d.Payload)
		if err != nil {
			t.Fatalf("mmtp.Parse: %v", err)
		}
		if m.PayloadType != mmtp.PayloadTypeMPU {
			continue
		}
		mpu, err := mmtp.ParseMPU(m.Payload, nil)
		if err != nil {
			t.Fatalf("mmtp.ParseMPU: %v", err)
		}
		if len(mpu.Units) != 1 {
			t.Fatalf("MPU has %d units, want 1", len(mpu.Units))
		}
		out = append(out, append([]byte(nil), mpu.Units[0].Data...))
	}
	return out
}

func TestReplayAVHEVC(t *testing.T) {
	sample1 := sampleFromNALs([]byte{0x26, 0x01, 0xaa}, []byte{0x02, 0x03})
	sample2 := sampleFromNALs([]byte{0x26, 0x01, 0xbb})
	annexB1, _, err := codec.HEVCAnnexB(nil, sample1)
	if err != nil {
		t.Fatal(err)
	}
	annexB2, _, err := codec.HEVCAnnexB(nil, sample2)
	if err != nil {
		t.Fatal(err)
	}

	entry := preservation.AVMapEntry{PacketID: 0x10, OutputPID: 0x1011, MPUSequence: 5}
	var buf bytes.Buffer
	if err := ReplayAV(&buf, entry, mpegts.StreamTypeHEVC, [][]byte{annexB1, annexB2}, mmtwrite.NewSequencer(),
		[]byte{192, 0, 2, 1}, []byte{224, 0, 0, 1}, 1000, 2000); err != nil {
		t.Fatal(err)
	}

	got := readMPUSamples(t, buf.Bytes())
	if len(got) != 3 {
		t.Fatalf("got %d NAL MFUs, want 3", len(got))
	}
	want := [][]byte{
		sampleFromNALs([]byte{0x26, 0x01, 0xaa}),
		sampleFromNALs([]byte{0x02, 0x03}),
		sampleFromNALs([]byte{0x26, 0x01, 0xbb}),
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("NAL MFU %d = %x, want %x", i, got[i], want[i])
		}
	}
}

func TestGeneralHEVCAdmissionNALIsType1AndFitsCompletePacket(t *testing.T) {
	large := append([]byte{0, 0, 0, 1, 0x02, 0x01}, make([]byte, 60000)...)
	small := []byte{0, 0, 1, 0x02, 0x01, 0xaa, 0xbb}
	pes := []tsdemux.PES{{Payload: append(large, small...)}}
	got := generalHEVCAdmissionNAL(pes)
	if len(got) == 0 || len(got) > 60000 {
		t.Fatalf("admission NAL length = %d", len(got))
	}
	if !bytes.Equal(got[:4], []byte{0, 0, 0, 1}) || (got[4]>>1)&0x3f != 1 {
		t.Fatalf("admission NAL = %x", got)
	}
}

func TestReplayAVADTS(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	ame := buildAME(t, 2, 3, 2, raw)
	var conv codec.ADTSConverter
	adts, err := conv.Convert(nil, ame)
	if err != nil {
		t.Fatal(err)
	}

	entry := preservation.AVMapEntry{PacketID: 0x20, OutputPID: 0x1100, MPUSequence: 9}
	var buf bytes.Buffer
	if err := ReplayAV(&buf, entry, mpegts.StreamTypeADTSAAC, [][]byte{adts}, mmtwrite.NewSequencer(),
		nil, nil, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := readMPUSamples(t, buf.Bytes())
	if len(got) != 1 {
		t.Fatalf("got %d samples, want 1", len(got))
	}
	var conv2 codec.ADTSConverter
	adts2, err := conv2.Convert(nil, got[0])
	if err != nil {
		t.Fatalf("regenerated AudioMuxElement did not convert: %v", err)
	}
	if !bytes.Equal(adts2, adts) {
		t.Fatalf("re-converted ADTS = %x, want %x", adts2, adts)
	}
}

func TestReplayAVLATM(t *testing.T) {
	ame := []byte{0xaa, 0xbb, 0xcc}
	loas, err := codec.LOASFrame(nil, ame)
	if err != nil {
		t.Fatal(err)
	}
	entry := preservation.AVMapEntry{PacketID: 0x30, OutputPID: 0x1101, MPUSequence: 1}
	var buf bytes.Buffer
	if err := ReplayAV(&buf, entry, mpegts.StreamTypeLATMAAC, [][]byte{loas}, mmtwrite.NewSequencer(), nil, nil, 0, 0); err != nil {
		t.Fatal(err)
	}
	got := readMPUSamples(t, buf.Bytes())
	if len(got) != 1 || !bytes.Equal(got[0], ame) {
		t.Fatalf("samples = %x, want [%x]", got, ame)
	}
}

func buildAME(t *testing.T, objectType, sampleRateIndex, channelConfig byte, raw []byte) []byte {
	t.Helper()
	var bits []byte
	push := func(v uint32, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, byte(v>>uint(i))&1)
		}
	}
	push(0, 1)
	push(0, 1)
	push(1, 1)
	push(0, 6)
	push(0, 4)
	push(0, 3)
	push(uint32(objectType), 5)
	push(uint32(sampleRateIndex), 4)
	push(uint32(channelConfig), 4)
	push(0, 1)
	push(0, 1)
	push(0, 1)
	push(0, 3)
	push(0, 8)
	push(0, 1)
	push(0, 1)
	n := len(raw)
	for n >= 255 {
		push(255, 8)
		n -= 255
	}
	push(uint32(n), 8)
	for _, b := range raw {
		push(uint32(b), 8)
	}
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b != 0 {
			out[i/8] |= 1 << uint(7-i%8)
		}
	}
	return out
}
