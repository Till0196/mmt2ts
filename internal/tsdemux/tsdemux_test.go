// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsdemux

import (
	"bytes"
	"encoding/binary"
	"testing"

	"mmt2ts/internal/mpegts"
)

func TestPATPMTAndDSMCCSection(t *testing.T) {
	var buf bytes.Buffer
	w := mpegts.NewWriter(&buf)
	if err := w.WriteSection(0x0000, mpegts.BuildPAT(1, 0, []mpegts.Program{{Number: 1, PID: 0x0100}}, 0)); err != nil {
		t.Fatal(err)
	}
	pmt := mpegts.BuildPMT(1, 0, 0x1011, nil, []mpegts.ElementaryStream{
		{StreamType: mpegts.StreamTypeHEVC, PID: 0x1011, Descriptors: mpegts.StreamIdentifierDescriptor(0x00)},
		{StreamType: mpegts.StreamTypeDSMCC, PID: 0x1d00, Descriptors: mpegts.StreamIdentifierDescriptor(0xe0)},
	})
	if err := w.WriteSection(0x0100, pmt); err != nil {
		t.Fatal(err)
	}
	dsmccSection := mpegts.LongSection(mpegts.TableIDDII, 0, 0, 0, 0, []byte("payload"))
	if err := w.WriteSection(0x1d00, dsmccSection); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	d := New()
	var gotPAT PAT
	var gotPMT PMT
	var gotSection Section
	d.Handlers.OnPAT = func(p PAT) { gotPAT = p }
	d.Handlers.OnPMT = func(p PMT) { gotPMT = p }
	d.Handlers.OnSection = func(s Section) { gotSection = s }

	b := buf.Bytes()
	for len(b) >= packetSize {
		d.Push(b[:packetSize])
		b = b[packetSize:]
	}
	d.Flush()

	if len(gotPAT.Programs) != 1 || gotPAT.Programs[0].PID != 0x0100 {
		t.Fatalf("PAT = %+v", gotPAT)
	}
	if gotPMT.PCRPID != 0x1011 || len(gotPMT.Streams) != 2 {
		t.Fatalf("PMT = %+v", gotPMT)
	}
	if gotPMT.Streams[1].StreamType != mpegts.StreamTypeDSMCC || !gotPMT.Streams[1].HasTag || gotPMT.Streams[1].ComponentTag != 0xe0 {
		t.Fatalf("DSM-CC stream entry = %+v", gotPMT.Streams[1])
	}
	if gotSection.PID != 0x1d00 || gotSection.TableID != mpegts.TableIDDII {
		t.Fatalf("Section = %+v", gotSection)
	}
}

func TestPESReassembly(t *testing.T) {
	var buf bytes.Buffer
	w := mpegts.NewWriter(&buf)
	au := bytes.Repeat([]byte{0xAB}, 1000)
	pes := buildPES(t, 0x000001e0, 90000, 0, au)
	if err := w.WriteUnit(0x0101, pes, mpegts.Adaptation{RandomAccess: true}); err != nil {
		t.Fatal(err)
	}
	au2 := []byte{0xCD, 0xEF}
	pes2 := buildPES(t, 0x000001e0, 180000, 0, au2)
	if err := w.WriteUnit(0x0101, pes2, mpegts.Adaptation{}); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	d := New()
	var got []PES
	d.Handlers.OnPES = func(p PES) { got = append(got, p) }
	b := buf.Bytes()
	for len(b) >= packetSize {
		d.Push(b[:packetSize])
		b = b[packetSize:]
	}
	d.Flush()

	if len(got) != 2 {
		t.Fatalf("got %d PES units, want 2", len(got))
	}
	if !got[0].HasPTS || got[0].PTS != 90000 || !bytes.Equal(got[0].Payload, au) {
		t.Fatalf("first PES = PTS %d hasPTS %v payload len %d, want PTS 90000 payload len %d",
			got[0].PTS, got[0].HasPTS, len(got[0].Payload), len(au))
	}
	if !got[0].RandomAccess {
		t.Error("first PES should carry random_access_indicator")
	}
	if !got[1].HasPTS || got[1].PTS != 180000 || !bytes.Equal(got[1].Payload, au2) {
		t.Fatalf("second PES = PTS %d payload %x", got[1].PTS, got[1].Payload)
	}
}

func buildPES(t *testing.T, startCodeAndStreamID uint32, pts int64, dts int64, payload []byte) []byte {
	t.Helper()
	out := []byte{
		byte(startCodeAndStreamID >> 24), byte(startCodeAndStreamID >> 16), byte(startCodeAndStreamID >> 8), byte(startCodeAndStreamID),
	}
	out = out[:3]
	out = append(out, byte(startCodeAndStreamID))
	out = append(out, 0, 0)
	out = append(out, 0x80, 0x80, 5)
	out = appendPTS(out, pts)
	return append(out, payload...)
}

func appendPTS(dst []byte, pts int64) []byte {
	b := make([]byte, 5)
	b[0] = 0x21 | byte(pts>>29)&0x0e
	b[1] = byte(pts >> 22)
	b[2] = byte(pts>>14)&0xfe | 0x01
	b[3] = byte(pts >> 7)
	b[4] = byte(pts<<1) | 0x01
	return append(dst, b...)
}

func TestSectionsPackedInOnePacket(t *testing.T) {
	section := func(tableID byte, id uint16, payload int) []byte {
		s := []byte{tableID, 0, 0}
		s = binary.BigEndian.AppendUint16(s, id)
		s = append(s, 0xc1, 0, 0)
		s = append(s, make([]byte, payload)...)
		binary.BigEndian.PutUint16(s[1:3], 0xf000|uint16(len(s)-3+4))
		return binary.BigEndian.AppendUint32(s, mpegts.CRC32(s))
	}
	first, second := section(0x4e, 0x0101, 8), section(0x4e, 0x0202, 8)
	long, third := section(0x4e, 0x0303, 200), section(0x4e, 0x0404, 8)

	split := 183
	payloads := [][]byte{
		append(append([]byte{0}, first...), second...),
		append([]byte{0}, long[:split]...),
		append(append([]byte{byte(len(long) - split)}, long[split:]...), third...),
	}

	d := New()
	var got []uint16
	d.Handlers.OnSection = func(s Section) {
		if s.PID == mpegts.PIDEIT {
			got = append(got, binary.BigEndian.Uint16(s.Data[3:5]))
		}
	}
	for i, p := range payloads {
		pkt := make([]byte, 188)
		pkt[0] = 0x47
		binary.BigEndian.PutUint16(pkt[1:3], mpegts.PIDEIT)
		pkt[1] |= 0x40
		pkt[3] = 0x10 | byte(i&0x0f)
		copy(pkt[4:], p)
		for j := 4 + len(p); j < len(pkt); j++ {
			pkt[j] = 0xff
		}
		d.Push(pkt)
	}
	want := []uint16{0x0101, 0x0202, 0x0303, 0x0404}
	if len(got) != len(want) {
		t.Fatalf("got %d sections %#04x, want %d %#04x", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("section %d id %#04x, want %#04x", i, got[i], want[i])
		}
	}
}

func TestContinuityCounterCountsLostPackets(t *testing.T) {
	packet := func(cc byte, discontinuity bool) []byte {
		p := make([]byte, 188)
		p[0] = 0x47
		binary.BigEndian.PutUint16(p[1:3], 0x0100)
		p[3] = 0x10 | cc&0x0f
		if discontinuity {
			p[3] = 0x30 | cc&0x0f
			p[4] = 1
			p[5] = 0x80
		}
		return p
	}
	for _, tc := range []struct {
		name string
		ccs  []byte
		disc int
		want uint64
	}{
		{"in order", []byte{0, 1, 2, 3}, -1, 0},
		{"three missing", []byte{0, 4}, -1, 3},
		{"duplicate", []byte{0, 0, 1}, -1, 0},
		{"wrap", []byte{14, 15, 0, 1}, -1, 0},
		{"announced discontinuity", []byte{0, 9}, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := New()
			for i, cc := range tc.ccs {
				d.Push(packet(cc, i == tc.disc))
			}
			if got := d.Lost[0x0100]; got != tc.want {
				t.Errorf("lost %d, want %d", got, tc.want)
			}
		})
	}
}
