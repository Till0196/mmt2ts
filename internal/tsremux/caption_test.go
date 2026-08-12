// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"bytes"
	"testing"

	"mmt2ts/internal/caption"
	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/tlv"
	"mmt2ts/internal/tsremux/mmtwrite"
)

func readMPUUnits(t *testing.T, buf []byte) []mmtp.DataUnit {
	t.Helper()
	r := tlv.NewReader(bytes.NewReader(buf))
	var out []mmtp.DataUnit
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
		u := mpu.Units[0]
		u.Data = append([]byte(nil), u.Data...)
		out = append(out, u)
	}
	return out
}

func TestBuildCaptionMFURoundTrip(t *testing.T) {
	data := []byte("<tt>hello</tt>")
	b := BuildCaptionMFU(0x01, 0x02, 0, 1, caption.DataTypeTTML, data)
	m, err := caption.ParseMFU(b)
	if err != nil {
		t.Fatalf("ParseMFU: %v", err)
	}
	if m.SubtitleTag != 1 || m.SequenceNumber != 2 || m.Number != 0 || m.LastNumber != 1 || m.DataType != caption.DataTypeTTML {
		t.Fatalf("parsed MFU = %+v", m)
	}
	if !bytes.Equal(m.Data, data) {
		t.Fatalf("data = %q, want %q", m.Data, data)
	}
}

func TestReplayCaptionResources(t *testing.T) {
	resources := []CaptionResource{
		{ComponentTag: 0x30, MPUSequence: 9, Tag: 1, SequenceNumber: 5, Number: 0, DataType: caption.DataTypeTTML, Data: []byte("<tt>doc</tt>")},
		{ComponentTag: 0x30, MPUSequence: 9, Tag: 1, SequenceNumber: 5, Number: 1, DataType: caption.DataTypePNG, Data: []byte{0x89, 'P', 'N', 'G'}},
	}
	packetIDFor := func(tag uint16) (uint16, bool) {
		if tag == 0x30 {
			return 0x40, true
		}
		return 0, false
	}
	var buf bytes.Buffer
	if err := ReplayCaptionResources(&buf, resources, packetIDFor, mmtwrite.NewSequencer(), nil, nil, 0, 0); err != nil {
		t.Fatal(err)
	}
	units := readMPUUnits(t, buf.Bytes())
	if len(units) != 2 {
		t.Fatalf("got %d units, want 2", len(units))
	}
	for i, u := range units {
		m, err := caption.ParseMFU(u.Data)
		if err != nil {
			t.Fatalf("unit %d: ParseMFU: %v", i, err)
		}
		if m.SubtitleTag != 1 || m.SequenceNumber != 5 || m.LastNumber != 1 {
			t.Fatalf("unit %d MFU = %+v", i, m)
		}
		if int(m.Number) != i {
			t.Fatalf("unit %d Number = %d, want %d", i, m.Number, i)
		}
		if !bytes.Equal(m.Data, resources[i].Data) {
			t.Fatalf("unit %d data = %x, want %x", i, m.Data, resources[i].Data)
		}
	}
}

func TestReplayApplicationItems(t *testing.T) {
	items := []ApplicationItem{
		{ID: 1, Data: []byte("index.html contents")},
		{ID: 2, Data: []byte("style.css contents")},
	}
	var buf bytes.Buffer
	if err := ReplayApplicationItems(&buf, items, 0x0050, mmtwrite.NewSequencer(), nil, nil, 0, 0); err != nil {
		t.Fatal(err)
	}
	units := readMPUUnits(t, buf.Bytes())
	if len(units) != 2 {
		t.Fatalf("got %d units, want 2", len(units))
	}
	for i, u := range units {
		if u.Sample != items[i].ID {
			t.Fatalf("unit %d item id = %d, want %d", i, u.Sample, items[i].ID)
		}
		if !bytes.Equal(u.Data, items[i].Data) {
			t.Fatalf("unit %d data = %q, want %q", i, u.Data, items[i].Data)
		}
	}
}
