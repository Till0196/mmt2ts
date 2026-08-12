// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package signaling

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func table(id, version byte, body []byte) []byte {
	out := []byte{id, version, 0, 0}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)))
	return append(out, body...)
}

func paMessage(tables ...[]byte) []byte {
	body := []byte{0}
	for _, t := range tables {
		body = append(body, t...)
	}
	msg := binary.BigEndian.AppendUint16(nil, MessageIDPA)
	msg = append(msg, 1)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(body)))
	return append(msg, body...)
}

func mptBody(assetDescriptors []byte) []byte {
	body := []byte{0x00, 2}
	body = binary.BigEndian.AppendUint16(body, 0x0066)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = append(body, 1)
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint32(body, 0)
	body = append(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0xf100)
	body = append(body, "hev1"...)
	body = append(body, 0x00, 2)
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint16(body, 0xf100)
	body = append(body, 0x05, 3, 'a', 'b', 'c')
	body = binary.BigEndian.AppendUint16(body, uint16(len(assetDescriptors)))
	return append(body, assetDescriptors...)
}

func TestReassembleFragmentedPAMessage(t *testing.T) {
	r := NewReassembler()
	message := paMessage(table(TableIDPLT, 2, pltBody()), table(TableIDMPTComplete, 3, mptBody(nil)))
	half := len(message) / 2
	if got := r.Push(0, append([]byte{0x40, 0x01}, message[:half]...)); got != nil {
		t.Fatalf("first fragment returned %v", got)
	}
	messages := r.Push(0, append([]byte{0xc0, 0x00}, message[half:]...))
	if len(messages) != 1 {
		t.Fatalf("messages = %d", len(messages))
	}
	tables := messages[0].Tables
	if len(tables) != 2 {
		t.Fatalf("tables = %d", len(tables))
	}
	if tables[0].PLT == nil || tables[0].Version != 2 {
		t.Fatalf("PLT = %+v", tables[0])
	}
	if tables[1].MPT == nil || tables[1].Version != 3 {
		t.Fatalf("MPT = %+v", tables[1])
	}
	if got := tables[0].PLT.Entries[0].Location.PacketID; got != 0xff01 {
		t.Fatalf("PLT location = %#04x", got)
	}
	mpt := tables[1].MPT
	if mpt.ServiceID() != 0x0066 || len(mpt.Assets) != 1 {
		t.Fatalf("MPT = %+v", mpt)
	}
	asset := mpt.Assets[0]
	if asset.Type != "hev1" || len(asset.Locations) != 2 {
		t.Fatalf("asset = %+v", asset)
	}
	if pid, ok := asset.LocalPacketID(); !ok || pid != 0xf100 {
		t.Fatalf("local packet id = %#04x, ok = %v", pid, ok)
	}
	if asset.Locations[1].Type != 0x05 || !bytes.Equal(asset.Locations[1].Raw, []byte{0x05, 3, 'a', 'b', 'c'}) {
		t.Fatalf("second location = %+v", asset.Locations[1])
	}
	if s := r.Stats(); s.Messages != 1 || s.Tables != 2 || s.MalformedTables != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestAggregatedSignalingWithBothLengthWidths(t *testing.T) {
	message := paMessage(table(TableIDPLT, 2, pltBody()))
	for _, width := range []int{2, 4} {
		t.Run(fmt.Sprintf("%d-bit", width*8), func(t *testing.T) {
			payload := []byte{0x01, 0}
			if width == 2 {
				payload = binary.BigEndian.AppendUint16(payload, uint16(len(message)))
			} else {
				payload[0] |= 0x02
				payload = binary.BigEndian.AppendUint32(payload, uint32(len(message)))
			}
			payload = append(payload, message...)
			got := NewReassembler().Push(1, payload)
			if len(got) != 1 || len(got[0].Tables) != 1 || got[0].Tables[0].PLT == nil {
				t.Fatalf("messages = %+v", got)
			}
		})
	}
}

func TestSignalingRejectsInvalidFragmentOrderAndAggregateFragment(t *testing.T) {
	r := NewReassembler()
	r.Push(1, []byte{0x80, 1, 1})
	r.Push(1, []byte{0xc0, 0, 1})
	r.Push(1, []byte{0x41, 0, 1})
	if got := r.Stats().DroppedFragments; got != 3 {
		t.Fatalf("DroppedFragments = %d, want 3", got)
	}
}

func pltBody() []byte {
	body := []byte{1, 2}
	body = binary.BigEndian.AppendUint16(body, 0x0066)
	body = append(body, 0x00)
	return binary.BigEndian.AppendUint16(body, 0xff01)
}

func TestAssetDescriptorsAreDecoded(t *testing.T) {
	var desc []byte
	desc = append(desc, 0x80, 0x11, 0x02, 0x00, 0x10)
	desc = append(desc, 0x80, 0x14, 0x0a, 0x02, 0x03, 0x00, 0x10, 0x11, 0xff, 0x5f, 'j', 'p', 'n')
	desc = append(desc, 0x80, 0x00, 0x02, 0x07, 0x01)
	desc = append(desc, 0x80, 0x37, 0x04, 0x21, 0x02, 0x81, 0x03)
	timestamps := []byte{0x00, 0x01, 12}
	timestamps = binary.BigEndian.AppendUint32(timestamps, 5)
	timestamps = binary.BigEndian.AppendUint64(timestamps, 0xe123456780000000)
	desc = append(desc, timestamps...)
	ext := []byte{0x80, 0x26, 0}
	extBody := []byte{0x03}
	extBody = binary.BigEndian.AppendUint32(extBody, 180000)
	extBody = binary.BigEndian.AppendUint16(extBody, 3003)
	extBody = binary.BigEndian.AppendUint32(extBody, 5)
	extBody = append(extBody, 0x00)
	extBody = binary.BigEndian.AppendUint16(extBody, 30030)
	extBody = append(extBody, 2)
	extBody = binary.BigEndian.AppendUint16(extBody, 0)
	extBody = binary.BigEndian.AppendUint16(extBody, 15015)
	ext[2] = byte(len(extBody))
	desc = append(desc, append(ext, extBody...)...)

	mpt, err := ParseMPT(TableIDMPTComplete, 1, mptBody(desc))
	if err != nil {
		t.Fatal(err)
	}
	a := mpt.Assets[0]
	if a.ComponentTag == nil || *a.ComponentTag != 0x0010 {
		t.Fatalf("component tag = %v", a.ComponentTag)
	}
	if a.Audio == nil || a.Audio.ComponentType != 3 || a.Audio.StreamType != 0x11 ||
		a.Audio.SimulcastGroupTag != 0xff || a.Audio.Language != "jpn" || a.Audio.MultiLingual() {
		t.Fatalf("audio component = %+v", a.Audio)
	}
	if a.Group == nil || a.Group.Identification != 7 || a.Group.SelectionLevel != 1 {
		t.Fatalf("asset group = %+v", a.Group)
	}
	if a.Hierarchy == nil || a.Hierarchy.LayerIndex != 2 || a.Hierarchy.EmbeddedLayerIndex != 1 ||
		a.Hierarchy.Channel != 3 || !a.Hierarchy.TREFPresent {
		t.Fatalf("hierarchy = %+v", a.Hierarchy)
	}
	if len(a.MPUTimestamps) != 1 || a.MPUTimestamps[0].Sequence != 5 || a.MPUTimestamps[0].NTP != 0xe123456780000000 {
		t.Fatalf("timestamps = %+v", a.MPUTimestamps)
	}
	e := a.Extended
	if e == nil || e.Invalid || e.Timescale != 180000 || e.PTSOffsetType != 1 || e.DefaultPTSOffset != 3003 {
		t.Fatalf("extended timestamp = %+v", e)
	}
	if len(e.Entries) != 1 || e.Entries[0].DecodingTimeOffset != 30030 || len(e.Entries[0].AUs) != 2 {
		t.Fatalf("extended entries = %+v", e.Entries)
	}
	if e.Entries[0].AUs[1].DTSPTSOffset != 15015 || e.Entries[0].AUs[1].PTSOffset != 3003 {
		t.Fatalf("per-AU timing = %+v", e.Entries[0].AUs)
	}
	if a.Key() != "0/00000000/f100" {
		t.Fatalf("asset key = %q", a.Key())
	}
}

func TestTruncatedTablesAreRejected(t *testing.T) {
	body := mptBody(nil)
	for cut := 1; cut < len(body); cut++ {
		if _, err := ParseMPT(TableIDMPTComplete, 1, body[:cut]); err == nil {
			t.Fatalf("truncating to %d bytes parsed successfully", cut)
		}
	}
	r := NewReassembler()
	if got := r.Push(0, []byte{0x00, 0x00, 0x00}); got != nil {
		t.Fatalf("short message returned %v", got)
	}
}

func TestExtendedTimestampRejectsZeroTimescale(t *testing.T) {
	got := ParseExtendedTimestamp([]byte{0x01, 0, 0, 0, 0})
	if !got.Invalid || got.HasTimescale {
		t.Fatalf("zero timescale = %+v", got)
	}
}

func TestUnknownTableIsCountedAndKeptRaw(t *testing.T) {
	r := NewReassembler()
	raw := table(0x81, 4, []byte{1, 2, 3})
	messages := r.Push(0, append([]byte{0x00, 0x00}, paMessage(raw)...))
	if len(messages) != 1 {
		t.Fatalf("messages = %d", len(messages))
	}
	tables := messages[0].Tables
	if len(tables) != 1 || tables[0].MPT != nil || tables[0].PLT != nil {
		t.Fatalf("tables = %+v", tables)
	}
	if !bytes.Equal(tables[0].Raw, []byte{1, 2, 3}) {
		t.Fatalf("raw bytes = % x", tables[0].Raw)
	}
	if r.Stats().UnknownTables[0x81] != 1 {
		t.Fatalf("unknown tables = %v", r.Stats().UnknownTables)
	}
}
