// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package si

import (
	"encoding/binary"
	"errors"
	"testing"

	"mmt2ts/internal/mpegts"
)

func longSection(tableID byte, ext uint16, version, number, last byte, body []byte) []byte {
	s := []byte{tableID, 0, 0}
	s = binary.BigEndian.AppendUint16(s, ext)
	s = append(s, 0xc1|version<<1&0x3e, number, last)
	s = append(s, body...)
	length := len(s) - 3 + 4
	binary.BigEndian.PutUint16(s[1:3], 0xb000|uint16(length))
	return binary.BigEndian.AppendUint32(s, mpegts.CRC32(s))
}

func shortSection(tableID byte, body []byte, crc bool) []byte {
	s := []byte{tableID, 0, 0}
	s = append(s, body...)
	length := len(s) - 3
	if crc {
		length += 4
	}
	binary.BigEndian.PutUint16(s[1:3], 0x7000|uint16(length))
	if crc {
		return binary.BigEndian.AppendUint32(s, mpegts.CRC32(s))
	}
	return s
}

func TestParseSectionChecksCRC(t *testing.T) {
	raw := longSection(TableIDMHSDTActual, 0x1234, 5, 0, 0, []byte{0, 1, 0xff})
	s, n, err := ParseSection(raw)
	if err != nil || n != len(raw) {
		t.Fatalf("parse: %v, n = %d", err, n)
	}
	if s.Extension != 0x1234 || s.Version != 5 || !s.Current || !s.CRCChecked {
		t.Fatalf("section = %+v", s)
	}
	raw[7] ^= 0x01
	if _, _, err := ParseSection(raw); !errors.Is(err, ErrCRC) {
		t.Fatalf("corrupted section returned %v", err)
	}
}

func TestCollectorWaitsForEverySection(t *testing.T) {
	c := NewCollector()
	body := func(id uint16) []byte {
		b := []byte{0x00, 0x01, 0xff}
		b = binary.BigEndian.AppendUint16(b, id)
		return append(b, 0x00, 0x00, 0x00)
	}
	first, _, _ := ParseSection(longSection(TableIDMHSDTActual, 0x10, 1, 0, 1, body(0x0060)))
	if _, ok := c.Push(first); ok {
		t.Fatal("published an incomplete set")
	}
	second, _, _ := ParseSection(longSection(TableIDMHSDTActual, 0x10, 1, 1, 1, body(0x0061)))
	set, ok := c.Push(second)
	if !ok || len(set.Sections) != 2 {
		t.Fatalf("set = %+v, ok = %v", set, ok)
	}
	if _, ok := c.Push(second); ok {
		t.Fatal("republished an unchanged set")
	}
}

func TestCollectorIgnoresNextVersion(t *testing.T) {
	c := NewCollector()
	raw := longSection(TableIDMHSDTActual, 0x10, 2, 0, 0, []byte{0, 1, 0xff})
	raw[5] &^= 0x01
	binary.BigEndian.PutUint32(raw[len(raw)-4:], mpegts.CRC32(raw[:len(raw)-4]))
	s, _, err := ParseSection(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Push(s); ok {
		t.Fatal("a next-version table was published as current")
	}
	if c.Stats().NotCurrent != 1 {
		t.Fatalf("stats = %+v", c.Stats())
	}
}

func TestCollectorUsesSegmentBoundsForSchedule(t *testing.T) {
	c := NewCollector()
	body := []byte{0x00, 0x01, 0x00, 0x02, 0x00, TableIDMHEITScheduleFirst}
	s, _, err := ParseSection(longSection(TableIDMHEITScheduleFirst, 0x0060, 1, 0, 0, body))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Push(s); !ok {
		t.Fatal("segment-bounded schedule never completed")
	}
}

func TestParseEITKeepsUndefinedTimes(t *testing.T) {
	event := []byte{0x12, 0x34}
	event = append(event, 0xff, 0xff, 0xff, 0xff, 0xff)
	event = append(event, 0x00, 0x30, 0x00)
	event = append(event, 0x80, 0x00)
	body := append([]byte{0x00, 0x01, 0x00, 0x02, 0x00, TableIDMHEITPF}, event...)
	s, _, err := ParseSection(longSection(TableIDMHEITPF, 0x0060, 1, 0, 1, body))
	if err != nil {
		t.Fatal(err)
	}
	eit, ok := ParseEIT(s)
	if !ok || len(eit.Events) != 1 {
		t.Fatalf("eit = %+v, ok = %v", eit, ok)
	}
	e := eit.Events[0]
	if e.EventID != 0x1234 || e.StartDefined() || !e.DurationDefined() {
		t.Fatalf("event = %+v", e)
	}
	if e.RunningStatus != 4 || eit.TLVStreamID != 1 || eit.OriginalNetworkID != 2 {
		t.Fatalf("event = %+v, eit = %+v", e, eit)
	}
}

func TestParseNITStreamLoop(t *testing.T) {
	name := []byte{TagTLVNetworkName, 0x02, 'B', 'S'}
	body := binary.BigEndian.AppendUint16(nil, 0xf000|uint16(len(name)))
	body = append(body, name...)
	stream := binary.BigEndian.AppendUint16(nil, 0x0004)
	stream = binary.BigEndian.AppendUint16(stream, 0x0007)
	stream = binary.BigEndian.AppendUint16(stream, 0xf000)
	body = binary.BigEndian.AppendUint16(body, 0xf000|uint16(len(stream)))
	body = append(body, stream...)

	s, _, err := ParseSection(longSection(TableIDTLVNITActual, 0x000a, 3, 0, 0, body))
	if err != nil {
		t.Fatal(err)
	}
	nit, ok := ParseNIT(s)
	if !ok || !nit.Actual() || nit.NetworkID != 0x000a {
		t.Fatalf("nit = %+v, ok = %v", nit, ok)
	}
	if len(nit.Streams) != 1 || nit.Streams[0].TLVStreamID != 4 || nit.Streams[0].OriginalNetworkID != 7 {
		t.Fatalf("streams = %+v", nit.Streams)
	}
	if len(nit.Descriptors) != 1 || nit.Descriptors[0].Tag != TagTLVNetworkName {
		t.Fatalf("descriptors = %+v", nit.Descriptors)
	}
}

func TestStateTracksShortTables(t *testing.T) {
	s := NewState()
	s.PushTLVSection(shortSection(TableIDMHDIT, []byte{0x80}, false))
	if s.LastDIT == nil || !s.LastDIT.Transition || s.DITs != 1 {
		t.Fatalf("DIT = %+v, count = %d", s.LastDIT, s.DITs)
	}
	tot := append([]byte{0xe1, 0x23, 0x45, 0x67, 0x89}, 0xf0, 0x00)
	s.PushTLVSection(shortSection(TableIDMHTOT, tot, true))
	if s.TOT == nil || s.TOT.JSTTime[0] != 0xe1 {
		t.Fatalf("TOT = %+v", s.TOT)
	}
}

func TestActualSDTPrefersANamedStream(t *testing.T) {
	// A self-stream MH-SDT that leaves tlv_stream_id at zero would otherwise
	// pin the identity to the placeholder stream and make every later,
	// properly named table look like a conflict.
	body := func(service uint16) []byte {
		b := binary.BigEndian.AppendUint16(nil, 0x0007)
		b = append(b, 0xff)
		b = binary.BigEndian.AppendUint16(b, service)
		return append(b, 0xfd, 0x80, 0x00)
	}
	s := NewState()
	s.PushTLVSection(longSection(TableIDMHSDTActual, 0x0000, 1, 0, 0, body(0x0060)))
	s.PushTLVSection(longSection(TableIDMHSDTActual, 0xb112, 1, 0, 0, body(0x0060)))
	sdt, ok := s.ActualSDT()
	if !ok || sdt.TLVStreamID != 0xb112 {
		t.Fatalf("ActualSDT = %+v, %v", sdt, ok)
	}
	if id := s.Identity(0x0060); id.TLVStreamID != 0xb112 || len(id.Conflicts) != 0 {
		t.Fatalf("identity = %+v", id)
	}
}

func TestIdentityReportsConflicts(t *testing.T) {
	s := NewState()
	nitBody := binary.BigEndian.AppendUint16(nil, 0xf000)
	stream := binary.BigEndian.AppendUint16(nil, 0x0004)
	stream = binary.BigEndian.AppendUint16(stream, 0x0007)
	stream = binary.BigEndian.AppendUint16(stream, 0xf000)
	nitBody = binary.BigEndian.AppendUint16(nitBody, 0xf000|uint16(len(stream)))
	nitBody = append(nitBody, stream...)
	s.PushTLVSection(longSection(TableIDTLVNITActual, 0x000a, 1, 0, 0, nitBody))

	id := s.Identity(0x0060)
	if !id.HaveNetworkID || id.NetworkID != 0x000a || id.TLVStreamID != 4 || len(id.Conflicts) != 0 {
		t.Fatalf("identity = %+v", id)
	}

	body := []byte{0x00, 0x09, 0x00, 0x07, 0x00, TableIDMHEITPF}
	msg := longSection(TableIDMHEITPF, 0x0060, 1, 0, 0, body)
	if err := s.PushMessage(MessageIDM2Section, 0, msg); err != nil {
		t.Fatal(err)
	}
	if id := s.Identity(0x0060); len(id.Conflicts) == 0 {
		t.Fatalf("conflicting tlv_stream_id not reported: %+v", id)
	}
}
