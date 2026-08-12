// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package siconv

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/si"
)

type fixedTags map[uint16]byte

func (f fixedTags) TSTag(mmt uint16) (byte, bool) { t, ok := f[mmt]; return t, ok }

func newTestConverter(mode TextMode) *Converter {
	return NewConverter(NewText(mode), fixedTags{0x0000: 0x00, 0x0010: 0x10})
}

func mhDescriptor(tag uint16, body []byte) si.Descriptor {
	return si.Descriptor{Tag: tag, Data: body}
}

func shortEventBody(lang, name, text string) []byte {
	b := append([]byte(lang), byte(len(name)))
	b = append(b, name...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(text)))
	return append(b, text...)
}

func TestShortEventIsReencoded(t *testing.T) {
	c := newTestConverter(TextARIB)
	out, results := c.Loop([]si.Descriptor{
		mhDescriptor(si.TagMHShortEvent, shortEventBody("jpn", "日本", "解説")),
	}, InEvent)
	if len(results) != 1 || results[0].Status != StatusConverted {
		t.Fatalf("results = %+v", results)
	}
	if out[0] != mpegts.DescShortEvent {
		t.Fatalf("descriptor tag = %#02x", out[0])
	}
	if int(out[1]) != len(out)-2 {
		t.Fatalf("length %d does not match %d bytes", out[1], len(out)-2)
	}
	if bytes.Contains(out, []byte("日本")) {
		t.Fatal("UTF-8 leaked into an ARIB coded descriptor")
	}
}

func TestShortEventTruncationIsReported(t *testing.T) {
	c := newTestConverter(TextARIB)
	long := strings.Repeat("あ", 200)
	c.Loop([]si.Descriptor{
		mhDescriptor(si.TagMHShortEvent, shortEventBody("jpn", "番組", long)),
	}, InEvent)
	stats := c.Text.Stats()
	if stats.Truncated == 0 || stats.Dropped == 0 {
		t.Fatalf("truncation was not reported: %+v", stats)
	}
	if stats.Lossless() {
		t.Fatal("a truncated string was reported as lossless")
	}
}

func TestComponentDescriptorsUseConventionalTSValues(t *testing.T) {
	c := newTestConverter(TextARIB)
	video := []byte{0x63, 0x9e, 0x00, 0x00, 0x00}
	video = append(video, "jpn"...)
	audio := []byte{0xf3, 0x03, 0x00, 0x10, 0x0f, 0xff, 0x6e}
	audio = append(audio, "jpn"...)

	v, vr := c.Loop([]si.Descriptor{mhDescriptor(si.TagVideoComponent, video)}, InEvent)
	a, ar := c.Loop([]si.Descriptor{mhDescriptor(si.TagMHAudioComponent, audio)}, InEvent)
	if len(vr) != 1 || vr[0].Status != StatusConverted || len(ar) != 1 || ar[0].Status != StatusConverted {
		t.Fatalf("video results = %+v, audio results = %+v", vr, ar)
	}
	if v[2]&0x0f != 1 || v[3] != 0x93 {
		t.Fatalf("video descriptor = % x, want stream_content 1 component_type 93", v)
	}
	if a[2]&0x0f != 2 {
		t.Fatalf("audio descriptor = % x, want stream_content 2", a)
	}
}

func TestExtendedEventIsSplitAndRenumbered(t *testing.T) {
	c := newTestConverter(TextARIB)
	var items []byte
	for range 8 {
		desc := strings.Repeat("d", 40)
		item := strings.Repeat("i", 60)
		items = append(items, byte(len(desc)))
		items = append(items, desc...)
		items = binary.BigEndian.AppendUint16(items, uint16(len(item)))
		items = append(items, item...)
	}
	body := []byte{0x00}
	body = append(body, "jpn"...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(items)))
	body = append(body, items...)
	body = binary.BigEndian.AppendUint16(body, 0)

	out, results := c.Loop([]si.Descriptor{mhDescriptor(si.TagMHExtendedEvent, body)}, InEvent)
	if len(results) < 2 {
		t.Fatalf("one MH descriptor produced %d transport stream descriptors", len(results))
	}
	var number, last byte
	count := 0
	for p := 0; p < len(out); {
		if out[p] != mpegts.DescExtendedEvent {
			t.Fatalf("unexpected tag %#02x", out[p])
		}
		length := int(out[p+1])
		number, last = out[p+2]>>4, out[p+2]&0x0f
		if int(number) != count {
			t.Fatalf("descriptor %d is numbered %d", count, number)
		}
		if int(last) != len(results)-1 {
			t.Fatalf("last_descriptor_number = %d, want %d", last, len(results)-1)
		}
		count++
		p += 2 + length
	}
	if count != len(results) {
		t.Fatalf("walked %d descriptors, converter reported %d", count, len(results))
	}
}

func TestCopyControlIsNotRelaxed(t *testing.T) {
	c := newTestConverter(TextARIB)
	body := []byte{0x10, 0xff}
	comp := binary.BigEndian.AppendUint16(nil, 0x00ff)
	comp = append(comp, 0xc0, 0xff)
	body = append(body, byte(len(comp)))
	body = append(body, comp...)
	_, results := c.Loop([]si.Descriptor{mhDescriptor(si.TagContentCopyControl, body)}, InEvent)
	if len(results) != 1 || results[0].Status != StatusUnsupported {
		t.Fatalf("results = %+v", results)
	}
	if !strings.Contains(results[0].Reason, "00ff") {
		t.Fatalf("reason does not name the missing tag: %q", results[0].Reason)
	}
	if results[0].Raw == nil {
		t.Fatal("the input bytes of an unconverted descriptor were not kept")
	}
}

func TestUnknownDescriptorIsReportedNotDropped(t *testing.T) {
	c := newTestConverter(TextARIB)
	_, results := c.Loop([]si.Descriptor{mhDescriptor(0x8099, []byte{1, 2, 3})}, InEvent)
	if len(results) != 1 || results[0].Status != StatusUnsupported {
		t.Fatalf("results = %+v", results)
	}
	if got := c.Stats[TagKey{Tag: 0x8099}]; got == nil || got.Unsupported != 1 {
		t.Fatalf("stats = %+v", c.Stats)
	}
}

func TestScheduleTableIDsKeepTheirIdentity(t *testing.T) {
	for i := 0; i < 16; i++ {
		mmt := byte(si.TableIDMHEITScheduleFirst + i)
		got, ok := TSTableID(mmt)
		if !ok || got != byte(mpegts.TableIDEITScheduleFirst+i) {
			t.Fatalf("MMT %#02x mapped to %#02x", mmt, got)
		}
	}
}

func TestEITFullTSSectionRules(t *testing.T) {
	state := si.NewState()
	state.EIT[si.EITKey{TableID: si.TableIDMHEITPF, ServiceID: 1, Section: 0}] = &si.EIT{
		TableID: si.TableIDMHEITPF, ServiceID: 1, OriginalNetworkID: 4,
		Events: []si.Event{{EventID: 10, RunningStatus: 4}},
	}
	state.EIT[si.EITKey{TableID: si.TableIDMHEITScheduleFirst, ServiceID: 1, Section: 0}] = &si.EIT{
		TableID: si.TableIDMHEITScheduleFirst, ServiceID: 1, SectionNumber: 0, OriginalNetworkID: 4,
		Events: []si.Event{{EventID: 20, RunningStatus: 4}},
	}
	state.EIT[si.EITKey{TableID: si.TableIDMHEITScheduleFirst, ServiceID: 1, Section: 16}] = &si.EIT{
		TableID: si.TableIDMHEITScheduleFirst, ServiceID: 1, SectionNumber: 16, OriginalNetworkID: 4,
		Events: []si.Event{{EventID: 30, RunningStatus: 4}},
	}
	g := NewGenerator(newTestConverter(TextARIB), state)
	g.ServiceID, g.TSID = 1, 2
	tables := g.Build()
	var pf, schedule Table
	for _, table := range tables {
		switch table.Name {
		case "EIT p/f":
			pf = table
		case "EIT schedule":
			schedule = table
		}
	}
	if len(pf.Sections) != 2 || pf.Sections[0][6] != 0 || pf.Sections[1][6] != 1 {
		t.Fatalf("p/f sections = %d, headers % x", len(pf.Sections), pf.Sections)
	}
	if len(schedule.Sections) != 3 {
		t.Fatalf("schedule sections = %d, want segment 0, empty 1, segment 2", len(schedule.Sections))
	}
	if schedule.Sections[1][6] != 8 || len(schedule.Sections[1]) != 18 {
		t.Fatalf("empty segment section = % x", schedule.Sections[1])
	}
	if got := schedule.Sections[0][24] >> 5; got != 0 {
		t.Fatalf("schedule running_status = %d", got)
	}
}

func mhComponentGroupBody(groupType byte, hasBitRate bool, groups []struct {
	id      byte
	caUnits []struct {
		id   byte
		tags []uint16
	}
	bitRate byte
	text    string
}) []byte {
	flag := byte(0)
	if hasBitRate {
		flag = 0x10
	}
	b := []byte{groupType<<5 | flag | byte(len(groups))&0x0f}
	for _, g := range groups {
		b = append(b, g.id<<4|byte(len(g.caUnits))&0x0f)
		for _, u := range g.caUnits {
			b = append(b, u.id<<4|byte(len(u.tags))&0x0f)
			for _, tag := range u.tags {
				b = binary.BigEndian.AppendUint16(b, tag)
			}
		}
		if hasBitRate {
			b = append(b, g.bitRate)
		}
		b = append(b, byte(len(g.text)))
		b = append(b, g.text...)
	}
	return b
}

type testCAUnit = struct {
	id   byte
	tags []uint16
}

type testGroup = struct {
	id      byte
	caUnits []testCAUnit
	bitRate byte
	text    string
}

func TestComponentGroupConvertsAMultiViewService(t *testing.T) {
	c := newTestConverter(TextARIB)
	body := mhComponentGroupBody(0, false, []testGroup{
		{id: 0, caUnits: []testCAUnit{{id: 0, tags: []uint16{0x0000, 0x0010}}}},
	})
	_, results := c.Loop([]si.Descriptor{mhDescriptor(si.TagMHComponentGroup, body)}, InEvent)
	if len(results) != 1 || results[0].Status != StatusConverted {
		t.Fatalf("results = %+v", results)
	}
	got := results[0].Bytes
	if got[0] != mpegts.DescComponentGroup {
		t.Fatalf("descriptor tag = %#02x", got[0])
	}
	b := got[2:]
	if b[0]>>5 != 0 {
		t.Errorf("component_group_type = %d, want 0 (multi-view)", b[0]>>5)
	}
	if b[0]&0x10 != 0 {
		t.Error("total_bit_rate_flag was set when the input did not set it")
	}
	if n := b[0] & 0x0f; n != 1 {
		t.Fatalf("num_of_group = %d, want 1", n)
	}
	if b[1]>>4 != 0 {
		t.Errorf("component_group_id = %d, want the main group", b[1]>>4)
	}
	if units := b[1] & 0x0f; units != 1 {
		t.Fatalf("num_of_CA_unit = %d", units)
	}
	if n := b[2] & 0x0f; n != 2 {
		t.Fatalf("num_of_component = %d, want 2", n)
	}
	if b[3] != 0x00 || b[4] != 0x10 {
		t.Errorf("component tags = %#02x, %#02x, want 0x00, 0x10", b[3], b[4])
	}
	if b[5] != 0 {
		t.Errorf("text_length = %d, want 0", b[5])
	}
}

func TestComponentGroupKeepsTheTotalBitRateAndTextOfEachGroup(t *testing.T) {
	c := newTestConverter(TextARIB)
	body := mhComponentGroupBody(0, true, []testGroup{
		{id: 0, caUnits: []testCAUnit{{id: 1, tags: []uint16{0x0000}}}, bitRate: 42, text: "main"},
		{id: 1, caUnits: []testCAUnit{{id: 1, tags: []uint16{0x0010}}}, bitRate: 7, text: "sub"},
	})
	_, results := c.Loop([]si.Descriptor{mhDescriptor(si.TagMHComponentGroup, body)}, InEvent)
	if len(results) != 1 || results[0].Status != StatusConverted {
		t.Fatalf("results = %+v", results)
	}
	b := results[0].Bytes[2:]
	if b[0]&0x10 == 0 {
		t.Fatal("total_bit_rate_flag was not carried over")
	}
	if n := b[0] & 0x0f; n != 2 {
		t.Fatalf("num_of_group = %d, want 2", n)
	}

	p := 1
	for i, want := range []struct {
		id      byte
		unitID  byte
		tag     byte
		bitRate byte
	}{
		{0, 1, 0x00, 42},
		{1, 1, 0x10, 7},
	} {
		if p >= len(b) {
			t.Fatalf("group %d runs past the descriptor", i)
		}
		if got := b[p] >> 4; got != want.id {
			t.Errorf("group %d component_group_id = %d, want %d", i, got, want.id)
		}
		if units := b[p] & 0x0f; units != 1 {
			t.Fatalf("group %d num_of_CA_unit = %d", i, units)
		}
		p++
		if got := b[p] >> 4; got != want.unitID {
			t.Errorf("group %d CA_unit_id = %d, want %d", i, got, want.unitID)
		}
		if n := b[p] & 0x0f; n != 1 {
			t.Fatalf("group %d num_of_component = %d", i, n)
		}
		p++
		if b[p] != want.tag {
			t.Errorf("group %d component tag = %#02x, want %#02x", i, b[p], want.tag)
		}
		p++
		if b[p] != want.bitRate {
			t.Errorf("group %d total_bit_rate = %d, want %d", i, b[p], want.bitRate)
		}
		p++
		textLen := int(b[p])
		p++
		if textLen == 0 {
			t.Errorf("group %d lost its text", i)
		}
		p += textLen
	}
	if p != len(b) {
		t.Errorf("%d bytes left after the group loop", len(b)-p)
	}
}

func TestComponentGroupLeavesOutComponentsThatAreNotInTheOutput(t *testing.T) {
	c := newTestConverter(TextARIB)
	body := mhComponentGroupBody(0, false, []testGroup{
		{id: 0, caUnits: []testCAUnit{{id: 0, tags: []uint16{0x0000, 0x0999}}}},
	})
	_, results := c.Loop([]si.Descriptor{mhDescriptor(si.TagMHComponentGroup, body)}, InEvent)
	if len(results) != 1 || results[0].Status != StatusConverted {
		t.Fatalf("results = %+v", results)
	}
	if results[0].Reason == "" {
		t.Error("dropping a component was not reported")
	}
	b := results[0].Bytes[2:]
	if n := b[2] & 0x0f; n != 1 {
		t.Fatalf("num_of_component = %d, want only the component that is in the output", n)
	}
	if b[3] != 0x00 {
		t.Errorf("component tag = %#02x, want 0x00", b[3])
	}
}

func TestComponentGroupWithNoConvertibleComponentIsReportedUnsupported(t *testing.T) {
	c := newTestConverter(TextARIB)
	body := mhComponentGroupBody(0, false, []testGroup{
		{id: 0, caUnits: []testCAUnit{{id: 0, tags: []uint16{0x0999}}}},
	})
	_, results := c.Loop([]si.Descriptor{mhDescriptor(si.TagMHComponentGroup, body)}, InEvent)
	if len(results) != 1 || results[0].Status != StatusUnsupported {
		t.Fatalf("results = %+v", results)
	}
}

func TestComponentGroupRejectsATruncatedDescriptor(t *testing.T) {
	c := newTestConverter(TextARIB)
	body := mhComponentGroupBody(0, false, []testGroup{
		{id: 0, caUnits: []testCAUnit{{id: 0, tags: []uint16{0x0000}}}},
	})
	for n := range len(body) {
		_, results := c.Loop([]si.Descriptor{mhDescriptor(si.TagMHComponentGroup, body[:n])}, InEvent)
		if len(results) != 1 || results[0].Status == StatusConverted {
			t.Errorf("a %d-byte body converted: %+v", n, results)
		}
	}
}
