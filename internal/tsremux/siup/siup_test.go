// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package siup

import (
	"encoding/binary"
	"testing"

	"mmt2ts/internal/arib"
	"mmt2ts/internal/logocarousel"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/si"
)

func aribASCII(s string) []byte {
	out := []byte{0x1b, 0x28, 0x4a}
	return append(out, s...)
}

func tsDescriptorBytes(tag byte, body []byte) []byte {
	return append([]byte{tag, byte(len(body))}, body...)
}

func TestDescriptorsRoundTripThroughMHParsers(t *testing.T) {
	name, text := aribASCII("TITLE"), aribASCII("SUMMARY")

	shortEvent := append([]byte("jpn"), byte(len(name)))
	shortEvent = append(shortEvent, name...)
	shortEvent = append(shortEvent, byte(len(text)))
	shortEvent = append(shortEvent, text...)

	provider, service := aribASCII("PROVIDER"), aribASCII("SERVICE")
	serviceBody := []byte{0xa5, byte(len(provider))}
	serviceBody = append(serviceBody, provider...)
	serviceBody = append(serviceBody, byte(len(service)))
	serviceBody = append(serviceBody, service...)

	audio := append([]byte{0x02, 0x03, 0x10, 0x11, 0xff, 0x5f}, "jpn"...)
	audio = append(audio, aribASCII("AUDIO")...)

	loop := tsDescriptorBytes(mpegts.DescShortEvent, shortEvent)
	loop = append(loop, tsDescriptorBytes(mpegts.DescService, serviceBody)...)
	loop = append(loop, tsDescriptorBytes(mpegts.DescAudioComponent, audio)...)
	loop = append(loop, tsDescriptorBytes(mpegts.DescContent, []byte{0x71, 0x00})...)

	c := New()
	out := si.ParseDescriptors(c.Descriptors(loop))
	if len(out) != 4 {
		t.Fatalf("got %d MH descriptors, want 4", len(out))
	}

	d, ok := si.Find(out, si.TagMHShortEvent)
	if !ok {
		t.Fatal("no MH-short event descriptor")
	}
	se, ok := si.ParseShortEvent(d.Data)
	if !ok {
		t.Fatal("MH-short event does not parse")
	}
	if se.Language != "jpn" || se.Name != "TITLE" || se.Text != "SUMMARY" {
		t.Errorf("short event = %q/%q/%q", se.Language, se.Name, se.Text)
	}

	d, _ = si.Find(out, si.TagMHService)
	sv, ok := si.ParseService(d.Data)
	if !ok {
		t.Fatal("MH-service does not parse")
	}
	if sv.Type != 0xa5 || sv.Provider != "PROVIDER" || sv.Name != "SERVICE" {
		t.Errorf("service = %#02x/%q/%q", sv.Type, sv.Provider, sv.Name)
	}

	d, _ = si.Find(out, si.TagMHAudioComponent)
	ac, ok := si.ParseAudioComponent(d.Data)
	if !ok {
		t.Fatal("MH-audio component does not parse")
	}
	if ac.ComponentTag != 0x10 || ac.Language != "jpn" || ac.StreamType != 0x11 {
		t.Errorf("audio component tag %#04x lang %q stream type %#02x", ac.ComponentTag, ac.Language, ac.StreamType)
	}
	if ac.StreamContent != mhAudioStreamContent {
		t.Errorf("audio stream_content %#02x, want the MMT value %#02x", ac.StreamContent, mhAudioStreamContent)
	}

	d, _ = si.Find(out, si.TagMHContent)
	if n := si.ParseContent(d.Data); len(n) != 1 || n[0].Level1 != 7 || n[0].Level2 != 1 {
		t.Errorf("content nibbles = %+v", n)
	}
}

func TestExtendedEventWidensItsLengths(t *testing.T) {
	desc, item := aribASCII("CAST"), aribASCII("SOMEONE")
	items := append([]byte{byte(len(desc))}, desc...)
	items = append(items, byte(len(item)))
	items = append(items, item...)

	tail := aribASCII("MORE")
	body := append([]byte{0x01}, "jpn"...)
	body = append(body, byte(len(items)))
	body = append(body, items...)
	body = append(body, byte(len(tail)))
	body = append(body, tail...)

	c := New()
	out := si.ParseDescriptors(c.Descriptors(tsDescriptorBytes(mpegts.DescExtendedEvent, body)))
	if len(out) != 1 {
		t.Fatalf("got %d descriptors, want 1", len(out))
	}
	ee, ok := si.ParseExtendedEvent(out[0].Data)
	if !ok {
		t.Fatal("MH-extended event does not parse")
	}
	if ee.Number != 0 || ee.LastNumber != 1 || ee.Language != "jpn" || ee.Partial {
		t.Errorf("header = %d/%d/%q partial=%v", ee.Number, ee.LastNumber, ee.Language, ee.Partial)
	}
	if len(ee.Items) != 1 || ee.Items[0].Description != "CAST" || ee.Items[0].Item != "SOMEONE" {
		t.Errorf("items = %+v", ee.Items)
	}
	if ee.Text != "MORE" {
		t.Errorf("text = %q", ee.Text)
	}
}

func TestUnknownTagsAreDroppedNotCopied(t *testing.T) {
	c := New()
	out := c.Descriptors(tsDescriptorBytes(mpegts.DescHierarchicalTx, []byte{0xfe, 0xe1, 0x00}))
	if len(out) != 0 {
		t.Errorf("emitted %d bytes for a tag with no MH form", len(out))
	}
	stats := c.Stats()
	if len(stats) != 1 || stats[0].TSTag != mpegts.DescHierarchicalTx || stats[0].Dropped != 1 {
		t.Errorf("stats = %+v", stats)
	}
}

func TestMHSDTKeepsServiceLoop(t *testing.T) {
	name := aribASCII("CHANNEL")
	body := []byte{0xa5, 0}
	body = append(body, byte(len(name)))
	body = append(body, name...)
	desc := tsDescriptorBytes(mpegts.DescService, body)

	svc := binary.BigEndian.AppendUint16(nil, 0x0191)
	svc = append(svc, 0xfb)
	svc = binary.BigEndian.AppendUint16(svc, 0x8000|uint16(len(desc)))
	svc = append(svc, desc...)

	section := []byte{mpegts.TableIDSDTActual, 0, 0}
	section = binary.BigEndian.AppendUint16(section, 0x0210)
	section = append(section, 0xc1, 0, 0)
	section = binary.BigEndian.AppendUint16(section, 0x0004)
	section = append(section, 0xff)
	section = append(section, svc...)
	binary.BigEndian.PutUint16(section[1:3], 0xf000|uint16(len(section)-3+4))
	section = binary.BigEndian.AppendUint32(section, mpegts.CRC32(section))

	out, ok := New().MHSDT(section, nil)
	if !ok {
		t.Fatal("MHSDT refused the section")
	}
	parsed, _, err := si.ParseSection(out)
	if err != nil {
		t.Fatalf("generated MH-SDT does not parse: %v", err)
	}
	sdt, ok := si.ParseSDT(parsed)
	if !ok {
		t.Fatal("MH-SDT body does not parse")
	}
	if !sdt.Actual() || sdt.TLVStreamID != 0x0210 || sdt.OriginalNetworkID != 0x0004 {
		t.Errorf("sdt = %+v", sdt)
	}
	if len(sdt.Services) != 1 || sdt.Services[0].ServiceID != 0x0191 || !sdt.Services[0].ScheduleFlag {
		t.Fatalf("services = %+v", sdt.Services)
	}
	d, ok := si.Find(sdt.Services[0].Descriptors, si.TagMHService)
	if !ok {
		t.Fatal("service has no MH-service descriptor")
	}
	if sv, ok := si.ParseService(d.Data); !ok || sv.Name != "CHANNEL" {
		t.Errorf("service descriptor = %+v ok=%v", sv, ok)
	}
}

func TestVideoComponentSplitsTheComponentTypeNibbles(t *testing.T) {
	for _, tc := range []struct {
		name          string
		streamContent byte
		componentType byte
		resolution    byte
		aspect        byte
		progressive   bool
	}{
		{"MPEG-2 1080i 16:9 without pan", 0x01, 0xb3, 5, 3, false},
		{"MPEG-2 480i 4:3", 0x01, 0x01, 3, 1, false},
		{"H.264 720p >16:9", 0x05, 0xc4, 4, 4, true},
		{"HEVC 2160p 16:9 without pan", 0x09, 0x93, 6, 3, true},
		{"HEVC 4320p 16:9 without pan", 0x09, 0x83, 7, 3, true},
		{"1080p 16:9 with pan", 0x01, 0xe2, 5, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := append([]byte{tc.streamContent, tc.componentType, 0x21}, "jpn"...)
			body = append(body, aribASCII("VIDEO")...)
			out := si.ParseDescriptors(New().Descriptors(tsDescriptorBytes(mpegts.DescComponent, body)))
			if len(out) != 1 {
				t.Fatalf("got %d descriptors, want 1", len(out))
			}
			v, ok := si.ParseVideoComponent(out[0].Data)
			if !ok {
				t.Fatal("MH-video component does not parse")
			}
			if v.Resolution != tc.resolution || v.AspectRatio != tc.aspect || v.ScanFlag != tc.progressive {
				t.Errorf("resolution=%d aspect=%d progressive=%v, want %d/%d/%v",
					v.Resolution, v.AspectRatio, v.ScanFlag, tc.resolution, tc.aspect, tc.progressive)
			}
			if v.ComponentTag != 0x21 || v.Language != "jpn" || v.Text != "VIDEO" {
				t.Errorf("tag=%#04x lang=%q text=%q", v.ComponentTag, v.Language, v.Text)
			}
			if v.FrameRate != 0 || v.Transfer != 0 {
				t.Errorf("frame rate=%d transfer=%d, want both unspecified", v.FrameRate, v.Transfer)
			}
		})
	}
}

func TestVideoComponentRefusesAudioStreamContent(t *testing.T) {
	body := append([]byte{0x02, 0x03, 0x10}, "jpn"...)
	c := New()
	if out := c.Descriptors(tsDescriptorBytes(mpegts.DescComponent, body)); len(out) != 0 {
		t.Errorf("converted a component descriptor naming audio: % x", out)
	}
}

func TestCopyControlKeepsEveryRestriction(t *testing.T) {
	loop := []byte{
		0x10, 0xdf,
		0x21, 0xbf, 0x40,
	}
	body := []byte{0xbf, 0x20}
	body = append(body, byte(len(loop)))
	body = append(body, loop...)

	out := si.ParseDescriptors(New().Descriptors(tsDescriptorBytes(mpegts.DescDigitalCopyControl, body)))
	if len(out) != 1 || out[0].Tag != si.TagContentCopyControl {
		t.Fatalf("got %d descriptors %+v", len(out), out)
	}
	cc, ok := si.ParseCopyControl(out[0].Data)
	if !ok {
		t.Fatal("content copy control does not parse")
	}
	if cc.RecordingControl != 0x02 || !cc.HasBitrate || cc.MaximumBitrate != 0x20 {
		t.Errorf("service level = control %d bitrate %#02x present %v",
			cc.RecordingControl, cc.MaximumBitrate, cc.HasBitrate)
	}
	if len(cc.Components) != 2 {
		t.Fatalf("components = %+v", cc.Components)
	}
	if c := cc.Components[0]; c.ComponentTag != 0x10 || c.RecordingControl != 0x03 || c.HasBitrate {
		t.Errorf("component 0 = %+v", c)
	}
	if c := cc.Components[1]; c.ComponentTag != 0x21 || c.RecordingControl != 0x02 || !c.HasBitrate || c.MaximumBitrate != 0x40 {
		t.Errorf("component 1 = %+v", c)
	}
}

func TestTLVNITCarriesTheDeliverySystem(t *testing.T) {
	cable := []byte{0x01, 0x59, 0x00, 0x00, 0xff, 0x12, 0x05, 0x00, 0x52, 0x74, 0x0f}
	satellite := []byte{0x01, 0x27, 0x33, 0x00, 0x11, 0x00, 0xff, 0x02, 0x83, 0x65, 0x93}
	networkName := aribASCII("NETWORK")

	network := tsDescriptorBytes(si.TagTLVNetworkName, networkName)
	stream := tsDescriptorBytes(si.TagTLVServiceList, []byte{0x01, 0x91, 0x01})
	stream = append(stream, tsDescriptorBytes(si.TagTLVCableSystem, cable)...)
	stream = append(stream, tsDescriptorBytes(si.TagTLVSatelliteSystem, satellite)...)

	section := []byte{mpegts.TableIDNITActual, 0, 0}
	section = binary.BigEndian.AppendUint16(section, 0xfff7)
	section = append(section, 0xc1, 0, 0)
	section = binary.BigEndian.AppendUint16(section, 0xf000|uint16(len(network)))
	section = append(section, network...)
	entry := binary.BigEndian.AppendUint16(nil, 0x0210)
	entry = binary.BigEndian.AppendUint16(entry, 0xfff7)
	entry = binary.BigEndian.AppendUint16(entry, 0xf000|uint16(len(stream)))
	entry = append(entry, stream...)
	section = binary.BigEndian.AppendUint16(section, 0xf000|uint16(len(entry)))
	section = append(section, entry...)
	binary.BigEndian.PutUint16(section[1:3], 0xf000|uint16(len(section)-3+4))
	section = binary.BigEndian.AppendUint32(section, mpegts.CRC32(section))

	out, ok := New().TLVNIT(section)
	if !ok {
		t.Fatal("TLVNIT refused the section")
	}
	if out[0] != si.TableIDTLVNITActual || binary.BigEndian.Uint16(out[3:5]) != 0xfff7 {
		t.Fatalf("table_id %#02x network_id %#04x", out[0], binary.BigEndian.Uint16(out[3:5]))
	}
	networkLen := int(binary.BigEndian.Uint16(out[8:10]) & 0x0fff)
	nd := si.ParseTLVDescriptors(out[10 : 10+networkLen])
	if len(nd) != 1 || nd[0].Tag != si.TagTLVNetworkName {
		t.Fatalf("network descriptors = %+v", nd)
	}
	if got, want := string(nd[0].Data), string(New().text(networkName)); got != want {
		t.Errorf("network name = %q, want %q", got, want)
	}

	p := 10 + networkLen
	loopLen := int(binary.BigEndian.Uint16(out[p:p+2]) & 0x0fff)
	loop := out[p+2 : p+2+loopLen]
	if binary.BigEndian.Uint16(loop[0:2]) != 0x0210 || binary.BigEndian.Uint16(loop[2:4]) != 0xfff7 {
		t.Fatalf("TLV stream loop head = % x", loop[:4])
	}
	descLen := int(binary.BigEndian.Uint16(loop[4:6]) & 0x0fff)
	sd := si.ParseTLVDescriptors(loop[6 : 6+descLen])
	if len(sd) != 3 {
		t.Fatalf("stream descriptors = %+v", sd)
	}
	for i, want := range []struct {
		tag  uint16
		body []byte
	}{
		{si.TagTLVServiceList, []byte{0x01, 0x91, 0x01}},
		{si.TagTLVCableSystem, cable},
		{si.TagTLVSatelliteSystem, satellite},
	} {
		if sd[i].Tag != want.tag || string(sd[i].Data) != string(want.body) {
			t.Errorf("descriptor %d = %#02x % x, want %#02x % x", i, sd[i].Tag, sd[i].Data, want.tag, want.body)
		}
	}
}

func TestRemoteControlKeyMovesFromTSInfoToNetworkLoop(t *testing.T) {
	name := aribASCII("TS")
	tsInfo := []byte{0x04, byte(len(name))<<2 | 0x02}
	tsInfo = append(tsInfo, name...)
	for range 2 {
		tsInfo = append(tsInfo, 0x0f, 0x02)
		tsInfo = binary.BigEndian.AppendUint16(tsInfo, 0x0400)
		tsInfo = binary.BigEndian.AppendUint16(tsInfo, 0x0401)
	}

	stream := tsDescriptorBytes(si.TagTLVServiceList, []byte{0x04, 0x00, 0x01})
	stream = append(stream, tsDescriptorBytes(mpegts.DescTSInformation, tsInfo)...)

	section := []byte{mpegts.TableIDNITActual, 0, 0}
	section = binary.BigEndian.AppendUint16(section, 0x0007)
	section = append(section, 0xc1, 0, 0, 0xf0, 0x00)
	entry := binary.BigEndian.AppendUint16(nil, 0x0400)
	entry = binary.BigEndian.AppendUint16(entry, 0x0007)
	entry = binary.BigEndian.AppendUint16(entry, 0xf000|uint16(len(stream)))
	entry = append(entry, stream...)
	section = binary.BigEndian.AppendUint16(section, 0xf000|uint16(len(entry)))
	section = append(section, entry...)
	binary.BigEndian.PutUint16(section[1:3], 0xf000|uint16(len(section)-3+4))
	section = binary.BigEndian.AppendUint32(section, mpegts.CRC32(section))

	out, ok := New().TLVNIT(section)
	if !ok {
		t.Fatal("TLVNIT refused the section")
	}
	networkLen := int(binary.BigEndian.Uint16(out[8:10]) & 0x0fff)
	nd := si.ParseTLVDescriptors(out[10 : 10+networkLen])
	if len(nd) != 1 || nd[0].Tag != si.TagTLVRemoteControlKey {
		t.Fatalf("network descriptors = %+v, want a remote control key descriptor", nd)
	}
	keys, ok := si.ParseRemoteControlKey(nd[0].Data)
	if !ok {
		t.Fatal("remote control key descriptor does not parse")
	}
	want := []si.RemoteControlKeyEntry{{KeyID: 4, ServiceID: 0x0400}, {KeyID: 4, ServiceID: 0x0401}}
	if len(keys.Entries) != len(want) {
		t.Fatalf("entries = %+v, want %+v", keys.Entries, want)
	}
	for i := range want {
		if keys.Entries[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, keys.Entries[i], want[i])
		}
	}
	p := 10 + networkLen
	loopLen := int(binary.BigEndian.Uint16(out[p:p+2]) & 0x0fff)
	loop := out[p+2 : p+2+loopLen]
	descLen := int(binary.BigEndian.Uint16(loop[4:6]) & 0x0fff)
	for _, d := range si.ParseTLVDescriptors(loop[6 : 6+descLen]) {
		if d.Tag == uint16(mpegts.DescTSInformation) {
			t.Errorf("TS information descriptor was copied through: % x", d.Data)
		}
	}
}

func TestMHCDTKeepsTheLogoModule(t *testing.T) {
	module := make([]byte, 512)
	for i := range module {
		module[i] = byte(i * 7)
	}
	body := binary.BigEndian.AppendUint16(nil, 0x000b)
	body = append(body, 0x01)
	body = binary.BigEndian.AppendUint16(body, 0xf000)
	body = append(body, module...)

	section := []byte{mpegts.TableIDCDT, 0, 0}
	section = binary.BigEndian.AppendUint16(section, 0x0002)
	section = append(section, 0xc1, 1, 1)
	section = append(section, body...)
	binary.BigEndian.PutUint16(section[1:3], 0xf000|uint16(len(section)-3+4))
	section = binary.BigEndian.AppendUint32(section, mpegts.CRC32(section))

	out, ok := New().MHCDT(section)
	if !ok {
		t.Fatal("MHCDT refused the section")
	}
	parsed, _, err := si.ParseSection(out)
	if err != nil {
		t.Fatalf("generated MH-CDT does not parse: %v", err)
	}
	if parsed.TableID != si.TableIDMHCDT {
		t.Errorf("table_id %#02x, want %#02x", parsed.TableID, si.TableIDMHCDT)
	}
	if parsed.Number != 1 || parsed.LastNumber != 1 {
		t.Errorf("section %d/%d, want 1/1", parsed.Number, parsed.LastNumber)
	}
	cdt, ok := si.ParseCDT(parsed)
	if !ok {
		t.Fatal("MH-CDT body does not parse")
	}
	if cdt.DownloadDataID != 0x0002 || cdt.OriginalNetworkID != 0x000b || cdt.DataType != 0x01 {
		t.Errorf("cdt = %+v", cdt)
	}
	if string(cdt.Module) != string(module) {
		t.Errorf("module is %d bytes, want the %d it was given", len(cdt.Module), len(module))
	}
}

func TestMHBITCarriesTheSIParameterPeriods(t *testing.T) {
	siParam := []byte{0x00, 0xe5, 0x48}
	for _, e := range []struct {
		table byte
		desc  []byte
	}{
		{mpegts.TableIDEITPFActual, []byte{0x03}},
		{0x60, []byte{0x4f, 0x08}},
		{mpegts.TableIDEITScheduleFirst, []byte{0x4f, 0x08, 0x10}},
		{mpegts.TableIDBIT, []byte{0x10}},
		{mpegts.TableIDSDTActual, []byte{0x03}},
	} {
		siParam = append(siParam, e.table, byte(len(e.desc)))
		siParam = append(siParam, e.desc...)
	}
	first := tsDescriptorBytes(mpegts.DescSIParameter, siParam)
	name := aribASCII("BROADCASTER")
	bcast := []byte{0x07}
	bcastDesc := tsDescriptorBytes(mpegts.DescBroadcasterName, name)
	bcast = binary.BigEndian.AppendUint16(bcast, 0xf000|uint16(len(bcastDesc)))
	bcast = append(bcast, bcastDesc...)

	section := []byte{mpegts.TableIDBIT, 0, 0}
	section = binary.BigEndian.AppendUint16(section, 0xfff7)
	section = append(section, 0xc1, 0, 0)
	section = binary.BigEndian.AppendUint16(section, 0xf000|0x1000|uint16(len(first)))
	section = append(section, first...)
	section = append(section, bcast...)
	binary.BigEndian.PutUint16(section[1:3], 0xf000|uint16(len(section)-3+4))
	section = binary.BigEndian.AppendUint32(section, mpegts.CRC32(section))

	out, ok := New().MHBIT(section)
	if !ok {
		t.Fatal("MHBIT refused the section")
	}
	parsed, _, err := si.ParseSection(out)
	if err != nil {
		t.Fatalf("generated MH-BIT does not parse: %v", err)
	}
	bit, ok := si.ParseBIT(parsed)
	if !ok {
		t.Fatal("MH-BIT body does not parse")
	}
	if parsed.TableID != si.TableIDMHBIT || bit.OriginalNetworkID != 0xfff7 || !bit.ViewPropriety {
		t.Errorf("bit = table %#02x onid %#04x propriety %v", parsed.TableID, bit.OriginalNetworkID, bit.ViewPropriety)
	}
	if len(bit.Broadcasters) != 1 || bit.Broadcasters[0].BroadcasterID != 0x07 {
		t.Fatalf("broadcasters = %+v", bit.Broadcasters)
	}
	if d, ok := si.Find(bit.Broadcasters[0].Descriptors, si.TagMHBroadcasterName); !ok {
		t.Error("the broadcaster kept no name")
	} else if got, want := string(d.Data), arib.DecodeString(name).Text; got != want {
		t.Errorf("broadcaster name = %q, want %q", got, want)
	}

	d, ok := si.Find(bit.Descriptors, si.TagMHSIParameter)
	if !ok {
		t.Fatal("no MH-SI parameter descriptor")
	}
	sp, ok := si.ParseSIParameter(d.Data)
	if !ok {
		t.Fatal("MH-SI parameter does not parse")
	}
	if sp.Version != 0x00 || sp.UpdateTime != 0xe548 {
		t.Errorf("si parameter head = %#02x/%#04x", sp.Version, sp.UpdateTime)
	}
	want := []byte{si.TableIDMHEITPF, si.TableIDMHEITScheduleFirst, si.TableIDMHBIT, si.TableIDMHSDTActual}
	if len(sp.Tables) != len(want) {
		t.Fatalf("tables = %+v, want the %d that have an MH counterpart", sp.Tables, len(want))
	}
	for i, id := range want {
		if sp.Tables[i].TableID != id {
			t.Errorf("table %d = %#02x, want %#02x", i, sp.Tables[i].TableID, id)
		}
	}
}

func TestLinkageKeepsItsBodyInMHSILoops(t *testing.T) {
	body := []byte{0x7f, 0xff, 0x7f, 0xff, 0x7f, 0xff, 0x81, 0x01, 0x01, 0x02}
	loop := tsDescriptorBytes(mpegts.DescLinkage, body)

	c := New()
	out := si.ParseDescriptors(c.Descriptors(loop))
	if len(out) != 1 || out[0].Tag != si.TagMHLink {
		t.Fatalf("got %+v, want one MH-linkage descriptor", out)
	}
	if string(out[0].Data) != string(body) {
		t.Errorf("body % x, want % x", out[0].Data, body)
	}

	tlv := New()
	if got := tlv.TLVDescriptors(loop); len(got) != 0 {
		t.Errorf("TLV-NIT emitted % x for a linkage descriptor", got)
	}
	stats := tlv.Stats()
	if len(stats) != 1 || stats[0].TSTag != mpegts.DescLinkage || stats[0].Dropped != 1 {
		t.Errorf("stats = %+v", stats)
	}
}

func TestLogosBecomeMHCDTAndAPointer(t *testing.T) {
	services := []logocarousel.Service{{NetworkID: 0xfff7, TransportStreamID: 0x0210, ServiceID: 0x0191}}
	logos := []logocarousel.Logo{
		{Type: 0, ID: 0x0e3, Services: services, Data: []byte{1, 2, 3}},
		{Type: 3, ID: 0x0e3, Services: services, Data: []byte{4, 5}},
		{Type: 5, ID: 0x0e3, Services: services, Data: []byte{6}},
	}
	sets := New().Logos(logos, 0xfff7)
	if len(sets) != 1 {
		t.Fatalf("got %d logo sets, want one per logo id", len(sets))
	}
	set := sets[0]
	if set.LogoID != 0x0e3 || set.DownloadDataID != 0x0e3 || len(set.Sections) != 3 {
		t.Fatalf("set = id %#05x download %#06x sections %d", set.LogoID, set.DownloadDataID, len(set.Sections))
	}

	for i, want := range logos {
		parsed, _, err := si.ParseSection(set.Sections[i])
		if err != nil {
			t.Fatalf("section %d does not parse: %v", i, err)
		}
		if parsed.TableID != si.TableIDMHCDT || parsed.Extension != set.DownloadDataID {
			t.Errorf("section %d table %#02x download %#06x", i, parsed.TableID, parsed.Extension)
		}
		if parsed.Number != byte(i) || parsed.LastNumber != byte(len(logos)-1) {
			t.Errorf("section %d numbered %d/%d", i, parsed.Number, parsed.LastNumber)
		}
		cdt, ok := si.ParseCDT(parsed)
		if !ok || cdt.OriginalNetworkID != 0xfff7 || cdt.DataType != 0x01 {
			t.Fatalf("section %d cdt = %+v ok=%v", i, cdt, ok)
		}
		m := cdt.Module
		if len(m) < 7 || m[0] != want.Type {
			t.Fatalf("section %d module = % x", i, m)
		}
		if id := binary.BigEndian.Uint16(m[1:3]) & 0x01ff; id != want.ID {
			t.Errorf("section %d logo_id %#05x, want %#05x", i, id, want.ID)
		}
		if size := int(binary.BigEndian.Uint16(m[5:7])); size != len(want.Data) || string(m[7:7+size]) != string(want.Data) {
			t.Errorf("section %d image = % x, want % x", i, m[7:], want.Data)
		}
	}

	d := si.ParseDescriptors(set.Descriptor())
	if len(d) != 1 || d[0].Tag != si.TagMHLogoTransmission {
		t.Fatalf("descriptor = %+v", d)
	}
	l, ok := si.ParseLogoTransmission(d[0].Data)
	if !ok || l.Type != 0x01 || l.LogoID != 0x0e3 || l.DownloadDataID != 0x0e3 {
		t.Fatalf("logo transmission = %+v ok=%v", l, ok)
	}
	tail := d[0].Data[7:]
	want := []byte{0, 0, 1, 3, 1, 1, 5, 2, 1}
	if string(tail) != string(want) {
		t.Errorf("logo_type/section list = % x, want % x", tail, want)
	}
}
