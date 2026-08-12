// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"bytes"
	"encoding/binary"
	"testing"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/timeline"
	"mmt2ts/internal/tlv"
	"mmt2ts/internal/tscheck"
)

func convertWith(t *testing.T, input []byte, carousel bool) (Report, []byte) {
	t.Helper()
	var out bytes.Buffer
	opts := DefaultOptions()
	opts.ServiceID = 1
	opts.Carousel = carousel
	report, err := Run(bytes.NewReader(input), &out, opts)
	if err != nil {
		t.Fatalf("Run(carousel=%v): %v", carousel, err)
	}
	return report, out.Bytes()
}

type esUnit struct {
	pts, dts int64
	hasPTS   bool
	hasDTS   bool
	payload  []byte
}

func collectES(ts []byte, pid uint16) []esUnit {
	var (
		out     []esUnit
		current *esUnit
	)
	flush := func() {
		if current != nil {
			out = append(out, *current)
			current = nil
		}
	}
	for off := 0; off+188 <= len(ts); off += 188 {
		p := ts[off : off+188]
		if p[0] != 0x47 || binary.BigEndian.Uint16(p[1:3])&0x1fff != pid {
			continue
		}
		afc := (p[3] >> 4) & 0x03
		if afc&0x01 == 0 {
			continue
		}
		payload := p[4:]
		if afc&0x02 != 0 {
			afLen := int(p[4])
			if afLen > 183 {
				continue
			}
			payload = p[5+afLen:]
		}
		if p[1]&0x40 != 0 {
			flush()
			if len(payload) < 9 || payload[0] != 0 || payload[1] != 0 || payload[2] != 1 {
				continue
			}
			u := esUnit{}
			flags := payload[7]
			headerLen := int(payload[8])
			if flags&0x80 != 0 && headerLen >= 5 {
				u.pts, u.hasPTS = readTimestamp(payload[9:14]), true
			}
			if flags&0x40 != 0 && headerLen >= 10 {
				u.dts, u.hasDTS = readTimestamp(payload[14:19]), true
			}
			if 9+headerLen <= len(payload) {
				u.payload = append(u.payload, payload[9+headerLen:]...)
			}
			current = &u
			continue
		}
		if current != nil {
			current.payload = append(current.payload, payload...)
		}
	}
	flush()
	return out
}

func readTimestamp(b []byte) int64 {
	return int64(b[0]>>1&0x07)<<30 |
		int64(binary.BigEndian.Uint16(b[1:3])>>1)<<15 |
		int64(binary.BigEndian.Uint16(b[3:5])>>1)
}

func collectPCR(ts []byte, pid uint16) []int64 {
	var out []int64
	for off := 0; off+188 <= len(ts); off += 188 {
		p := ts[off : off+188]
		if p[0] != 0x47 || binary.BigEndian.Uint16(p[1:3])&0x1fff != pid {
			continue
		}
		if (p[3]>>4)&0x02 == 0 || p[4] == 0 || p[5]&0x10 == 0 {
			continue
		}
		base := int64(p[6])<<25 | int64(p[7])<<17 | int64(p[8])<<9 | int64(p[9])<<1 | int64(p[10]>>7)
		ext := int64(p[10]&0x01)<<8 | int64(p[11])
		out = append(out, base*300+ext)
	}
	return out
}

func TestTheCarouselDoesNotChangeTheMediaOutput(t *testing.T) {
	input := withSI(buildStream(4, 3, 5, -1))
	_, with := convertWith(t, input, true)
	_, without := convertWith(t, input, false)

	for _, pid := range []uint16{0x1011, 0x1100} {
		a, b := collectES(without, pid), collectES(with, pid)
		if len(a) != len(b) {
			t.Fatalf("PID %#04x: %d PES units without the carousel, %d with it", pid, len(a), len(b))
		}
		for i := range a {
			if a[i].hasPTS != b[i].hasPTS || a[i].pts != b[i].pts {
				t.Errorf("PID %#04x unit %d: PTS %d/%v without, %d/%v with", pid, i, a[i].pts, a[i].hasPTS, b[i].pts, b[i].hasPTS)
			}
			if a[i].hasDTS != b[i].hasDTS || a[i].dts != b[i].dts {
				t.Errorf("PID %#04x unit %d: DTS %d/%v without, %d/%v with", pid, i, a[i].dts, a[i].hasDTS, b[i].dts, b[i].hasDTS)
			}
			if !bytes.Equal(a[i].payload, b[i].payload) {
				t.Errorf("PID %#04x unit %d: PES payload differs (%d bytes without, %d with)",
					pid, i, len(a[i].payload), len(b[i].payload))
			}
		}
	}

	if a, b := collectPCR(without, 0x1011), collectPCR(with, 0x1011); len(a) != len(b) {
		t.Errorf("PCR count %d without the carousel, %d with it", len(a), len(b))
	} else {
		for i := range a {
			if a[i] != b[i] {
				t.Errorf("PCR %d = %d without the carousel, %d with it", i, a[i], b[i])
			}
		}
	}
}

func TestTheCaptionOutputIsUnchangedByTheCarousel(t *testing.T) {
	input := buildCaptionStream()
	_, with := convertWith(t, input, true)
	_, without := convertWith(t, input, false)

	a, b := collectES(without, 0x1200), collectES(with, 0x1200)
	if len(a) == 0 {
		t.Skip("the synthetic caption stream produced no caption PES")
	}
	if len(a) != len(b) {
		t.Fatalf("%d caption PES units without the carousel, %d with it", len(a), len(b))
	}
	for i := range a {
		if a[i].pts != b[i].pts || a[i].hasPTS != b[i].hasPTS {
			t.Errorf("caption unit %d: PTS %d/%v without, %d/%v with", i, a[i].pts, a[i].hasPTS, b[i].pts, b[i].hasPTS)
		}
		if !bytes.Equal(a[i].payload, b[i].payload) {
			t.Errorf("caption unit %d: payload differs", i)
		}
	}
}

func TestTheCarouselIsAnnouncedInThePMTWithoutADataComponentDescriptor(t *testing.T) {
	report, out := convertWith(t, withSI(buildStream(4, 3, 5, -1)), true)
	pmt := lastSection(out, 0x0100, mpegts.TableIDPMT)
	if pmt == nil {
		t.Fatal("no PMT in the output")
	}

	found := map[uint16]byte{}
	infoLen := int(binary.BigEndian.Uint16(pmt[10:12]) & 0x0fff)
	for p, end := 12+infoLen, len(pmt)-4; p+5 <= end; {
		streamType := pmt[p]
		pid := binary.BigEndian.Uint16(pmt[p+1:p+3]) & 0x1fff
		esLen := int(binary.BigEndian.Uint16(pmt[p+3:p+5]) & 0x0fff)
		p += 5
		if streamType == mpegts.StreamTypeDSMCC {
			var tag byte
			for d := pmt[p : p+esLen]; len(d) >= 2 && len(d) >= 2+int(d[1]); d = d[2+int(d[1]):] {
				switch d[0] {
				case mpegts.DescStreamIdentifier:
					tag = d[2]
				case 0xfd:
					t.Errorf("PID %#04x carries a data_component_descriptor, which this profile forbids", pid)
				}
			}
			found[pid] = tag
		}
		p += esLen
	}
	if len(found) != 2 {
		t.Fatalf("the PMT announces %d DSM-CC streams, want 2", len(found))
	}
	if tag, ok := found[report.CarouselRealtimePID]; !ok || tag != realtimeCarouselTag {
		t.Errorf("realtime carousel PID %#04x tag %#02x", report.CarouselRealtimePID, tag)
	}
	if tag, ok := found[report.CarouselObjectPID]; !ok || tag != objectCarouselTag {
		t.Errorf("object carousel PID %#04x tag %#02x", report.CarouselObjectPID, tag)
	}
	if report.CarouselRealtimePID != realtimeCarouselPID || report.CarouselObjectPID != objectCarouselPID {
		t.Errorf("carousels landed on %#04x/%#04x, want the preferred %#04x/%#04x",
			report.CarouselRealtimePID, report.CarouselObjectPID, realtimeCarouselPID, objectCarouselPID)
	}
}

func lastSection(ts []byte, pid uint16, tableID byte) []byte {
	var out []byte
	for off := 0; off+188 <= len(ts); off += 188 {
		p := ts[off : off+188]
		if p[0] != 0x47 || binary.BigEndian.Uint16(p[1:3])&0x1fff != pid || p[1]&0x40 == 0 {
			continue
		}
		afc := (p[3] >> 4) & 0x03
		payload := p[4:]
		if afc&0x02 != 0 {
			payload = p[5+int(p[4]):]
		}
		if len(payload) < 4 {
			continue
		}
		payload = payload[1+int(payload[0]):]
		if len(payload) < 3 || payload[0] != tableID {
			continue
		}
		length := int(binary.BigEndian.Uint16(payload[1:3])&0x0fff) + 3
		if length > len(payload) {
			continue
		}
		out = bytes.Clone(payload[:length])
	}
	return out
}

func TestTheReferenceReaderVerifiesTheCarousel(t *testing.T) {
	report, out := convertWith(t, withSI(buildStream(6, 3, 5, -1)), true)
	check, err := tscheck.Scan(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("tscheck: %v", err)
	}
	if check.Errors() != 0 {
		tscheck.WriteReport(testWriter{t}, check)
		t.Fatalf("independent check found %d problems", check.Errors())
	}
	if check.DIISections == 0 || check.DDBSections == 0 {
		t.Fatalf("reader saw DII %d, DDB %d", check.DIISections, check.DDBSections)
	}
	if check.ModulesVerified == 0 {
		t.Fatal("no module passed its own checksums")
	}
	if check.BootstrapModules == 0 || check.DirectoryVerified == 0 {
		t.Errorf("bootstraps %d, directory entries verified %d", check.BootstrapModules, check.DirectoryVerified)
	}
	if check.ModuleKinds[byte(preservation.KindTimedSegment)] == 0 {
		t.Errorf("no time segment reached the output: %v", check.ModuleKinds)
	}
	if report.Carousel.Records == 0 || report.Carousel.Segments == 0 {
		t.Errorf("the recorder stored %d records in %d segments", report.Carousel.Records, report.Carousel.Segments)
	}
}

func TestLosingOneCarouselSectionLeavesTheMediaIntact(t *testing.T) {
	input := withSI(buildStream(6, 3, 5, -1))
	report, out := convertWith(t, input, true)

	damaged := bytes.Clone(out)
	dropped := 0
	for off := 0; off+188 <= len(damaged); off += 188 {
		p := damaged[off : off+188]
		if binary.BigEndian.Uint16(p[1:3])&0x1fff != report.CarouselRealtimePID {
			continue
		}
		p[1], p[2] = 0x1f, 0xff
		p[3] &^= 0x30
		dropped++
		break
	}
	if dropped == 0 {
		t.Fatal("no carousel packet to damage")
	}

	for _, pid := range []uint16{0x1011, 0x1100} {
		a, b := collectES(out, pid), collectES(damaged, pid)
		if len(a) != len(b) {
			t.Fatalf("PID %#04x: %d units before the damage, %d after", pid, len(a), len(b))
		}
		for i := range a {
			if a[i].pts != b[i].pts || !bytes.Equal(a[i].payload, b[i].payload) {
				t.Fatalf("PID %#04x unit %d changed when a carousel section was lost", pid, i)
			}
		}
	}
}

func TestTheCarouselSurvivesAMidStreamJoin(t *testing.T) {
	_, out := convertWith(t, withSI(buildStream(8, 3, 5, -1)), true)
	cut := (len(out) / 188 / 3) * 188
	check, err := tscheck.Scan(bytes.NewReader(out[cut:]))
	if err != nil {
		t.Fatalf("tscheck: %v", err)
	}
	if check.DSMCCErrors != 0 {
		tscheck.WriteReport(testWriter{t}, check)
		t.Fatalf("a mid-stream join produced %d DSM-CC errors", check.DSMCCErrors)
	}
	if check.ModulesVerified == 0 {
		t.Error("no module could be rebuilt after a mid-stream join")
	}
}

func TestDisablingTheCarouselLeavesNoTraceInTheOutput(t *testing.T) {
	report, out := convertWith(t, withSI(buildStream(4, 3, 5, -1)), false)
	if report.CarouselRealtimePID != 0 || report.CarouselObjectPID != 0 {
		t.Errorf("the report names carousel PIDs %#04x/%#04x with the carousel off",
			report.CarouselRealtimePID, report.CarouselObjectPID)
	}
	check, err := tscheck.Scan(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("tscheck: %v", err)
	}
	if check.DSMCCSections != 0 {
		t.Errorf("found %d DSM-CC sections with the carousel off", check.DSMCCSections)
	}
	for _, pid := range []uint16{realtimeCarouselPID, objectCarouselPID} {
		if check.PIDs[pid] != nil {
			t.Errorf("PID %#04x carries packets with the carousel off", pid)
		}
	}
}

func metaValue(m preservation.Metadata, t preservation.MetaType) []byte {
	for _, e := range m {
		if e.Type == t {
			return e.Value
		}
	}
	return nil
}

func TestTransportMetadataCarriesTheAddressesOfTheInputPacket(t *testing.T) {
	src := []byte{0x24, 0x01, 0xdb, 0xc0, 0x10, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	dst := []byte{0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa0, 0x00, 0x10, 0x00}
	meta := tlvMeta(
		tlv.Packet{Type: tlv.TypeCompressedIP, Offset: 4096},
		tlv.Datagram{Src: src, Dst: dst, SrcPort: 50000, DstPort: 51216, HasPort: true},
		true,
	)

	for _, tc := range []struct {
		name string
		typ  preservation.MetaType
		want []byte
	}{
		{"TLV packet type", preservation.MetaTLVPacketType, []byte{tlv.TypeCompressedIP}},
		{"input offset", preservation.MetaInputOffset, []byte{0, 0, 0, 0, 0, 0, 0x10, 0x00}},
		{"IP source", preservation.MetaIPSource, src},
		{"IP destination", preservation.MetaIPDestination, dst},
		{"IP protocol", preservation.MetaIPProtocol, []byte{17}},
		{"UDP source port", preservation.MetaUDPSourcePort, []byte{0xc3, 0x50}},
		{"UDP destination port", preservation.MetaUDPDestPort, []byte{0xc8, 0x10}},
	} {
		if got := metaValue(meta, tc.typ); !bytes.Equal(got, tc.want) {
			t.Errorf("%s = % x, want % x", tc.name, got, tc.want)
		}
	}
	if _, err := preservation.EncodeSegment([]preservation.Record{
		{Kind: preservation.RecordRawSignalling, Metadata: meta},
	}); err != nil {
		t.Errorf("EncodeSegment rejected the transport metadata: %v", err)
	}
}

func TestTransportMetadataOmitsWhatTheInputDidNotCarry(t *testing.T) {
	meta := tlvMeta(
		tlv.Packet{Type: tlv.TypeCompressedIP, Offset: 8},
		tlv.Datagram{Payload: []byte("mmt")},
		true,
	)
	for _, typ := range []preservation.MetaType{
		preservation.MetaIPSource, preservation.MetaIPDestination,
		preservation.MetaIPProtocol, preservation.MetaUDPSourcePort, preservation.MetaUDPDestPort,
	} {
		if got := metaValue(meta, typ); got != nil {
			t.Errorf("metadata %#04x = % x for a packet that carried none", uint16(typ), got)
		}
	}
	if got := metaValue(meta, preservation.MetaTLVPacketType); got == nil {
		t.Error("the TLV packet type is always known and must still be recorded")
	}
}

func videoComponentDescriptorBody(resolution, aspect byte, tag uint16, lang string) []byte {
	b := []byte{resolution<<4 | aspect&0x0f, 0x80 | 0x08}
	b = binary.BigEndian.AppendUint16(b, tag)
	b = append(b, 0x10)
	return append(b, lang...)
}

func pmtStreams(ts []byte) map[uint16]struct {
	streamType  byte
	descriptors []byte
} {
	out := map[uint16]struct {
		streamType  byte
		descriptors []byte
	}{}
	pmt := lastSection(ts, 0x0100, mpegts.TableIDPMT)
	if pmt == nil {
		return out
	}
	infoLen := int(binary.BigEndian.Uint16(pmt[10:12]) & 0x0fff)
	for p, end := 12+infoLen, len(pmt)-4; p+5 <= end; {
		st := pmt[p]
		pid := binary.BigEndian.Uint16(pmt[p+1:p+3]) & 0x1fff
		esLen := int(binary.BigEndian.Uint16(pmt[p+3:p+5]) & 0x0fff)
		p += 5
		if p+esLen > end {
			break
		}
		out[pid] = struct {
			streamType  byte
			descriptors []byte
		}{st, bytes.Clone(pmt[p : p+esLen])}
		p += esLen
	}
	return out
}

func findDescriptor(loop []byte, tag byte) []byte {
	for d := loop; len(d) >= 2 && len(d) >= 2+int(d[1]); d = d[2+int(d[1]):] {
		if d[0] == tag {
			return d[2 : 2+int(d[1])]
		}
	}
	return nil
}

func TestVideoStreamsCarryAComponentDescriptor(t *testing.T) {
	b := newBuilder()
	const secondVideoPID = 0xf101
	seqA := []uint32{100, 101, 102}
	seqB := []uint32{300, 301, 302}
	timesA := map[uint32]uint64{}
	timesB := map[uint32]uint64{}
	for i := range seqA {
		when := testNTPBase + uint64(i)*2*testVideoTick<<32/testTimescale
		timesA[seqA[i]], timesB[seqB[i]] = when, when
	}
	videoAsset := func(pid, tag uint16, resolution byte, seqs []uint32, times map[uint32]uint64) testAsset {
		d := append(mpuTimestampDescriptor(times, seqs),
			extendedTimestampDescriptor(seqs, 2, testVideoTick, []uint16{0})...)
		d = append(d, descriptor(signaling.TagVideoComponent,
			videoComponentDescriptorBody(resolution, 3, tag, "jpn"))...)
		return testAsset{assetType: "hev1", packetID: pid, tag: tag, descriptors: d}
	}
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTable(1)), 0)
	b.mmtp(testMPTPID, 0x02, false, signalingPayload(mptTable(1, []testAsset{
		videoAsset(testVideoPID, 0x0000, 5, seqA, timesA),
		videoAsset(secondVideoPID, 0x0001, 1, seqB, timesB),
	})), 0)
	writeVideo := func(pid uint16, seq uint32) {
		b.mmtp(pid, 0x00, true, mpuPayload(seq, nal(35, 3)), 0)
		for _, typ := range []byte{32, 33, 34} {
			b.mmtp(pid, 0x00, false, mpuPayload(seq, nal(typ, 16)), 0)
		}
		b.mmtp(pid, 0x00, false, mpuPayload(seq, nal(19, 64)), 0)
	}
	for i := range seqA {
		writeVideo(testVideoPID, seqA[i])
		writeVideo(secondVideoPID, seqB[i])
	}
	_, _, out := convert(t, b.buf.Bytes())

	streams := pmtStreams(out)
	for _, tc := range []struct {
		pid           uint16
		tag           byte
		componentType byte
	}{
		{0x1011, 0x00, 0xe0 | 3},
		{0x1012, 0x01, 0xf0 | 3},
	} {
		es, ok := streams[tc.pid]
		if !ok {
			t.Fatalf("PID %#04x is not in the PMT", tc.pid)
		}
		if es.streamType != mpegts.StreamTypeHEVC {
			t.Errorf("PID %#04x stream_type = %#02x", tc.pid, es.streamType)
		}
		body := findDescriptor(es.descriptors, mpegts.DescComponent)
		if body == nil {
			t.Fatalf("PID %#04x has no component descriptor: % x", tc.pid, es.descriptors)
		}
		if len(body) < 6 {
			t.Fatalf("PID %#04x component descriptor is %d bytes", tc.pid, len(body))
		}
		if got := body[0] & 0x0f; got != 0x01 {
			t.Errorf("PID %#04x stream_content = %#x, want 1", tc.pid, got)
		}
		if body[1] != tc.componentType {
			t.Errorf("PID %#04x component_type = %#02x, want %#02x", tc.pid, body[1], tc.componentType)
		}
		if body[2] != tc.tag {
			t.Errorf("PID %#04x component_tag = %#02x, want %#02x", tc.pid, body[2], tc.tag)
		}
		if string(body[3:6]) != "jpn" {
			t.Errorf("PID %#04x language = %q", tc.pid, body[3:6])
		}
		if id := findDescriptor(es.descriptors, mpegts.DescStreamIdentifier); len(id) != 1 || id[0] != tc.tag {
			t.Errorf("PID %#04x stream identifier = % x, want %#02x", tc.pid, id, tc.tag)
		}
	}
}

func TestAVideoTagOutsideItsRangeDoesNotReachIntoTheAudioBand(t *testing.T) {
	for _, tc := range []struct {
		name string
		tag  uint16
		want uint16
	}{
		{"main video", 0x0000, 0x1011},
		{"second video", 0x0001, 0x1012},
		{"last video tag", 0x000f, 0x1020},
		{"past the video range", 0x0010, 0x1011},
		{"far past the video range", 0x00ef, 0x1011},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &converter{usedPID: make(map[uint16]bool)}
			s := &stream{pkg: newPkg(0, nil), kind: KindVideo, mmtTag: tc.tag, hasMMTTag: true}
			if got := c.allocatePID(s); got != tc.want {
				t.Errorf("tag %#04x allocated PID %#04x, want %#04x", tc.tag, got, tc.want)
			}
		})
	}

	c := &converter{usedPID: make(map[uint16]bool)}
	p := newPkg(0, nil)
	video := c.allocatePID(&stream{pkg: p, kind: KindVideo, mmtTag: 0x00ef, hasMMTTag: true})
	audio := c.allocatePID(&stream{pkg: p, kind: KindAudio, mmtTag: 0x0010, hasMMTTag: true})
	if audio != 0x1100 {
		t.Errorf("audio landed on %#04x after a video with tag 0x00ef took %#04x", audio, video)
	}
}

func assetGroupDescriptor(identification, selectionLevel byte) []byte {
	return descriptor(signaling.TagAssetGroup, []byte{identification, selectionLevel})
}

// buildRainFadePair carries one asset group holding the video a receiver
// shows and the backup that stands in for it during rain fade.  The backup
// is on the air throughout; mainStartsAt is the MPU the video it backs up
// first appears on, which on a real stream trails it by whole seconds.
func buildRainFadePair(mpuCount, mainStartsAt int) []byte {
	b := newBuilder()
	seqA := make([]uint32, mpuCount)
	seqB := make([]uint32, mpuCount)
	timesA := map[uint32]uint64{}
	timesB := map[uint32]uint64{}
	for i := range seqA {
		seqA[i], seqB[i] = uint32(100+i), uint32(300+i)
		when := testNTPBase + uint64(i)*2*testVideoTick<<32/testTimescale
		timesA[seqA[i]], timesB[seqB[i]] = when, when
	}
	videoAsset := func(pid, tag uint16, selection byte, seqs []uint32, times map[uint32]uint64) testAsset {
		d := append(mpuTimestampDescriptor(times, seqs),
			extendedTimestampDescriptor(seqs, 2, testVideoTick, []uint16{0})...)
		d = append(d, assetGroupDescriptor(1, selection)...)
		return testAsset{assetType: "hev1", packetID: pid, tag: tag, descriptors: d}
	}
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTable(1)), 0)
	b.mmtp(testMPTPID, 0x02, false, signalingPayload(mptTable(1, []testAsset{
		videoAsset(testVideoPID, 0x0000, 0, seqA, timesA),
		videoAsset(backupVideoPID, 0x0001, 1, seqB, timesB),
	})), 0)
	writeVideo := func(pid uint16, seq uint32) {
		b.mmtp(pid, 0x00, true, mpuPayload(seq, nal(35, 3)), 0)
		for _, typ := range []byte{32, 33, 34} {
			b.mmtp(pid, 0x00, false, mpuPayload(seq, nal(typ, 16)), 0)
		}
		b.mmtp(pid, 0x00, false, mpuPayload(seq, nal(19, 64)), 0)
	}
	for i := range seqA {
		writeVideo(backupVideoPID, seqB[i])
		if i >= mainStartsAt {
			writeVideo(testVideoPID, seqA[i])
		}
	}
	return b.buf.Bytes()
}

const backupVideoPID = 0xf101

func TestARainFadeVideoPairIsDescribedAsHierarchicalTransmission(t *testing.T) {
	_, _, out := convert(t, buildRainFadePair(3, 0))

	streams := pmtStreams(out)
	for _, tc := range []struct {
		pid         uint16
		peer        uint16
		highQuality bool
	}{
		{0x1011, 0x1012, true},
		{0x1012, 0x1011, false},
	} {
		es, ok := streams[tc.pid]
		if !ok {
			t.Fatalf("PID %#04x is not in the PMT", tc.pid)
		}
		body := findDescriptor(es.descriptors, mpegts.DescHierarchicalTx)
		if len(body) != 3 {
			t.Fatalf("PID %#04x hierarchical transmission descriptor = % x", tc.pid, body)
		}
		if got := body[0]&0x01 != 0; got != tc.highQuality {
			t.Errorf("PID %#04x quality_level high = %v, want %v", tc.pid, got, tc.highQuality)
		}
		if got := binary.BigEndian.Uint16(body[1:3]) & 0x1fff; got != tc.peer {
			t.Errorf("PID %#04x reference_PID = %#04x, want %#04x", tc.pid, got, tc.peer)
		}
	}
}

func TestTheClockLandsOnTheVideoTheGroupLeadsWith(t *testing.T) {
	// The backup is alone on the air long enough to be written before the
	// video it stands in for exists, so the clock has to move off it again:
	// a PCR on the rain fade stream leaves a receiver reading the time from
	// a picture it never decodes.  A short reorder window puts the first
	// packets out early, the way a long stream does once its window fills.
	var buf bytes.Buffer
	opts := DefaultOptions()
	opts.ServiceID = 1
	opts.ReorderWindow = timeline.Hz / 10
	if _, err := Run(bytes.NewReader(buildRainFadePair(20, 8)), &buf, opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := buf.Bytes()
	check, err := tscheck.Scan(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("tscheck: %v", err)
	}
	pmt := lastSection(out, 0x0100, mpegts.TableIDPMT)
	if pmt == nil {
		t.Fatal("no PMT was written")
	}
	if pcr := binary.BigEndian.Uint16(pmt[8:10]) & 0x1fff; pcr != 0x1011 {
		t.Errorf("PCR PID = %#04x, want the video the group leads with, %#04x", pcr, 0x1011)
	}
	if check.Errors() != 0 {
		tscheck.WriteReport(testWriter{t}, check)
		t.Fatalf("independent check found %d problems", check.Errors())
	}
}

func TestVideoWithoutAnAssetGroupHasNoHierarchyDescriptor(t *testing.T) {
	_, _, out := convert(t, withSI(buildStream(4, 3, 5, -1)))
	es, ok := pmtStreams(out)[0x1011]
	if !ok {
		t.Fatal("the video stream is not in the PMT")
	}
	if body := findDescriptor(es.descriptors, mpegts.DescHierarchicalTx); body != nil {
		t.Errorf("a single video was described as hierarchically transmitted: % x", body)
	}
}

func (b *builder) mmtpScrambled(pid uint16, payload []byte) {
	seq := b.seqs[pid]
	b.seqs[pid] = seq + 1
	head := make([]byte, 12)
	head[0] = 0x02
	head[1] = 0x00
	binary.BigEndian.PutUint16(head[2:4], pid)
	binary.BigEndian.PutUint32(head[8:12], seq)
	ext := []byte{0x80, 0x01, 0x00, 0x01, 0x01}
	head = binary.BigEndian.AppendUint16(head, 0x0000)
	head = binary.BigEndian.AppendUint16(head, uint16(len(ext)))
	head = append(head, ext...)
	b.tlv(append(head, payload...))
}

func buildEncryptedVideoStream() []byte {
	b := newBuilder()
	const audioPID = 0xf110
	seqs := []uint32{100, 101, 102}
	times := map[uint32]uint64{}
	for i := range seqs {
		times[seqs[i]] = testNTPBase + uint64(i)*2*testVideoTick<<32/testTimescale
	}
	video := testAsset{assetType: "hev1", packetID: testVideoPID, tag: 0x0000, descriptors: append(
		mpuTimestampDescriptor(times, seqs),
		extendedTimestampDescriptor(seqs, 2, testVideoTick, []uint16{0})...)}
	audio := testAsset{assetType: "mp4a", packetID: audioPID, tag: 0x0010, descriptors: append(
		mpuTimestampDescriptor(times, seqs),
		extendedTimestampDescriptor(seqs, 2, testVideoTick, []uint16{0})...)}
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTable(1)), 0)
	b.mmtp(testMPTPID, 0x02, false, signalingPayload(mptTable(1, []testAsset{video, audio})), 0)
	for _, seq := range seqs {
		b.mmtpScrambled(testVideoPID, mpuPayload(seq, nal(35, 3)))
		b.mmtpScrambled(testVideoPID, mpuPayload(seq, nal(19, 64)))
		b.mmtp(audioPID, 0x00, true, mpuPayload(seq, audioFrame(64)), 0)
	}
	return b.buf.Bytes()
}

func TestAnEncryptedAssetStaysOutOfThePMT(t *testing.T) {
	report, out := convertWith(t, buildEncryptedVideoStream(), true)

	streams := pmtStreams(out)
	if _, ok := streams[0x1011]; ok {
		t.Error("the encrypted video reached the PMT")
	}
	if _, ok := streams[0x1100]; !ok {
		t.Fatalf("the clear audio is not in the PMT: %v", streams)
	}
	check, err := tscheck.Scan(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("tscheck: %v", err)
	}
	if check.Errors() != 0 {
		tscheck.WriteReport(testWriter{t}, check)
		t.Fatalf("independent check found %d problems", check.Errors())
	}
	if check.PIDs[0x1011] != nil {
		t.Error("packets were written on the PID of the encrypted asset")
	}
	if check.PCRPID != 0x1100 {
		t.Errorf("PCR PID = %#04x, want the clear audio", check.PCRPID)
	}

	var video, audio *StreamStat
	for i := range report.Streams {
		switch report.Streams[i].AssetType {
		case "hev1":
			video = &report.Streams[i]
		case "mp4a":
			audio = &report.Streams[i]
		}
	}
	if video == nil || audio == nil {
		t.Fatalf("streams = %+v", report.Streams)
	}
	if video.InPMT {
		t.Error("the encrypted asset was reported as being in the PMT")
	}
	if video.ScrambledPackets == 0 {
		t.Error("no encrypted packet was counted for the video asset")
	}
	if !audio.InPMT || audio.AUsOut == 0 {
		t.Errorf("the clear audio was not converted: %+v", audio)
	}
	if report.Carousel.Records == 0 {
		t.Error("the encrypted packets were not preserved")
	}
}

func TestNothingIsMarkedScrambledInTheOutput(t *testing.T) {
	_, out := convertWith(t, buildEncryptedVideoStream(), true)
	for off := 0; off+188 <= len(out); off += 188 {
		if out[off] != 0x47 {
			continue
		}
		if out[off+3]&0xc0 != 0 {
			pid := binary.BigEndian.Uint16(out[off+1:off+3]) & 0x1fff
			t.Fatalf("packet at %d on PID %#04x sets transport_scrambling_control", off, pid)
		}
	}
}

func TestAProgrammeWithNoClearStreamDeclaresTheNullPCRPID(t *testing.T) {
	b := newBuilder()
	seqs := []uint32{100, 101}
	times := map[uint32]uint64{}
	for i := range seqs {
		times[seqs[i]] = testNTPBase + uint64(i)*2*testVideoTick<<32/testTimescale
	}
	video := testAsset{assetType: "hev1", packetID: testVideoPID, tag: 0x0000, descriptors: append(
		mpuTimestampDescriptor(times, seqs),
		extendedTimestampDescriptor(seqs, 2, testVideoTick, []uint16{0})...)}
	b.ntp(testNTPBase)
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTable(1)), 0)
	b.mmtp(testMPTPID, 0x02, false, signalingPayload(mptTable(1, []testAsset{video})), 0)
	for i, seq := range seqs {
		b.ntp(testNTPBase + uint64(i+1)<<32)
		b.mmtpScrambled(testVideoPID, mpuPayload(seq, nal(35, 3)))
		b.mmtpScrambled(testVideoPID, mpuPayload(seq, nal(19, 64)))
	}
	_, out := convertWith(t, b.buf.Bytes(), true)

	pmt := lastSection(out, 0x0100, mpegts.TableIDPMT)
	if pmt == nil {
		t.Fatal("no PMT in the output")
	}
	if got := binary.BigEndian.Uint16(pmt[8:10]) & 0x1fff; got != mpegts.PIDNull {
		t.Errorf("PCR_PID = %#04x, want the null PID when nothing is clear", got)
	}
}

func TestTheEITDoesNotDescribeAnEncryptedComponent(t *testing.T) {
	c := &converter{usedPID: make(map[uint16]bool)}
	p := newPkg(0, nil)
	encrypted := &stream{pkg: p, kind: KindVideo, mmtTag: 0x0000, hasMMTTag: true}
	clear := &stream{pkg: p, kind: KindAudio, mmtTag: 0x0010, hasMMTTag: true}
	p.order = []*stream{encrypted, clear}

	if _, ok := p.TSTag(0x0000); ok {
		t.Error("an asset with no clear PES was offered to the SI converter")
	}
	if _, ok := p.TSTag(0x0010); ok {
		t.Error("an asset with no clear PES was offered to the SI converter")
	}

	c.assignOutput(clear)
	if _, ok := p.TSTag(0x0000); ok {
		t.Error("the encrypted video is still named by the SI converter")
	}
	tag, ok := p.TSTag(0x0010)
	if !ok || tag != clear.tsTag {
		t.Errorf("TSTag(0x0010) = %#02x, %v, want the tag of the converted audio", tag, ok)
	}
}
