// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"bytes"
	"encoding/binary"
	"io"
	"mmt2ts/internal/tlv"
	"testing"
	"time"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/si"
	"mmt2ts/internal/tsdemux"
)

const (
	testService  = 0x0066
	testNTPBase  = uint64(0xebd83880) << 32
	testRealtime = 0x1d00
	testObject   = 0x1d01
)

func buildCarouselTS(t *testing.T, fill func(r *preservation.Recorder)) []byte {
	return buildCarouselTSWith(t, carouselTSOptions{fill: fill})
}

type carouselTSOptions struct {
	fill    func(r *preservation.Recorder)
	streams []mpegts.ElementaryStream
	media   func(w *mpegts.Writer)
	span    uint64 // 秒。0 なら 4
}

func buildCarouselTSWith(t *testing.T, o carouselTSOptions) []byte {
	t.Helper()
	rec, err := preservation.NewRecorder(preservation.Config{
		ServiceID: testService, TransportStreamID: 0x4010, OriginalNetworkID: 4,
		RealtimePID: testRealtime, ObjectPID: testObject, RealtimeTag: 0xe0, ObjectTag: 0xe1,
	})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	span := o.span
	if span == 0 {
		span = 4
	}
	rec.Observe(testNTPBase)
	o.fill(rec)
	rec.Observe(testNTPBase + (span << 32))
	if err := rec.Finish(4_000_000_000); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	var buf bytes.Buffer
	w := mpegts.NewWriter(&buf)
	if err := w.WriteSection(0x0000, mpegts.BuildPAT(1, 0, []mpegts.Program{{Number: 1, PID: 0x0100}}, 0)); err != nil {
		t.Fatal(err)
	}
	streams := append([]mpegts.ElementaryStream{
		{StreamType: mpegts.StreamTypeDSMCC, PID: testRealtime, Descriptors: mpegts.StreamIdentifierDescriptor(0xe0)},
		{StreamType: mpegts.StreamTypeDSMCC, PID: testObject, Descriptors: mpegts.StreamIdentifierDescriptor(0xe1)},
	}, o.streams...)
	pmt := mpegts.BuildPMT(1, 0, testRealtime, nil, streams)
	if err := w.WriteSection(0x0100, pmt); err != nil {
		t.Fatal(err)
	}
	if o.media != nil {
		o.media(w)
	}
	if err := rec.Emit(4_000_000_000, func(pid uint16, section []byte) error {
		return w.WriteSection(pid, section)
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func signallingMeta(packetID uint16) preservation.Metadata {
	var meta preservation.Metadata
	meta.AddU16(preservation.MetaPacketID, packetID)
	meta.AddU8(preservation.MetaSignallingKind, preservation.SignallingPA)
	meta.AddIP(preservation.MetaIPSource, []byte{192, 0, 2, 9})
	meta.AddIP(preservation.MetaIPDestination, []byte{224, 0, 0, 9})
	meta.AddU16(preservation.MetaUDPSourcePort, 1111)
	meta.AddU16(preservation.MetaUDPDestPort, 2222)
	return meta
}

// Recorder.Emit は object カルーセルを realtime の後に書くので、窓を短くすれば
// activation が窓の外へ出た時点でまだ object がない。
func TestRunWritesCaptionWhoseObjectArrivesAfterItsActivation(t *testing.T) {
	ttml := []byte("<tt xmlns=\"http://www.w3.org/ns/ttml\">late object</tt>")
	const objectID = 0x0200000000000001
	ts := buildCarouselTSWith(t, carouselTSOptions{span: 12, fill: func(rec *preservation.Recorder) {
		rec.AddRecord(preservation.RecordRawSignalling, preservation.RecordRawExact|preservation.RecordRequired,
			testNTPBase, signallingMeta(0x0000), buildPAMessage())
		if err := rec.AddObject(preservation.PackInput{ID: objectID, Class: preservation.ClassTTML,
			Flags: preservation.ObjectRawExact, MediaType: "application/ttml+xml", Stored: ttml}); err != nil {
			t.Fatalf("AddObject: %v", err)
		}
		var meta preservation.Metadata
		meta.AddU16(preservation.MetaPacketID, 0xf330)
		meta.AddU16(preservation.MetaComponentTag, 0x0030)
		meta.AddU32(preservation.MetaMPUSequence, 7)
		meta.AddBytes(preservation.MetaSubtitleID, []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00})
		activation := preservation.ObjectActivation{ObjectID: objectID, Generation: 7, Action: preservation.ObjectActivate}
		rec.AddRecord(preservation.RecordObjectActivation, preservation.RecordRequired,
			testNTPBase+(1<<32), meta, activation.Encode())
		rec.AddRecord(preservation.RecordRawSignalling, preservation.RecordRawExact|preservation.RecordRequired,
			testNTPBase+(10<<32), signallingMeta(0x0000), buildPAMessage())
	}})

	var out bytes.Buffer
	report, err := RunWithOptions(bytes.NewReader(ts), &out, Options{Window: time.Second})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Problems) > 0 {
		t.Fatalf("unexpected problems: %v", report.Problems)
	}
	if report.CaptionUnits != 1 {
		t.Fatalf("CaptionUnits = %d, want 1", report.CaptionUnits)
	}
	if !bytes.Contains(out.Bytes(), ttml) {
		t.Fatal("the caption resource was not written")
	}
}

func TestRunReplaysAccessUnitsThroughTheAVMap(t *testing.T) {
	nal := []byte{0x26, 0x01, 0xaa, 0xbb, 0xcc}
	annexB := append([]byte{0, 0, 0, 1}, nal...)
	ts := buildCarouselTSWith(t, carouselTSOptions{
		streams: []mpegts.ElementaryStream{
			{StreamType: mpegts.StreamTypeHEVC, PID: 0x1011, Descriptors: mpegts.StreamIdentifierDescriptor(0)},
		},
		media: func(w *mpegts.Writer) {
			if err := w.WriteUnit(0x1011, generalTestPES(0xe0, 90000, annexB), mpegts.Adaptation{RandomAccess: true}); err != nil {
				t.Fatal(err)
			}
		},
		fill: func(rec *preservation.Recorder) {
			rec.AddRecord(preservation.RecordRawSignalling, preservation.RecordRawExact|preservation.RecordRequired,
				testNTPBase, signallingMeta(0x0000), buildPAMessage())
			rec.AddAVMapEntry(preservation.AVMapEntry{
				PacketID: 0xf300, OutputPID: 0x1011, MPUSequence: 3, FirstAUOrdinal: 0, AUCount: 1,
				StartNTP: testNTPBase + (1 << 32), EndNTP: testNTPBase + (1 << 32), AssetType: [4]byte{'h', 'e', 'v', '1'},
			})
		},
	})

	var out bytes.Buffer
	report, err := Run(bytes.NewReader(ts), &out)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Problems) > 0 {
		t.Fatalf("unexpected problems: %v", report.Problems)
	}
	if report.AVAccessUnits != 1 {
		t.Fatalf("AVAccessUnits = %d, want 1", report.AVAccessUnits)
	}
	samples := readMPUSamples(t, out.Bytes())
	if len(samples) != 1 || !bytes.Equal(samples[0], sampleFromNALs(nal)) {
		t.Fatalf("samples = %x, want the one NAL unit", samples)
	}
}

func TestAUQueueDropsWrittenUnitsAndKeepsOrdinals(t *testing.T) {
	var q auQueue
	for i := range 100 {
		q.push(tsdemux.PES{Payload: []byte{byte(i)}})
	}
	q.dropBefore(60)
	if q.base != 60 || q.end() != 100 {
		t.Fatalf("base = %d, end = %d, want 60 and 100", q.base, q.end())
	}
	got := q.payloads(60, 63)
	if len(got) != 3 || got[0][0] != 60 || got[2][0] != 62 {
		t.Fatalf("payloads(60, 63) = %v", got)
	}
	q.dropBefore(10)
	if q.base != 60 {
		t.Fatalf("dropping before the base moved it to %d", q.base)
	}
	q.dropBefore(1000)
	if q.base != 100 || len(q.pes) != 0 {
		t.Fatalf("dropping past the end left base %d and %d units", q.base, len(q.pes))
	}
}

func TestRunReplaysRawSignalling(t *testing.T) {
	pa := buildPAMessage()
	ts := buildCarouselTS(t, func(rec *preservation.Recorder) {
		var meta preservation.Metadata
		meta.AddU16(preservation.MetaPacketID, 0x0000)
		meta.AddU8(preservation.MetaSignallingKind, preservation.SignallingPA)
		meta.AddIP(preservation.MetaIPSource, []byte{192, 0, 2, 9})
		meta.AddIP(preservation.MetaIPDestination, []byte{224, 0, 0, 9})
		meta.AddU16(preservation.MetaUDPSourcePort, 1111)
		meta.AddU16(preservation.MetaUDPDestPort, 2222)
		rec.AddRecord(preservation.RecordRawSignalling, preservation.RecordRawExact|preservation.RecordRequired,
			testNTPBase, meta, pa)
	})

	var out bytes.Buffer
	report, err := Run(bytes.NewReader(ts), &out)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.SignallingRecords != 1 {
		t.Fatalf("SignallingRecords = %d, want 1", report.SignallingRecords)
	}
	if len(report.Problems) > 0 {
		t.Fatalf("unexpected problems: %v", report.Problems)
	}

	if !bytes.Contains(out.Bytes(), pa) {
		t.Fatalf("replayed output does not contain the original PA message bytes")
	}
}

func TestRunOnEmptyInput(t *testing.T) {
	report, err := Run(bytes.NewReader(nil), &bytes.Buffer{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.TSPackets != 0 {
		t.Fatalf("TSPackets = %d, want 0", report.TSPackets)
	}
}

func TestRunAutoDetectsOrdinaryHEVCAACTS(t *testing.T) {
	var input bytes.Buffer
	w := mpegts.NewWriter(&input)
	if err := w.WriteSection(0, mpegts.BuildPAT(1, 0, []mpegts.Program{{Number: 401, PID: 0x1200}}, 0x10)); err != nil {
		t.Fatal(err)
	}
	pmt := mpegts.BuildPMT(401, 0, 0x1400, nil, []mpegts.ElementaryStream{
		{StreamType: mpegts.StreamTypeHEVC, PID: 0x1400, Descriptors: mpegts.StreamIdentifierDescriptor(0)},
		{StreamType: mpegts.StreamTypeADTSAAC, PID: 0x1404, Descriptors: mpegts.StreamIdentifierDescriptor(0x10)},
	})
	if err := w.WriteSection(0x1200, pmt); err != nil {
		t.Fatal(err)
	}
	hevc := []byte{0, 0, 0, 1, 0x46, 1, 0, 0, 0, 1, 0x26, 1, 0xaa, 0xbb}
	if err := w.WriteUnit(0x1400, generalTestPES(0xe0, 90000, hevc), mpegts.Adaptation{RandomAccess: true}); err != nil {
		t.Fatal(err)
	}
	rawAAC := []byte{0x21, 0x1a, 0x94, 0xa5}
	frameLen := 7 + len(rawAAC)
	adts := []byte{0xff, 0xf9, 0x4c, byte(frameLen >> 11), byte(frameLen >> 3), byte(frameLen<<5) | 0x1f, 0xfc}
	adts = append(adts, rawAAC...)
	if err := w.WriteUnit(0x1404, generalTestPES(0xc0, 90000, adts), mpegts.Adaptation{RandomAccess: true}); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	report, err := Run(&input, &output)
	if err != nil {
		t.Fatal(err)
	}
	if report.InputProfile != "ARIB STD-B10 MPEG-2 TS" {
		t.Fatalf("profile = %q", report.InputProfile)
	}
	if report.AVAccessUnits != 2 || len(report.Problems) != 0 {
		t.Fatalf("report = %+v", report)
	}
	if output.Len() == 0 {
		t.Fatal("ordinary TS conversion produced no MMTS")
	}
}

func TestGeneralPLTListsEveryPackage(t *testing.T) {
	services := []*generalService{
		{number: 0x0191, flow: generalFlowFor(0), mptPID: 0xff01},
		{number: 0x01f4, flow: generalFlowFor(1), mptPID: 0xff02},
	}
	message := buildGeneralPLT(services)
	body := message[12:]
	if body[0] != byte(len(services)) {
		t.Fatalf("num_of_package = %d, want %d", body[0], len(services))
	}
	if got := int(message[10])<<8 | int(message[11]); got != len(body) {
		t.Fatalf("table body length = %d, want %d", got, len(body))
	}
	if body[len(body)-1] != 0 {
		t.Errorf("PLT does not end with num_of_ip_delivery: %x", body)
	}
	p := 1
	for i, s := range services {
		idLen := int(body[p])
		if idLen != 2 || binary.BigEndian.Uint16(body[p+1:p+3]) != s.number {
			t.Fatalf("package %d id = %x", i, body[p:p+1+idLen])
		}
		p += 1 + idLen
		if body[p] != 0x02 {
			t.Fatalf("package %d location_type = %#02x, want an IPv6 data flow", i, body[p])
		}
		p++
		if string(body[p:p+16]) != string(pad16(s.flow.src)) || string(body[p+16:p+32]) != string(pad16(s.flow.dst)) {
			t.Errorf("package %d addresses = % x", i, body[p:p+32])
		}
		p += 32
		if binary.BigEndian.Uint16(body[p:p+2]) != s.flow.dstPort {
			t.Errorf("package %d dst_port = %d", i, binary.BigEndian.Uint16(body[p:p+2]))
		}
		if binary.BigEndian.Uint16(body[p+2:p+4]) != s.mptPID {
			t.Errorf("package %d MPT packet id = %#06x, want %#06x", i, binary.BigEndian.Uint16(body[p+2:p+4]), s.mptPID)
		}
		p += 4
	}
	if p != len(body)-1 {
		t.Errorf("walked %d of %d body bytes", p, len(body)-1)
	}
	if services[0].flow.cid == services[1].flow.cid ||
		string(services[0].flow.dst) == string(services[1].flow.dst) {
		t.Errorf("flows collide: %+v and %+v", services[0].flow, services[1].flow)
	}
}

func TestGeneralMHTOTMatchesNTPClock(t *testing.T) {
	section := buildGeneralMHTOT(generalNTPBase)
	got, _, err := si.ParseSection(section)
	if err != nil {
		t.Fatal(err)
	}
	tot, ok := si.ParseTOT(got)
	if !ok {
		t.Fatalf("MH-TOT did not parse: %x", section)
	}
	if got := tot.JSTTime[2:]; !bytes.Equal(got, []byte{0x09, 0x00, 0x00}) {
		t.Fatalf("JST time = %x, want 090000", got)
	}
}

func generalTestPES(streamID byte, pts int64, payload []byte) []byte {
	out := []byte{0, 0, 1, streamID, 0, 0, 0x80, 0x80, 5}
	v := uint64(pts) & ((1 << 33) - 1)
	out = append(out,
		byte(0x20|((v>>29)&0x0e)|1), byte(v>>22), byte(((v>>14)&0xfe)|1), byte(v>>7), byte((v<<1)|1))
	return append(out, payload...)
}

func TestRunConvertsEveryServiceOfAMultiplex(t *testing.T) {
	var input bytes.Buffer
	w := mpegts.NewWriter(&input)
	programs := []mpegts.Program{{Number: 401, PID: 0x1200}, {Number: 402, PID: 0x1201}}
	if err := w.WriteSection(0, mpegts.BuildPAT(1, 0, programs, 0x10)); err != nil {
		t.Fatal(err)
	}
	type service struct {
		number        uint16
		pmtPID        uint16
		videoPID      uint16
		audioPID      uint16
		announcedOnly bool
	}
	services := []service{
		{number: 401, pmtPID: 0x1200, videoPID: 0x1400, audioPID: 0x1404},
		{number: 402, pmtPID: 0x1201, videoPID: 0x1420, audioPID: 0x1424},
	}
	hevc := []byte{0, 0, 0, 1, 0x46, 1, 0, 0, 0, 1, 0x26, 1, 0xaa, 0xbb}
	rawAAC := []byte{0x21, 0x1a, 0x94, 0xa5}
	frameLen := 7 + len(rawAAC)
	adts := []byte{0xff, 0xf9, 0x4c, byte(frameLen >> 11), byte(frameLen >> 3), byte(frameLen<<5) | 0x1f, 0xfc}
	adts = append(adts, rawAAC...)

	for _, s := range services {
		pmt := mpegts.BuildPMT(s.number, 0, s.videoPID, nil, []mpegts.ElementaryStream{
			{StreamType: mpegts.StreamTypeHEVC, PID: s.videoPID, Descriptors: mpegts.StreamIdentifierDescriptor(0)},
			{StreamType: mpegts.StreamTypeADTSAAC, PID: s.audioPID, Descriptors: mpegts.StreamIdentifierDescriptor(0x10)},
		})
		if err := w.WriteSection(s.pmtPID, pmt); err != nil {
			t.Fatal(err)
		}
		if err := w.WriteUnit(s.videoPID, generalTestPES(0xe0, 90000, hevc), mpegts.Adaptation{RandomAccess: true}); err != nil {
			t.Fatal(err)
		}
		if err := w.WriteUnit(s.audioPID, generalTestPES(0xc0, 90000, adts), mpegts.Adaptation{RandomAccess: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	report, err := Run(&input, &output)
	if err != nil {
		t.Fatal(err)
	}
	if report.ServicesConverted != 2 || report.ServicesWithoutStreams != 0 {
		t.Fatalf("services converted %d, announced without streams %d",
			report.ServicesConverted, report.ServicesWithoutStreams)
	}
	if report.AVAccessUnits != 4 {
		t.Fatalf("access units = %d, want two per service", report.AVAccessUnits)
	}

	flows := map[string]bool{}
	contexts := map[uint16]bool{}
	r := tlv.NewReader(bytes.NewReader(output.Bytes()))
	for {
		p, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if p.Type == tlv.TypeCompressedIP && len(p.Payload) >= 2 {
			contexts[binary.BigEndian.Uint16(p.Payload[:2])>>4] = true
		}
		d, ok := r.Datagram(p)
		if !ok || d.IsNTP() {
			continue
		}
		flows[string(d.Dst)] = true
	}
	if len(contexts) != 2 {
		t.Errorf("context identifiers = %v, want one per service", contexts)
	}
	if len(flows) != 2 {
		t.Errorf("destination addresses = %d, want one per service", len(flows))
	}
}

func TestRunReplaysAcrossAClockGlitch(t *testing.T) {
	nal := []byte{0x26, 0x01, 0xaa, 0xbb, 0xcc}
	annexB := append([]byte{0, 0, 0, 1}, nal...)
	ts := buildCarouselTSWith(t, carouselTSOptions{
		streams: []mpegts.ElementaryStream{
			{StreamType: mpegts.StreamTypeHEVC, PID: 0x1011, Descriptors: mpegts.StreamIdentifierDescriptor(0)},
		},
		media: func(w *mpegts.Writer) {
			for _, pts := range []int64{90000, 180000} {
				if err := w.WriteUnit(0x1011, generalTestPES(0xe0, pts, annexB), mpegts.Adaptation{RandomAccess: true}); err != nil {
					t.Fatal(err)
				}
			}
		},
		fill: func(rec *preservation.Recorder) {
			rec.AddRecord(preservation.RecordRawSignalling, preservation.RecordRawExact|preservation.RecordRequired,
				testNTPBase, signallingMeta(0x0000), buildPAMessage())
			rec.AddAVMapEntry(preservation.AVMapEntry{PacketID: 0xf300, OutputPID: 0x1011, MPUSequence: 3,
				FirstAUOrdinal: 0, AUCount: 1, StartNTP: testNTPBase + (1 << 32), EndNTP: testNTPBase + (1 << 32)})
			rec.Observe(testNTPBase + (2 << 32))
			rec.Observe(testNTPBase + (3600 << 32)) // 壊れた NTP
			rec.Observe(testNTPBase + (2 << 32) + (1 << 31))
			rec.AddRecord(preservation.RecordRawSignalling, preservation.RecordRawExact|preservation.RecordRequired,
				testNTPBase+(3<<32), signallingMeta(0x0000), buildPAMessage())
			rec.AddAVMapEntry(preservation.AVMapEntry{PacketID: 0xf300, OutputPID: 0x1011, MPUSequence: 4,
				FirstAUOrdinal: 1, AUCount: 1, StartNTP: testNTPBase + (3 << 32), EndNTP: testNTPBase + (3 << 32)})
		},
		span: 5,
	})

	var out bytes.Buffer
	report, err := Run(bytes.NewReader(ts), &out)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Problems) > 0 {
		t.Fatalf("unexpected problems: %v", report.Problems)
	}
	if report.AVAccessUnits != 2 {
		t.Fatalf("AVAccessUnits = %d, want both sides of the glitch", report.AVAccessUnits)
	}
	if report.Epochs == 0 {
		t.Fatal("the report does not mention the epoch change")
	}
	if samples := readMPUSamples(t, out.Bytes()); len(samples) != 2 {
		t.Fatalf("%d samples written, want 2", len(samples))
	}
}
