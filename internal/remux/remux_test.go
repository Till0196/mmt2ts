// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"bytes"
	"encoding/binary"
	"testing"

	"mmt2ts/internal/caption"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/siconv"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/timeline"
	"mmt2ts/internal/tscheck"
)

func TestPMTAudioComponentUsesTSStreamContent(t *testing.T) {
	a := &signaling.AudioComponent{
		StreamContent: 3, ComponentType: 3, ComponentTag: 0x10,
		Language: "jpn",
	}
	d := audioComponentDescriptor(a, 0x10)
	if len(d) < 3 || d[0] != mpegts.DescAudioComponent || d[2]&0x0f != 2 {
		t.Fatalf("audio component descriptor = % x, want TS stream_content 2", d)
	}
}

func TestCaptionDescriptorDMFFollowsTheStandard(t *testing.T) {
	for _, tc := range []struct{ in, want byte }{
		{0x0a, 0x0a},
		{0x05, 0x05},
		{0x02, 0x03},
		{0x08, 0x03},
		{0x00, 0x03},
		{0x0f, 0x0f},
	} {
		if got := descriptorDMF(tc.in); got != tc.want {
			t.Errorf("descriptorDMF(%#02x) = %#02x, want %#02x", tc.in, got, tc.want)
		}
	}
	info := &caption.AdditionalInfo{DMF: 0x02, Type: caption.TypeClosedCaption}
	if got := captionAdditionalInfo(info); got != 0x31 {
		t.Errorf("additional_arib_caption_info = %#02x, want 0x31", got)
	}
	sup := &caption.AdditionalInfo{DMF: 0x0a, Type: caption.TypeSuperimposition}
	if got := captionAdditionalInfo(sup); got != 0xa0 {
		t.Errorf("superimposition info = %#02x, want 0xa0 (asynchronous)", got)
	}
}

const (
	testVideoPID  = 0xf100
	testAudioPID  = 0xf110
	testMPTPID    = 0xff01
	testService   = 0x0066
	testTimescale = 180000
	testVideoTick = 3003
	testAudioTick = 3840
	testNTPBase   = uint64(0xebd83880) << 32
)

type builder struct {
	buf  bytes.Buffer
	seqs map[uint16]uint32
}

func newBuilder() *builder { return &builder{seqs: make(map[uint16]uint32)} }

func (b *builder) tlv(payload []byte) {
	b.buf.Write([]byte{0x7f, 0x03})
	binary.Write(&b.buf, binary.BigEndian, uint16(len(payload)+3))
	b.buf.Write([]byte{0x00, 0x00, 0x61})
	b.buf.Write(payload)
}

func (b *builder) control(payload []byte) {
	b.buf.Write([]byte{0x7f, 0xfe})
	binary.Write(&b.buf, binary.BigEndian, uint16(len(payload)))
	b.buf.Write(payload)
}

func actualNIT(networkID uint16) []byte {
	section := []byte{0x40, 0, 0}
	section = binary.BigEndian.AppendUint16(section, networkID)
	section = append(section, 0xc1, 0, 0)
	section = append(section, 0xf0, 0x00)
	stream := binary.BigEndian.AppendUint16(nil, 0x0004)
	stream = binary.BigEndian.AppendUint16(stream, 0x0004)
	stream = binary.BigEndian.AppendUint16(stream, 0xf000)
	section = binary.BigEndian.AppendUint16(section, 0xf000|uint16(len(stream)))
	section = append(section, stream...)
	binary.BigEndian.PutUint16(section[1:3], 0xf000|uint16(len(section)-3+4))
	return binary.BigEndian.AppendUint32(section, mpegts.CRC32(section))
}

func (b *builder) mmtp(pid uint16, payloadType byte, rap bool, payload []byte, skip uint32) {
	seq := b.seqs[pid] + skip
	b.seqs[pid] = seq + 1
	head := make([]byte, 12)
	head[0] = 0x00
	if rap {
		head[0] |= 0x01
	}
	head[1] = payloadType
	binary.BigEndian.PutUint16(head[2:4], pid)
	binary.BigEndian.PutUint32(head[4:8], 0)
	binary.BigEndian.PutUint32(head[8:12], seq)
	b.tlv(append(head, payload...))
}

func mpuPayload(mpuSeq uint32, data []byte) []byte {
	out := make([]byte, 0, 22+len(data))
	out = append(out, 0, 0)
	out = append(out, 0x28)
	out = append(out, 0)
	out = binary.BigEndian.AppendUint32(out, mpuSeq)
	out = append(out, make([]byte, 14)...)
	out = append(out, data...)
	binary.BigEndian.PutUint16(out[:2], uint16(len(out)-2))
	return out
}

func nal(nalType byte, size int) []byte {
	body := make([]byte, size)
	body[0] = nalType << 1
	body[1] = 0x01
	for i := 2; i < size; i++ {
		body[i] = byte(i)
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(size)), body...)
}

func audioFrame(size int) []byte {
	var bits []byte
	put := func(v uint32, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, byte(v>>i)&1)
		}
	}
	put(0, 1)
	put(0, 1)
	put(1, 1)
	put(0, 6)
	put(0, 4)
	put(0, 3)
	put(2, 5)
	put(3, 4)
	put(2, 4)
	put(0, 3)
	put(0, 3)
	put(0xff, 8)
	put(0, 1)
	put(1, 1)
	put(0, 8)
	put(uint32(size), 8)
	for i := range size {
		put(uint32(byte(i)), 8)
	}
	out := make([]byte, (len(bits)+7)/8)
	for i, bit := range bits {
		out[i/8] |= bit << (7 - (i & 7))
	}
	return out
}

func signalingPayload(table []byte) []byte {
	message := make([]byte, 0, len(table)+16)
	message = binary.BigEndian.AppendUint16(message, 0)
	message = append(message, 0)
	body := append([]byte{0}, table...)
	message = binary.BigEndian.AppendUint32(message, uint32(len(body)))
	message = append(message, body...)
	return append([]byte{0x00, 0x00}, message...)
}

func table(id, version byte, body []byte) []byte {
	out := []byte{id, version, 0, 0}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)))
	return append(out, body...)
}

func pltTable(version byte) []byte {
	return pltTableFor(version, []testPackage{{service: testService, mptPID: testMPTPID}})
}

func pltTableFor(version byte, packages []testPackage) []byte {
	body := []byte{byte(len(packages))}
	for _, p := range packages {
		body = append(body, 2)
		body = binary.BigEndian.AppendUint16(body, p.service)
		body = append(body, 0x00)
		body = binary.BigEndian.AppendUint16(body, p.mptPID)
	}
	return table(0x80, version, body)
}

type testAsset struct {
	assetType   string
	packetID    uint16
	tag         uint16
	descriptors []byte
}

func mptTable(version byte, assets []testAsset) []byte {
	return mptTableFor(version, testService, assets)
}

func mptTableFor(version byte, service uint16, assets []testAsset) []byte {
	body := []byte{0x00, 2}
	body = binary.BigEndian.AppendUint16(body, service)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = append(body, byte(len(assets)))
	for _, a := range assets {
		body = append(body, 0x00)
		body = binary.BigEndian.AppendUint32(body, 0x00000000)
		body = append(body, 2)
		body = binary.BigEndian.AppendUint16(body, a.packetID)
		body = append(body, a.assetType...)
		body = append(body, 0x00)
		body = append(body, 1)
		body = append(body, 0x00)
		body = binary.BigEndian.AppendUint16(body, a.packetID)
		desc := append(descriptor(0x8011, binary.BigEndian.AppendUint16(nil, a.tag)), a.descriptors...)
		body = binary.BigEndian.AppendUint16(body, uint16(len(desc)))
		body = append(body, desc...)
	}
	return table(0x20, version, body)
}

func descriptor(tag uint16, data []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, tag)
	out = append(out, byte(len(data)))
	return append(out, data...)
}

func mpuTimestampDescriptor(entries map[uint32]uint64, order []uint32) []byte {
	var data []byte
	for _, seq := range order {
		data = binary.BigEndian.AppendUint32(data, seq)
		data = binary.BigEndian.AppendUint64(data, entries[seq])
	}
	return descriptor(0x0001, data)
}

func extendedTimestampDescriptor(order []uint32, auCount int, interval uint16, dtsOffsets []uint16) []byte {
	data := []byte{0x03}
	data = binary.BigEndian.AppendUint32(data, testTimescale)
	data = binary.BigEndian.AppendUint16(data, interval)
	for _, seq := range order {
		data = binary.BigEndian.AppendUint32(data, seq)
		data = append(data, 0)
		decoding := uint16(0)
		if len(dtsOffsets) > 0 {
			decoding = dtsOffsets[0]
		}
		data = binary.BigEndian.AppendUint16(data, decoding)
		data = append(data, byte(auCount))
		for i := range auCount {
			offset := uint16(0)
			if len(dtsOffsets) > 0 {
				offset = dtsOffsets[i%len(dtsOffsets)]
			}
			data = binary.BigEndian.AppendUint16(data, offset)
		}
	}
	return descriptor(0x8026, data)
}

func audioComponent(tag uint16) []byte { return audioComponentMode(tag, 0x03) }

func audioComponentMode(tag uint16, componentType byte) []byte {
	d := []byte{0x02, componentType}
	d = binary.BigEndian.AppendUint16(d, tag)
	d = append(d, 0x11, 0xff, 0x00)
	d = append(d, "jpn"...)
	return descriptor(0x8014, d)
}

type testPackage struct {
	service            uint16
	mptPID             uint16
	videoPID, audioPID uint16
}

var testPackages = [2]testPackage{
	{service: testService, mptPID: testMPTPID, videoPID: testVideoPID, audioPID: testAudioPID},
	{service: testService + 1, mptPID: testMPTPID + 1, videoPID: testVideoPID + 1, audioPID: testAudioPID + 1},
}

func buildStream(mpuCount int, videoAUs, audioAUs int, lossAtVideoMPU int) []byte {
	b := newBuilder()
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTable(1)), 0)
	b.mediaPackage(testPackages[0], mpuCount, videoAUs, audioAUs, lossAtVideoMPU)
	return b.buf.Bytes()
}

func buildMultiPackageStream(mpuCount, videoAUs, audioAUs int) []byte {
	b := newBuilder()
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTableFor(1, testPackages[:])), 0)
	for _, p := range testPackages {
		b.mediaPackage(p, mpuCount, videoAUs, audioAUs, -1)
	}
	return b.buf.Bytes()
}

func (b *builder) mediaPackage(p testPackage, mpuCount, videoAUs, audioAUs, lossAtVideoMPU int) {
	videoSeqs := make([]uint32, mpuCount)
	audioSeqs := make([]uint32, mpuCount)
	videoTimes := make(map[uint32]uint64, mpuCount)
	audioTimes := make(map[uint32]uint64, mpuCount)
	for i := range mpuCount {
		videoSeqs[i] = uint32(100 + i)
		audioSeqs[i] = uint32(200 + i)
		videoTimes[videoSeqs[i]] = testNTPBase + uint64(i)*uint64(videoAUs)*testVideoTick<<32/testTimescale
		audioTimes[audioSeqs[i]] = testNTPBase + uint64(i)*uint64(audioAUs)*testAudioTick<<32/testTimescale
	}
	assets := []testAsset{
		{
			assetType: "hev1", packetID: p.videoPID, tag: 0x0000,
			descriptors: append(
				mpuTimestampDescriptor(videoTimes, videoSeqs),
				extendedTimestampDescriptor(videoSeqs, videoAUs, testVideoTick, []uint16{0})...),
		},
		{
			assetType: "mp4a", packetID: p.audioPID, tag: 0x0010,
			descriptors: append(append(
				mpuTimestampDescriptor(audioTimes, audioSeqs),
				extendedTimestampDescriptor(audioSeqs, audioAUs, testAudioTick, []uint16{0})...),
				audioComponent(0x0010)...),
		},
	}
	b.mmtp(p.mptPID, 0x02, false, signalingPayload(mptTableFor(1, p.service, assets)), 0)

	for i := range mpuCount {
		for au := range videoAUs {
			skip := uint32(0)
			if i == lossAtVideoMPU && au == 1 {
				skip = 1
			}
			b.mmtp(p.videoPID, 0x00, au == 0, mpuPayload(videoSeqs[i], nal(35, 3)), skip)
			if au == 0 {
				for _, t := range []byte{32, 33, 34} {
					b.mmtp(p.videoPID, 0x00, false, mpuPayload(videoSeqs[i], nal(t, 16)), 0)
				}
			}
			b.mmtp(p.videoPID, 0x00, false, mpuPayload(videoSeqs[i], nal(irapOrTrail(au), 64)), 0)
		}
		for au := range audioAUs {
			b.mmtp(p.audioPID, 0x00, au == 0, mpuPayload(audioSeqs[i], audioFrame(64)), 0)
		}
	}
}

func buildJunctionStream(mpuCount, audioAUs int) []byte {
	b := newBuilder()
	seqs := make([]uint32, mpuCount)
	times := make(map[uint32]uint64, mpuCount)
	for i := range mpuCount {
		seqs[i] = uint32(200 + i)
		times[seqs[i]] = testNTPBase + uint64(i)*uint64(audioAUs)*testAudioTick<<32/testTimescale
	}
	asset := func(componentType byte) []testAsset {
		return []testAsset{{
			assetType: "mp4a", packetID: testAudioPID, tag: 0x0010,
			descriptors: append(append(
				mpuTimestampDescriptor(times, seqs),
				extendedTimestampDescriptor(seqs, audioAUs, testAudioTick, []uint16{0})...),
				audioComponentMode(0x0010, componentType)...),
		}}
	}
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTable(1)), 0)
	b.mmtp(testMPTPID, 0x02, false, signalingPayload(mptTable(1, asset(0x03))), 0)
	for i := range mpuCount {
		if i == 2 {
			b.mmtp(testMPTPID, 0x02, false, signalingPayload(mptTable(2, asset(0x11))), 0)
		}
		for au := range audioAUs {
			b.mmtp(testAudioPID, 0x00, au == 0, mpuPayload(seqs[i], audioFrame(64)), 0)
		}
	}
	return b.buf.Bytes()
}

func TestAudioFramingMatchesTheDeclaredStreamType(t *testing.T) {
	_, check, out := convert(t, buildJunctionStream(4, 5))
	if check.Errors() != 0 {
		tscheck.WriteReport(testWriter{t}, check)
		t.Fatalf("independent check found %d problems", check.Errors())
	}
	audio := check.PIDs[0x1100]
	if audio == nil {
		t.Fatalf("the audio stream is missing: %v", check.PIDs)
	}
	if audio.StreamType != mpegts.StreamTypeLATMAAC {
		t.Fatalf("stream type = %#02x, want LATM after the junction", audio.StreamType)
	}
	adts, loas, other := countAudioFraming(out, 0x1100)
	if adts != 0 || other != 0 {
		t.Fatalf("framing in a LATM stream: %d ADTS, %d LOAS, %d unrecognised", adts, loas, other)
	}
	if loas == 0 {
		t.Fatal("no audio was written at all")
	}
}

func countAudioFraming(ts []byte, pid uint16) (adts, loas, other int) {
	for i := 0; i+188 <= len(ts); i += 188 {
		p := ts[i : i+188]
		if uint16(p[1]&0x1f)<<8|uint16(p[2]) != pid || p[1]&0x40 == 0 {
			continue
		}
		off := 4
		if p[3]&0x20 != 0 {
			off += 1 + int(p[4])
		}
		if p[3]&0x10 == 0 || off+9 > len(p) {
			continue
		}
		d := p[off:]
		if !bytes.HasPrefix(d, []byte{0x00, 0x00, 0x01}) {
			continue
		}
		body := d[9+int(d[8]):]
		switch {
		case len(body) < 2:
		case body[0] == 0xff && body[1]&0xf0 == 0xf0:
			adts++
		case body[0] == 0x56 && body[1]&0xe0 == 0xe0:
			loas++
		default:
			other++
		}
	}
	return adts, loas, other
}

func irapOrTrail(au int) byte {
	if au == 0 {
		return 19
	}
	return 1
}

func convert(t *testing.T, input []byte) (Report, tscheck.Report, []byte) {
	t.Helper()
	var out bytes.Buffer
	opts := DefaultOptions()
	opts.ServiceID = 1
	report, err := Run(bytes.NewReader(input), &out, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	check, err := tscheck.Scan(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("tscheck: %v", err)
	}
	return report, check, out.Bytes()
}

func TestConvertSyntheticStream(t *testing.T) {
	report, check, out := convert(t, buildStream(4, 3, 5, -1))
	if len(out)%188 != 0 || len(out) == 0 {
		t.Fatalf("output is %d bytes", len(out))
	}
	if check.Errors() != 0 {
		tscheck.WriteReport(testWriter{t}, check)
		t.Fatalf("independent check found %d problems", check.Errors())
	}
	if got := check.Programs[1]; got != 0x0100 {
		t.Fatalf("PMT PID = %#04x", got)
	}
	if check.PCRPID != 0x1011 {
		t.Fatalf("PCR PID = %#04x", check.PCRPID)
	}
	video := check.PIDs[0x1011]
	audio := check.PIDs[0x1100]
	if video == nil || audio == nil {
		t.Fatalf("missing elementary streams: %v", check.PIDs)
	}
	if video.StreamType != mpegts.StreamTypeHEVC || audio.StreamType != mpegts.StreamTypeADTSAAC {
		t.Fatalf("stream types = %#02x / %#02x", video.StreamType, audio.StreamType)
	}
	if audio.ComponentTag != 0x10 || video.ComponentTag != 0x00 {
		t.Fatalf("component tags = %#02x / %#02x", video.ComponentTag, audio.ComponentTag)
	}
	if video.PESUnits != 8 {
		t.Fatalf("video access units = %d, want 8", video.PESUnits)
	}
	if audio.PESUnits != 14 {
		t.Fatalf("audio access units = %d, want 14", audio.PESUnits)
	}
	videoT1 := testNTPBase + uint64(1)*uint64(3)*testVideoTick<<32/testTimescale
	audioT1 := testNTPBase + uint64(1)*uint64(5)*testAudioTick<<32/testTimescale
	if want, got := timeline.NTPTo90k(videoT1, audioT1), check.AVSkew[0x1100]; got != want {
		t.Fatalf("A/V skew = %d ticks, want %d", got, want)
	}
	if step := (video.LastPTS - video.FirstPTS) / 7; step < 1501 || step > 1502 {
		t.Fatalf("video PTS step = %d", step)
	}
	if step := (audio.LastPTS - audio.FirstPTS) / 13; step != testAudioTick/2 {
		t.Fatalf("audio PTS step = %d, want %d", step, testAudioTick/2)
	}
	for _, s := range report.Streams {
		if s.MPUsAUDiffer != 0 || s.MPUsAUMatch != 3 {
			t.Fatalf("PID %04x MPU check: matched %d, differed %d", s.PID, s.MPUsAUMatch, s.MPUsAUDiffer)
		}
	}
}

func TestMultipleVideoAssetsKeepIndependentPIDs(t *testing.T) {
	b := newBuilder()
	const secondVideoPID = 0xf101
	seqA := []uint32{100, 101, 102}
	seqB := []uint32{300, 301, 302}
	timesA := map[uint32]uint64{}
	timesB := map[uint32]uint64{}
	for i := range seqA {
		t := testNTPBase + uint64(i)*2*testVideoTick<<32/testTimescale
		timesA[seqA[i]], timesB[seqB[i]] = t, t
	}
	videoAsset := func(pid, tag uint16, seqs []uint32, times map[uint32]uint64) testAsset {
		return testAsset{assetType: "hev1", packetID: pid, tag: tag, descriptors: append(
			mpuTimestampDescriptor(times, seqs),
			extendedTimestampDescriptor(seqs, 2, testVideoTick, []uint16{0})...)}
	}
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTable(1)), 0)
	b.mmtp(testMPTPID, 0x02, false, signalingPayload(mptTable(1, []testAsset{
		videoAsset(testVideoPID, 0x0000, seqA, timesA),
		videoAsset(secondVideoPID, 0x0001, seqB, timesB),
	})), 0)
	writeVideo := func(pid uint16, seq uint32) {
		b.mmtp(pid, 0x00, true, mpuPayload(seq, nal(35, 3)), 0)
		for _, typ := range []byte{32, 33, 34} {
			b.mmtp(pid, 0x00, false, mpuPayload(seq, nal(typ, 16)), 0)
		}
		b.mmtp(pid, 0x00, false, mpuPayload(seq, nal(19, 64)), 0)
		b.mmtp(pid, 0x00, false, mpuPayload(seq, nal(35, 3)), 0)
		b.mmtp(pid, 0x00, false, mpuPayload(seq, nal(1, 64)), 0)
	}
	for i := range seqA {
		writeVideo(testVideoPID, seqA[i])
		writeVideo(secondVideoPID, seqB[i])
	}
	_, check, _ := convert(t, b.buf.Bytes())
	for pid, tag := range map[uint16]byte{0x1011: 0x00, 0x1012: 0x01} {
		s := check.PIDs[pid]
		if s == nil || s.StreamType != mpegts.StreamTypeHEVC || s.ComponentTag != tag || s.PESUnits == 0 {
			t.Fatalf("video PID %#04x = %+v", pid, s)
		}
	}
}

func TestLossDropsRestOfMPUAndWaitsForIRAP(t *testing.T) {
	report, check, _ := convert(t, buildStream(4, 3, 5, 2))
	var carried, ccErrors uint64
	for _, s := range report.Streams {
		carried += s.LostPacketsCarried
	}
	for _, p := range check.PIDs {
		ccErrors += p.CCErrors
	}
	if carried == 0 {
		t.Fatal("the input loss was not carried into the transport stream")
	}
	if ccErrors != carried {
		t.Fatalf("continuity errors %d, want the %d carried packets", ccErrors, carried)
	}
	if check.Errors() != ccErrors {
		t.Fatalf("independent check found %d problems, want only the %d carried packets", check.Errors(), ccErrors)
	}
	video := check.PIDs[0x1011]
	if video.PESUnits != 5 {
		t.Fatalf("video access units = %d, want 5", video.PESUnits)
	}
	if video.Discontinuity == 0 {
		t.Fatal("no discontinuity was signalled after the loss")
	}
	if report.MPU.SequenceGaps != 1 {
		t.Fatalf("sequence gaps = %d, want 1", report.MPU.SequenceGaps)
	}
	audio := check.PIDs[0x1100]
	if audio.PESUnits != 14 {
		t.Fatalf("audio access units = %d, want 14", audio.PESUnits)
	}
}

func TestTimescaleConversionIsExactAndIntegral(t *testing.T) {
	if got := timeline.NTPTo90k(0, 1<<32); got != 90000 {
		t.Fatalf("one second = %d ticks", got)
	}
	if got := timeline.NTPTo90k(1<<32, 0); got != -90000 {
		t.Fatalf("minus one second = %d ticks", got)
	}
	if got := timeline.TicksTo90k(3003, 180000); got != 1502 {
		t.Fatalf("3003/180000 = %d ticks", got)
	}
	if got := timeline.TicksTo90k(-3003, 180000); got != -1502 {
		t.Fatalf("-3003/180000 = %d ticks", got)
	}
	if got := timeline.TicksTo90k(3840, 180000); got != 1920 {
		t.Fatalf("3840/180000 = %d ticks", got)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func (b *builder) m2Section(packetID uint16, messageID uint16, section []byte) {
	message := binary.BigEndian.AppendUint16(nil, messageID)
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, uint16(len(section)))
	message = append(message, section...)
	b.mmtp(packetID, 0x02, false, append([]byte{0x00, 0x00}, message...), 0)
}

func siSection(tableID byte, extension uint16, version, number, last byte, body []byte) []byte {
	s := []byte{tableID, 0, 0}
	s = binary.BigEndian.AppendUint16(s, extension)
	s = append(s, 0xc1|version<<1&0x3e, number, last)
	s = append(s, body...)
	binary.BigEndian.PutUint16(s[1:3], 0xf000|uint16(len(s)-3+4))
	return binary.BigEndian.AppendUint32(s, mpegts.CRC32(s))
}

func eventSection(serviceID uint16, name, text string) []byte {
	short := append([]byte("jpn"), byte(len(name)))
	short = append(short, name...)
	short = binary.BigEndian.AppendUint16(short, uint16(len(text)))
	short = append(short, text...)
	desc := binary.BigEndian.AppendUint16(nil, 0xf001)
	desc = binary.BigEndian.AppendUint16(desc, uint16(len(short)))
	desc = append(desc, short...)

	event := binary.BigEndian.AppendUint16(nil, 0x4321)
	event = append(event, 0xe1, 0x23, 0x45, 0x67, 0x89)
	event = append(event, 0x01, 0x30, 0x00)
	event = binary.BigEndian.AppendUint16(event, 0x8000|uint16(len(desc)))
	event = append(event, desc...)

	body := binary.BigEndian.AppendUint16(nil, 0x0004)
	body = binary.BigEndian.AppendUint16(body, 0x0004)
	body = append(body, 0x00, 0x8b)
	return siSection(0x8b, serviceID, 1, 0, 0, append(body, event...))
}

func serviceSection(serviceID uint16, provider, name string) []byte {
	svc := []byte{0x01, byte(len(provider))}
	svc = append(svc, provider...)
	svc = append(svc, byte(len(name)))
	svc = append(svc, name...)
	desc := binary.BigEndian.AppendUint16(nil, 0x8019)
	desc = append(desc, byte(len(svc)))
	desc = append(desc, svc...)

	body := binary.BigEndian.AppendUint16(nil, 0x0004)
	body = append(body, 0xff)
	entry := binary.BigEndian.AppendUint16(nil, serviceID)
	entry = append(entry, 0xfd)
	entry = binary.BigEndian.AppendUint16(entry, 0x8000|uint16(len(desc)))
	entry = append(entry, desc...)
	return siSection(0x9f, 0x0004, 1, 0, 0, append(body, entry...))
}

func totSection() []byte {
	s := []byte{0xa1, 0, 0, 0xe1, 0x23, 0x45, 0x67, 0x89, 0xf0, 0x00}
	binary.BigEndian.PutUint16(s[1:3], 0x7000|uint16(len(s)-3+4))
	return binary.BigEndian.AppendUint32(s, mpegts.CRC32(s))
}

func withSI(media []byte) []byte {
	b := newBuilder()
	b.control(actualNIT(0x0004))
	b.m2Section(0x8000, 0x8000, eventSection(testService, "テスト番組", "解説"))
	b.m2Section(0x8004, 0x8000, serviceSection(testService, "放送", "テスト"))
	b.m2Section(0x8005, 0x8002, totSection())
	b.buf.Write(media)
	return b.buf.Bytes()
}

func TestFullProfileGeneratesSIFromMMTSI(t *testing.T) {
	var out bytes.Buffer
	opts := DefaultOptions()
	opts.ServiceID = testService
	report, err := Run(bytes.NewReader(withSI(buildStream(4, 3, 5, -1))), &out, opts)
	if err != nil {
		t.Fatal(err)
	}
	check, err := tscheck.Scan(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if check.Errors() != 0 {
		t.Fatalf("independent check found %d problems: %v", check.Errors(), check.ProfileErrors())
	}
	for _, want := range []struct {
		id   byte
		name string
	}{{0x40, "NIT"}, {0x42, "SDT"}, {0x4e, "EIT p/f"}, {0x73, "TOT"}} {
		if check.Tables[want.id] == 0 {
			t.Errorf("no %s section was written", want.name)
		}
	}
	if check.Tables[0x7f] != 0 || check.Tables[0x7e] != 0 {
		t.Error("a full transport stream must not carry SIT or DIT")
	}
	if check.NetworkPID != mpegts.PIDNIT {
		t.Errorf("PAT network PID = %#04x, want %#04x", check.NetworkPID, mpegts.PIDNIT)
	}
	if report.SIText.Strings == 0 || report.SIText.Scalars == 0 {
		t.Fatalf("no SI text was encoded: %+v", report.SIText)
	}
	if report.SIText.Unconvertible != 0 {
		t.Errorf("unconvertible characters: %q", string(report.SIText.Samples))
	}
	if n := report.SIDescriptors[siconv.TagKey{Tag: 0xf001}]; n == nil || n.Converted == 0 {
		t.Errorf("short event descriptor was not converted: %+v", report.SIDescriptors)
	}
}

const testCaptionPID = 0xf130

func (b *builder) ntp(clock uint64) {
	pkt := make([]byte, 48)
	binary.BigEndian.PutUint64(pkt[40:48], clock)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[2:4], 123)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)+len(pkt)))
	udp = append(udp, pkt...)
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(udp)))
	ip[6] = 17
	ip[7] = 64
	packet := append(ip, udp...)
	b.buf.Write([]byte{0x7f, 0x02})
	binary.Write(&b.buf, binary.BigEndian, uint16(len(packet)))
	b.buf.Write(packet)
}

func captionAssetNoTimestamps() testAsset {
	a := captionAsset(nil, nil)
	a.descriptors = descriptor(0x8020, captionDataComponentBody())
	return a
}

func captionDataComponentBody() []byte {
	info := []byte{0x30, 0x00}
	info = append(info, "jpn"...)
	info = append(info, 0x00, 0xfa, 0x10)
	return append(binary.BigEndian.AppendUint16(nil, 0x0020), info...)
}

func captionAsset(times map[uint32]uint64, order []uint32) testAsset {
	info := []byte{0x30, 0x00}
	info = append(info, "jpn"...)
	info = append(info, 0x00, 0x33, 0x10)
	body := binary.BigEndian.AppendUint16(nil, 0x0020)
	body = append(body, info...)
	return testAsset{
		assetType: "stpp", packetID: testCaptionPID, tag: 0x0030,
		descriptors: append(mpuTimestampDescriptor(times, order), descriptor(0x8020, body)...),
	}
}

func captionMFU(number, last byte, dataType byte, data []byte) []byte {
	b := []byte{0x30, 0x01, number, last, dataType << 4}
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

const testTTML = `<tt xmlns="http://www.w3.org/ns/ttml" xmlns:tts="http://www.w3.org/ns/ttml#styling">` +
	`<head><layout><region xml:id="r" tts:origin="480px 1620px" tts:extent="2880px 360px"/></layout></head>` +
	`<body><div begin="00:00:00.000" end="00:00:02.000"><p region="r">字幕テスト</p></div></body></tt>`

func buildCaptionStream() []byte {
	media := buildStream(2, 3, 5, -1)
	b := newBuilder()
	seqs := []uint32{300, 301}
	times := map[uint32]uint64{
		seqs[0]: testNTPBase,
		seqs[1]: testNTPBase + 1<<32,
	}
	assets := []testAsset{captionAsset(times, seqs)}
	b.mmtp(testMPTPID, 0x02, false, signalingPayload(mptTable(2, append(defaultAssets(), assets...))), 0)
	for _, seq := range seqs {
		b.mmtp(testCaptionPID, 0x00, true, mpuPayload(seq, captionMFU(0, 1, 0, []byte(testTTML))), 0)
		b.mmtp(testCaptionPID, 0x00, false, mpuPayload(seq, captionMFU(1, 1, 1, []byte{0x89, 'P', 'N', 'G'})), 0)
	}
	return append(media, b.buf.Bytes()...)
}

func defaultAssets() []testAsset {
	return []testAsset{
		{assetType: "hev1", packetID: testVideoPID, tag: 0x0000},
		{assetType: "mp4a", packetID: testAudioPID, tag: 0x0010, descriptors: audioComponent(0x0010)},
	}
}

func TestCaptionWithoutTimestampsUsesTheClockOfItsOwnArrival(t *testing.T) {
	b := newBuilder()
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTable(1)), 0)
	b.mmtp(testMPTPID, 0x02, false, signalingPayload(mptTable(1,
		append(defaultAssets(), captionAssetNoTimestamps()))), 0)

	second := func(n uint64) uint64 { return testNTPBase + n<<32 }
	arrivals := []uint64{second(0), second(1), second(5), second(6)}
	for i, seq := range []uint32{300, 301, 302, 303} {
		b.ntp(arrivals[i])
		b.mmtp(testCaptionPID, 0x00, true,
			mpuPayload(seq, captionMFU(0, 0, 0, []byte(testTTML))), 0)
	}

	var out bytes.Buffer
	opts := DefaultOptions()
	opts.ServiceID = testService
	report, err := Run(bytes.NewReader(b.buf.Bytes()), &out, opts)
	if err != nil {
		t.Fatal(err)
	}
	var caption *StreamStat
	for i := range report.Streams {
		if report.Streams[i].AssetType == "stpp" {
			caption = &report.Streams[i]
		}
	}
	if caption == nil {
		t.Fatal("the caption stream is missing from the report")
	}
	if caption.MPUsSenderClock == 0 {
		t.Fatal("the asset had no MPU timestamps, so the sender clock must be reported")
	}
	times := captionPTS(out.Bytes(), 0x1200)
	if len(times) != 4 {
		t.Fatalf("caption statements = %v, want four", times)
	}
	gaps := []int64{times[1] - times[0], times[2] - times[1], times[3] - times[2]}
	want := []int64{1 * 90000, 4 * 90000, 1 * 90000}
	for i := range want {
		if gaps[i] != want[i] {
			t.Fatalf("gaps between caption statements = %v (from %v), want %v", gaps, times, want)
		}
	}
	if times[0] != int64(opts.Preroll) {
		t.Fatalf("first caption PTS = %d, want the preroll %d", times[0], opts.Preroll)
	}
}

func captionPTS(ts []byte, pid uint16) []int64 {
	var out []int64
	for i := 0; i+188 <= len(ts); i += 188 {
		p := ts[i : i+188]
		if uint16(p[1]&0x1f)<<8|uint16(p[2]) != pid || p[1]&0x40 == 0 {
			continue
		}
		off := 4
		if p[3]&0x20 != 0 {
			off += 1 + int(p[4])
		}
		if p[3]&0x10 == 0 || off+14 > len(p) {
			continue
		}
		d := p[off:]
		if !bytes.HasPrefix(d, []byte{0x00, 0x00, 0x01}) || d[7]&0x80 == 0 {
			continue
		}
		pts := int64(d[9]>>1&7)<<30 | int64(d[10])<<22 |
			int64(d[11]>>1)<<15 | int64(d[12])<<7 | int64(d[13])>>1
		body := d[9+int(d[8]):]
		if len(body) > 3 && body[3]>>2 == 0x01 {
			out = append(out, pts)
		}
	}
	return out
}

func TestCaptionAssetBecomesItsOwnPES(t *testing.T) {
	var out bytes.Buffer
	opts := DefaultOptions()
	opts.ServiceID = testService
	report, err := Run(bytes.NewReader(buildCaptionStream()), &out, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Captions) != 1 {
		t.Fatalf("caption assets = %d", len(report.Captions))
	}
	c := report.Captions[0]
	if c.Language != "jpn" || c.Superimposition {
		t.Fatalf("caption = %+v", c)
	}
	if c.Stats.Documents == 0 || c.Stats.Statements == 0 {
		t.Fatalf("nothing was converted: %+v", c.Stats)
	}
	if c.Stats.Resources["PNG"] == 0 {
		t.Fatalf("the external resource was not reported: %+v", c.Stats.Resources)
	}
	check, err := tscheck.Scan(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := check.PIDs[c.PID]
	if !ok {
		t.Fatalf("no packets on the caption PID %#04x", c.PID)
	}
	if stat.StreamType != mpegts.StreamTypePES {
		t.Fatalf("stream type = %#02x, want %#02x", stat.StreamType, mpegts.StreamTypePES)
	}
	if stat.PESUnits == 0 {
		t.Fatal("no caption PES packets were written")
	}
}

func TestMultiPackageStreamBecomesMultiProgramTS(t *testing.T) {
	var out bytes.Buffer
	opts := DefaultOptions()
	report, err := Run(bytes.NewReader(buildMultiPackageStream(4, 3, 5)), &out, opts)
	if err != nil {
		t.Fatal(err)
	}
	check, err := tscheck.Scan(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if check.Errors() != 0 {
		tscheck.WriteReport(testWriter{t}, check)
		t.Fatalf("independent check found %d problems: %v", check.Errors(), check.ProfileErrors())
	}

	if len(report.Programs) != 2 {
		t.Fatalf("got %d program(s), want one per MMT package: %+v", report.Programs, report.Programs)
	}
	if len(check.Programs) != 2 {
		t.Fatalf("the PAT announces %v, want both services", check.Programs)
	}
	for _, p := range report.Programs {
		pmtPID, ok := check.Programs[p.ServiceID]
		if !ok {
			t.Errorf("service %#04x is not in the PAT: %v", p.ServiceID, check.Programs)
			continue
		}
		if pmtPID != p.PMTPID {
			t.Errorf("service %#04x is on PMT PID %#04x, the converter reported %#04x", p.ServiceID, pmtPID, p.PMTPID)
		}
		if p.Streams != 2 {
			t.Errorf("service %#04x has %d elementary stream(s), want video and audio", p.ServiceID, p.Streams)
		}
	}

	seen := make(map[uint16]uint16)
	byService := make(map[uint16][]StreamStat)
	for _, s := range report.Streams {
		if other, ok := seen[s.PID]; ok {
			t.Errorf("PID %#04x carries components of both service %#04x and %#04x", s.PID, other, s.ServiceID)
		}
		seen[s.PID] = s.ServiceID
		byService[s.ServiceID] = append(byService[s.ServiceID], s)
	}
	if report.Programs[0].PCRPID == report.Programs[1].PCRPID {
		t.Errorf("both programs declare PCR PID %#04x", report.Programs[0].PCRPID)
	}
	if report.MPU.OutOfOrderPackets != 0 || report.MPU.SequenceGaps != 0 || report.MPU.FragmentErrors != 0 {
		t.Errorf("the packages interfered during reassembly: out of order %d, gaps %d, fragment errors %d",
			report.MPU.OutOfOrderPackets, report.MPU.SequenceGaps, report.MPU.FragmentErrors)
	}
	single, _, _ := convert(t, buildStream(4, 3, 5, -1))
	want := make(map[string]uint64)
	for _, s := range single.Streams {
		want[s.AssetType] = s.AUsOut
	}
	for service, streams := range byService {
		for _, s := range streams {
			if s.AUsOut != want[s.AssetType] {
				t.Errorf("service %#04x %s wrote %d access units, want the %d a single-service conversion writes",
					service, s.AssetType, s.AUsOut, want[s.AssetType])
			}
		}
	}
}

func TestEachProgramKeepsItsOwnEIT(t *testing.T) {
	b := newBuilder()
	b.control(actualNIT(0x0004))
	for _, p := range testPackages {
		b.m2Section(0x8000, 0x8000, eventSection(p.service, "テスト番組", "解説"))
	}
	b.buf.Write(buildMultiPackageStream(4, 3, 5))

	var out bytes.Buffer
	if _, err := Run(bytes.NewReader(b.buf.Bytes()), &out, DefaultOptions()); err != nil {
		t.Fatal(err)
	}
	check, err := tscheck.Scan(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if check.Errors() != 0 {
		tscheck.WriteReport(testWriter{t}, check)
		t.Fatalf("independent check found %d problems", check.Errors())
	}
	for _, p := range testPackages {
		if !hasEITFor(out.Bytes(), p.service) {
			t.Errorf("no EIT section names service %#04x", p.service)
		}
	}
}

func hasEITFor(ts []byte, service uint16) bool {
	for i := 0; i+6 < len(ts); i++ {
		if ts[i] != mpegts.TableIDEITPFActual || ts[i+1]&0xf0 != 0xf0 {
			continue
		}
		if binary.BigEndian.Uint16(ts[i+3:i+5]) == service && ts[i+5]&0xc0 == 0xc0 {
			return true
		}
	}
	return false
}
