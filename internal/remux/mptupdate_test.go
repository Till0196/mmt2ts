// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/timeline"
	"mmt2ts/internal/tscheck"
)

// What a broadcast does while it is running: an asset appears, an asset goes
// away, an asset moves to another packet identifier, an asset changes what it
// is. The rule the receiving side depends on is that none of it disturbs the
// assets that did not change -- a stream must not be pushed to another PID
// because the one beside it left.

const (
	// One tick for both kinds, and the same number of units in a media unit.
	//
	// The other fixtures give the picture and the sound their own rates,
	// which is what a broadcast does. It cannot be done here: the two then
	// cover different amounts of time per media unit, the sound runs ahead of
	// the picture, and by the third map the skew is wider than the reorder
	// window. What is being tested is what the PMT says over time, so the two
	// are made to advance together and the rate itself is not looked at.
	upTick = testAudioTick
	upAUs  = 2
	// The PMT the converter writes, which `DefaultOptions` puts here.
	pmtOutPID = 0x0100
)

// The converter, told to hand its output over as it goes.
//
// `DefaultOptions` holds three seconds against reordering and a second of
// preroll, which is longer than any of these transmissions: everything would
// leave in one flush at the end and every PMT section would carry the last
// state. A map update that is never seen in the output cannot be tested, so
// the two are shortened to less than one phase.
func convertLive(t *testing.T, input []byte) (Report, []byte) {
	t.Helper()
	var out bytes.Buffer
	opts := DefaultOptions()
	opts.ServiceID = 1
	opts.ReorderWindow = timeline.Hz / 15
	opts.Preroll = timeline.Hz / 50
	report, err := Run(bytes.NewReader(input), &out, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.ReorderDrops != 0 {
		t.Fatalf("%d access units were dropped by the reorder window, so the "+
			"output does not show what the converter decided", report.ReorderDrops)
	}
	// The shortened window must not have made a stream that is merely
	// different rather than valid: a test reading a broken table proves
	// nothing about what the converter decided.
	check, err := tscheck.Scan(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("tscheck: %v", err)
	}
	if check.Errors() != 0 {
		tscheck.WriteReport(testWriter{t}, check)
		t.Fatalf("independent check found %d problems", check.Errors())
	}
	return report, out.Bytes()
}

// One asset as a map update names it.
//
// `id` is what tells the asset apart from one map to the next, and it is kept
// separate from `packetID` on purpose: a transmission may move an asset to
// another packet identifier without it becoming a different asset. Nought
// means the packet identifier, which is what an asset that never moves wants.
type upAsset struct {
	audio    bool
	latm     bool
	packetID uint16
	id       uint16
	tag      uint16
}

// One stretch of the transmission: a map, and the media that arrives while it
// stands.
type upPhase struct {
	assets []upAsset
	mpus   int
}

// A stream whose package table is sent once and whose map is sent again at
// each phase, with the version raised so that the change is taken.
func upStream(phases []upPhase) []byte {
	b := newBuilder()
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTable(1)), 0)
	at := 0
	for n, phase := range phases {
		b.mmtp(testMPTPID, 0x02, false,
			signalingPayload(mptTable(byte(n+1), upAssets(phase.assets, at, phase.mpus))), 0)
		for i := at; i < at+phase.mpus; i++ {
			for _, asset := range phase.assets {
				b.upMedia(asset, uint32(100+i))
			}
		}
		at += phase.mpus
	}
	return b.buf.Bytes()
}

// The map entries for one phase, timed for the media units that phase sends.
//
// The sequence numbers carry on across phases so that time keeps moving: a
// map update is not a discontinuity.
func upAssets(assets []upAsset, from, count int) []testAsset {
	out := make([]testAsset, 0, len(assets))
	for _, a := range assets {
		tick, aus := uint64(upTick), upAUs
		seqs := make([]uint32, count)
		times := make(map[uint32]uint64, count)
		for i := range count {
			seqs[i] = uint32(100 + from + i)
			times[seqs[i]] = testNTPBase + uint64(from+i)*uint64(aus)*tick<<32/testTimescale
		}
		desc := append(
			mpuTimestampDescriptor(times, seqs),
			extendedTimestampDescriptor(seqs, aus, uint16(tick), []uint16{0})...)
		assetType := "hev1"
		if a.audio {
			assetType = "mp4a"
			mode := byte(0x03)
			if a.latm {
				mode = 0x11
			}
			desc = append(desc, audioComponentMode(a.tag, mode)...)
		}
		out = append(out, testAsset{
			assetType: assetType, packetID: a.packetID, id: a.id, tag: a.tag, descriptors: desc,
		})
	}
	return out
}

// One media unit of one asset, built the way `mediaPackage` builds it.
func (b *builder) upMedia(a upAsset, seq uint32) {
	if a.audio {
		for au := range upAUs {
			b.mmtp(a.packetID, 0x00, au == 0, mpuPayload(seq, audioFrame(64)), 0)
		}
		return
	}
	for au := range upAUs {
		b.mmtp(a.packetID, 0x00, au == 0, mpuPayload(seq, nal(35, 3)), 0)
		if au == 0 {
			for _, t := range []byte{32, 33, 34} {
				b.mmtp(a.packetID, 0x00, false, mpuPayload(seq, nal(t, 16)), 0)
			}
		}
		b.mmtp(a.packetID, 0x00, false, mpuPayload(seq, nal(irapOrTrail(au), 64)), 0)
	}
}

type pmtES struct {
	pid        uint16
	streamType byte
	tag        byte
	hasTag     bool
}

type pmtSnapshot struct {
	version byte
	pcrPID  uint16
	streams []pmtES
}

func (s pmtSnapshot) find(pid uint16) (pmtES, bool) {
	for _, es := range s.streams {
		if es.pid == pid {
			return es, true
		}
	}
	return pmtES{}, false
}

func (s pmtSnapshot) has(pid uint16) bool {
	_, ok := s.find(pid)
	return ok
}

// What the section says, in a form two of them can be compared by.
func (s pmtSnapshot) content() string {
	out := fmt.Sprintf("pcr=%04x", s.pcrPID)
	for _, es := range s.streams {
		out += fmt.Sprintf(" %04x/%02x/%02x/%t", es.pid, es.streamType, es.tag, es.hasTag)
	}
	return out
}

func (s pmtSnapshot) String() string {
	return fmt.Sprintf("v%d %s", s.version, s.content())
}

// Every PMT section the output carries, in the order it was written.
//
// The sections are reassembled from the packets rather than assumed to fit in
// one, because what is being tested is partly how large the table gets.
func pmtSections(ts []byte) []pmtSnapshot {
	var out []pmtSnapshot
	var held []byte
	take := func(section []byte) {
		if len(section) < 16 || section[0] != 0x02 {
			return
		}
		body := section[:len(section)-4]
		snap := pmtSnapshot{
			version: (body[5] >> 1) & 0x1f,
			pcrPID:  uint16(body[8]&0x1f)<<8 | uint16(body[9]),
		}
		at := 12 + int(uint16(body[10]&0x0f)<<8|uint16(body[11]))
		for at+5 <= len(body) {
			es := pmtES{
				streamType: body[at],
				pid:        uint16(body[at+1]&0x1f)<<8 | uint16(body[at+2]),
			}
			n := int(uint16(body[at+3]&0x0f)<<8 | uint16(body[at+4]))
			info := body[at+5 : min(at+5+n, len(body))]
			for j := 0; j+2 <= len(info); {
				length := int(info[j+1])
				if info[j] == mpegts.DescStreamIdentifier && length >= 1 && j+2+length <= len(info) {
					es.tag, es.hasTag = info[j+2], true
				}
				j += 2 + length
			}
			snap.streams = append(snap.streams, es)
			at += 5 + n
		}
		out = append(out, snap)
	}
	push := func(d []byte) {
		held = append(held, d...)
		for len(held) >= 3 {
			// Stuffing after the last section of a packet.
			if held[0] == 0xff {
				held = nil
				return
			}
			n := 3 + int(binary.BigEndian.Uint16(held[1:3])&0x0fff)
			if len(held) < n {
				return
			}
			take(held[:n])
			held = append([]byte(nil), held[n:]...)
		}
	}
	for i := 0; i+188 <= len(ts); i += 188 {
		p := ts[i : i+188]
		if uint16(p[1]&0x1f)<<8|uint16(p[2]) != pmtOutPID || p[3]&0x10 == 0 {
			continue
		}
		off := 4
		if p[3]&0x20 != 0 {
			off += 1 + int(p[4])
		}
		if off >= len(p) {
			continue
		}
		d := p[off:]
		if p[1]&0x40 == 0 {
			if len(held) > 0 {
				push(d)
			}
			continue
		}
		pointer := int(d[0])
		d = d[1:]
		if pointer > len(d) {
			continue
		}
		if pointer > 0 && len(held) > 0 {
			push(d[:pointer])
		}
		held = nil
		push(d[pointer:])
	}
	return out
}

// The PMT as it changed, one entry per version the output actually carried.
func pmtHistory(t *testing.T, ts []byte) []pmtSnapshot {
	t.Helper()
	all := pmtSections(ts)
	if len(all) == 0 {
		t.Fatal("the output carries no PMT at all")
	}
	out := make([]pmtSnapshot, 0, 4)
	for _, s := range all {
		if len(out) == 0 || out[len(out)-1].version != s.version {
			out = append(out, s)
		}
	}
	return out
}

func streamStat(t *testing.T, report Report, packetID uint16) StreamStat {
	t.Helper()
	for _, s := range report.Streams {
		if s.PacketID == packetID {
			return s
		}
	}
	t.Fatalf("no stream for packet id %#04x in %v", packetID, report.Streams)
	return StreamStat{}
}

var (
	upVideo  = upAsset{packetID: testVideoPID, tag: 0x0000}
	upSound  = upAsset{audio: true, packetID: testAudioPID, tag: 0x0010}
	upSound2 = upAsset{audio: true, packetID: testAudioPID + 1, tag: 0x0011}

	// Two sounds whose order in the map is the reverse of the order their
	// tags put them in. Nothing else in these tests can tell a PID worked out
	// from the tag apart from one handed out as the streams are met, because
	// everywhere else the two orders agree.
	upLateTag  = upAsset{audio: true, packetID: testAudioPID + 2, tag: 0x0012}
	upEarlyTag = upAsset{audio: true, packetID: testAudioPID + 3, tag: 0x0010}
)

// An asset the map stops naming leaves the PMT.
//
// This is the half that is easy to leave out: a converter that only ever adds
// keeps handing a receiver a stream that is no longer transmitted.
func TestAssetDroppedFromTheMapLeavesThePMT(t *testing.T) {
	_, out := convertLive(t, upStream([]upPhase{
		{assets: []upAsset{upVideo, upSound}, mpus: 10},
		{assets: []upAsset{upVideo}, mpus: 10},
	}))
	history := pmtHistory(t, out)
	var carried bool
	for _, s := range history {
		carried = carried || s.has(audioPIDBase)
	}
	if !carried {
		t.Fatalf("the sound never reached the PMT at all: %v", history)
	}
	last := history[len(history)-1]
	if last.has(audioPIDBase) {
		t.Errorf("the sound is still in the PMT after the map dropped it: %v", last)
	}
	if !last.has(videoPIDBase) {
		t.Errorf("the picture left the PMT as well: %v", last)
	}
}

// An asset the map names but never sends does not reach the PMT.
//
// The rule is that a stream is announced when it can be played, not when it
// is promised: a receiver that opens a PID carrying nothing waits on it.
func TestAssetNamedButNeverSentStaysOutOfThePMT(t *testing.T) {
	silent := upAsset{audio: true, packetID: testAudioPID + 2, tag: 0x0012}
	_, out := convertLive(t, upStream([]upPhase{
		{assets: []upAsset{upVideo, upSound}, mpus: 10},
	}))
	full := pmtHistory(t, out)
	if !full[len(full)-1].has(audioPIDBase) {
		t.Fatalf("the sound that was sent is missing, so the test proves nothing: %v", full)
	}

	// The same transmission, with one more asset in the map and nothing on
	// its packet identifier.
	b := newBuilder()
	b.mmtp(0x0000, 0x02, false, signalingPayload(pltTable(1)), 0)
	b.mmtp(testMPTPID, 0x02, false,
		signalingPayload(mptTable(1, upAssets([]upAsset{upVideo, upSound, silent}, 0, 10))), 0)
	for i := range 10 {
		b.upMedia(upVideo, uint32(100+i))
		b.upMedia(upSound, uint32(100+i))
	}
	_, quiet := convertLive(t, b.buf.Bytes())
	// The whole run of sections, not just the last: an asset that never had a
	// PID assigned would be announced on nought rather than on a PID of its
	// own, so looking only for the PID the mapping would have given it would
	// miss it. Naming an asset that sends nothing must change nothing at all.
	had, got := pmtContents(out), pmtContents(quiet)
	if len(had) != len(got) {
		t.Fatalf("%d PMT sections with the silent asset, %d without", len(got), len(had))
	}
	for i := range had {
		if had[i] != got[i] {
			t.Fatalf("PMT section %d differs when an asset that sends nothing is named:\n"+
				"  got  %s\n  want %s", i, got[i], had[i])
		}
	}
}

// What each PMT section said, in order.
func pmtContents(ts []byte) []string {
	sections := pmtSections(ts)
	out := make([]string, len(sections))
	for i, s := range sections {
		out[i] = s.content()
	}
	return out
}

// A stream's PID comes from its component tag, not from where it sits.
//
// The map here names the higher tag first, so a converter handing out PIDs as
// it meets the streams would give the two the other way round. It would also
// move the survivor down when the one before it is dropped, and a receiver
// holding the PID would find another asset on it.
func TestPIDFollowsTheTagRatherThanThePlaceInTheMap(t *testing.T) {
	_, out := convertLive(t, upStream([]upPhase{
		{assets: []upAsset{upVideo, upLateTag, upEarlyTag}, mpus: 10},
		{assets: []upAsset{upVideo, upEarlyTag}, mpus: 10},
	}))
	history := pmtHistory(t, out)
	var both pmtSnapshot
	for _, s := range history {
		if s.has(audioPIDBase) && s.has(audioPIDBase+2) {
			both = s
		}
	}
	if len(both.streams) == 0 {
		t.Fatalf("the two sounds were never in the PMT together: %v", history)
	}
	// The one named second in the map carries the lower tag, so it takes the
	// lower PID.
	early, _ := both.find(audioPIDBase)
	late, _ := both.find(audioPIDBase + 2)
	if early.tag != 0x10 {
		t.Errorf("PID %#04x carries tag %#02x, want 0x10", audioPIDBase, early.tag)
	}
	if late.tag != 0x12 {
		t.Errorf("PID %#04x carries tag %#02x, want 0x12", audioPIDBase+2, late.tag)
	}

	last := history[len(history)-1]
	if last.has(audioPIDBase + 2) {
		t.Errorf("the dropped sound is still in the PMT: %v", last)
	}
	kept, ok := last.find(audioPIDBase)
	if !ok {
		t.Fatalf("the sound that stayed left the PMT with the one that went: %v", last)
	}
	if kept != early {
		t.Errorf("the surviving sound changed from %+v to %+v when the other was dropped",
			early, kept)
	}
}

// An asset moved to another packet identifier is the same asset.
//
// The map identifies an asset by its identifier, not by where it is carried,
// so the PID handed to a receiver must not change when the transmission moves
// it.
func TestAnAssetMovedToAnotherPacketIDKeepsItsPID(t *testing.T) {
	moved := upSound
	moved.id = upSound.packetID
	stayed := moved
	stayed.packetID = testAudioPID + 8
	report, out := convertLive(t, upStream([]upPhase{
		{assets: []upAsset{upVideo, moved}, mpus: 10},
		{assets: []upAsset{upVideo, stayed}, mpus: 10},
	}))
	last := pmtHistory(t, out)[0]
	for _, s := range pmtHistory(t, out) {
		last = s
	}
	if !last.has(audioPIDBase) {
		t.Errorf("the moved sound lost its PID: %v", last)
	}
	if last.has(audioPIDBase + 1) {
		t.Errorf("the moved sound was given a second PID as well: %v", last)
	}
	stat := streamStat(t, report, stayed.packetID)
	if stat.PacketIDMoves != 1 {
		t.Errorf("PacketIDMoves = %d, want 1", stat.PacketIDMoves)
	}
	if stat.PID != audioPIDBase {
		t.Errorf("PID = %#04x, want %#04x", stat.PID, audioPIDBase)
	}
}

// An asset that changes what it is is noticed, and the PMT says so.
//
// Ordinary AAC and 22.2 channel sound leave this converter under different
// stream types, and a receiver that kept the first would frame the second
// wrongly.
func TestStreamTypeChangeReachesThePMT(t *testing.T) {
	latm := upSound
	latm.latm = true
	report, out := convertLive(t, upStream([]upPhase{
		{assets: []upAsset{upVideo, upSound}, mpus: 10},
		{assets: []upAsset{upVideo, latm}, mpus: 10},
	}))
	history := pmtHistory(t, out)
	var saw, want bool
	for _, s := range history {
		if es, ok := s.find(audioPIDBase); ok {
			saw = saw || es.streamType == mpegts.StreamTypeADTSAAC
			want = es.streamType == mpegts.StreamTypeLATMAAC
		}
	}
	if !saw {
		t.Errorf("the sound was never announced as ADTS: %v", history)
	}
	if !want {
		t.Errorf("the sound is not LATM in the last PMT: %v", history[len(history)-1])
	}
	if got := streamStat(t, report, testAudioPID).StreamTypeChanges; got != 1 {
		t.Errorf("StreamTypeChanges = %d, want 1", got)
	}
}

// Two PMT sections with the same version say the same thing.
//
// This is what a receiver is entitled to assume: it drops a repeat without
// reading it. A table that changed while its version stood still would be
// read once and then never again.
func TestPMTContentNeverChangesUnderAStandingVersion(t *testing.T) {
	_, out := convertLive(t, upStream([]upPhase{
		{assets: []upAsset{upVideo, upSound}, mpus: 10},
		{assets: []upAsset{upVideo, upSound, upSound2}, mpus: 10},
		{assets: []upAsset{upVideo, upSound2}, mpus: 10},
	}))
	sections := pmtSections(out)
	if len(sections) < 4 {
		t.Fatalf("only %d PMT sections were written", len(sections))
	}
	seen := make(map[byte]pmtSnapshot)
	for _, s := range sections {
		had, ok := seen[s.version]
		if !ok {
			seen[s.version] = s
			continue
		}
		if had.content() != s.content() {
			t.Errorf("version %d says two things:\n  %s\n  %s", s.version, had.content(), s.content())
		}
	}
	if len(seen) < 2 {
		t.Errorf("the PMT never changed version across three maps: %v", pmtHistory(t, out))
	}
}
