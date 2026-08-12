// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"errors"
	"testing"
)

const (
	testService  = 0x0066
	testNTPBase  = uint64(0xebd83880) << 32
	testRealtime = 0x1d00
	testObject   = 0x1d01
)

type collector struct {
	sections map[uint16][][]byte
	order    []uint16
}

func newCollector() *collector {
	return &collector{sections: make(map[uint16][][]byte)}
}

func (c *collector) write(pid uint16, section []byte) error {
	c.sections[pid] = append(c.sections[pid], bytes.Clone(section))
	c.order = append(c.order, pid)
	return nil
}

func (c *collector) tableIDs(pid uint16) []byte {
	var out []byte
	for _, s := range c.sections[pid] {
		out = append(out, s[0])
	}
	return out
}

func newTestRecorder(t *testing.T) *Recorder {
	t.Helper()
	r, err := NewRecorder(Config{
		ServiceID: testService, TransportStreamID: 0x4010, OriginalNetworkID: 4,
		RealtimePID: testRealtime, ObjectPID: testObject, RealtimeTag: 0xe0, ObjectTag: 0xe1,
	})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	return r
}

func ntpAfter(ms uint64) uint64 { return testNTPBase + msToNTP(ms) }

func TestSegmentWindowsFollowTheSourceClock(t *testing.T) {
	r := newTestRecorder(t)
	r.Observe(testNTPBase)

	for _, ms := range []uint64{0, 200, 499, 500, 700, 1000} {
		r.AddRecord(RecordRawSignalling, RecordRawExact, ntpAfter(ms), nil, []byte{byte(ms)})
	}
	r.Observe(ntpAfter(1200))

	c := newCollector()
	if err := r.Emit(0, c.write); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := r.Stats().Segments; got != 2 {
		t.Fatalf("closed %d segments, want 2", got)
	}
	if !r.realtime.Has(TimedModuleID(0, 0)) || !r.realtime.Has(TimedModuleID(1, 0)) {
		t.Error("closed segments were not installed into the realtime carousel")
	}
	if r.realtime.Has(TimedModuleID(2, 0)) {
		t.Error("the open window was installed early")
	}
}

func TestSegmentRingReusesModuleIDsWithAFreshVersion(t *testing.T) {
	r := newTestRecorder(t)
	r.Observe(testNTPBase)
	const turns = 2
	for i := range uint64(timedRingSegments * turns) {
		r.AddRecord(RecordRawSignalling, 0, ntpAfter(i*500+10), nil, []byte{byte(i)})
	}
	r.Observe(ntpAfter(timedRingSegments*turns*500 + 600))

	c := newCollector()
	now := int64(0)
	for range 4 {
		if err := r.Emit(now, c.write); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		now += SegmentInterval
	}
	const closed = timedRingSegments * turns
	if got := r.Stats().Segments; got != closed {
		t.Fatalf("closed %d segments, want %d", got, closed)
	}

	window := r.repeatWindow()
	for seq := uint64(0); seq < closed; seq++ {
		id := TimedModuleID(seq, 0)
		advertised := r.realtime.Has(id)
		want := seq >= closed-window
		if !want && advertised && r.realtime.modules[id].entry.LogicalID == seq {
			t.Errorf("segment %d is still being sent, outside the %d-segment repeat window", seq, window)
		}
		if want && !advertised {
			t.Errorf("segment %d is inside the repeat window but is not advertised", seq)
		}
	}

	slot := TimedModuleID(0, 0)
	if got := r.realtime.lastVersion[slot]; got == 0 {
		t.Errorf("ring slot %#04x was reused with moduleVersion 0 again", slot)
	}
}

func TestTheRealtimeCarouselStaysInsideItsModuleBudget(t *testing.T) {
	r := newTestRecorder(t)
	r.Observe(testNTPBase)
	for i := range uint64(200) {
		r.AddRecord(RecordRawSignalling, 0, ntpAfter(i*500+10), nil, []byte{byte(i)})
		r.SetCodecConfig(CodecConfig{ConfigID: 1, Kind: ConfigHEVC, Data: []byte{byte(i)}})
		r.AddLoss(LossEntry{Scope: ScopeSegment, Reason: ReasonInputMissing, Severity: SeverityPartial, LogicalID: i})
		r.Observe(ntpAfter(i*500 + 400))
	}
	c := newCollector()
	now := int64(0)
	for range 20 {
		if err := r.Emit(now, c.write); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		now += SegmentInterval
	}
	if got := r.realtime.ModuleCount(); got > MaxRealtimeModules {
		t.Errorf("realtime carousel holds %d modules, budget is %d", got, MaxRealtimeModules)
	}
}

func TestEveryCycleSendsTheDIIBeforeItsBlocks(t *testing.T) {
	r := newTestRecorder(t)
	r.Observe(testNTPBase)
	r.AddRecord(RecordRawSignalling, 0, ntpAfter(10), nil, []byte("x"))
	r.Observe(ntpAfter(1200))

	c := newCollector()
	if err := r.Emit(0, c.write); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	ids := c.tableIDs(testRealtime)
	if len(ids) == 0 {
		t.Fatal("the realtime carousel sent nothing")
	}
	if ids[0] != 0x3b {
		t.Errorf("first section is table id %#02x, want the DII 0x3b", ids[0])
	}
	for _, id := range ids[1:] {
		if id != 0x3c {
			t.Errorf("unexpected table id %#02x after the DII", id)
		}
	}
}

func TestTheObjectCycleCommitsTheManifestAfterItsObjects(t *testing.T) {
	r := newTestRecorder(t)
	r.Observe(testNTPBase)
	for i := range uint64(3) {
		err := r.AddObject(PackInput{
			ID: i, Class: ClassApplicationItem, Path: "index.html",
			MediaType: "text/html", Stored: bytes.Repeat([]byte{byte(i)}, 100),
		})
		if err != nil {
			t.Fatalf("AddObject: %v", err)
		}
	}
	if err := r.Finish(0); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	c := newCollector()
	if err := r.Emit(0, c.write); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var seen []uint16
	for _, s := range c.sections[testObject] {
		if s[0] != 0x3c {
			continue
		}
		seen = append(seen, uint16(s[3])<<8|uint16(s[4]))
	}
	if len(seen) < 3 {
		t.Fatalf("object carousel sent %d blocks, want the objects, the manifest and the bootstrap", len(seen))
	}
	last := seen[len(seen)-1]
	manifest := seen[len(seen)-2]
	if last != ModuleIDBootstrap {
		t.Errorf("last module of the cycle is %#04x, want the bootstrap", last)
	}
	if manifest != ModuleIDObjectManifest {
		t.Errorf("second to last module is %#04x, want the manifest", manifest)
	}
	for _, id := range seen[:len(seen)-2] {
		if id < moduleIDObjectBase {
			t.Errorf("module %#04x was sent before the object blocks", id)
		}
	}
}

func TestTheCommittedManifestDescribesTheObjectsThatWereSent(t *testing.T) {
	r := newTestRecorder(t)
	r.Observe(testNTPBase)
	want := map[uint64][]byte{
		1: bytes.Repeat([]byte{0xa1}, 5000),
		2: bytes.Repeat([]byte{0xb2}, 300),
	}
	for id, data := range want {
		if err := r.AddObject(PackInput{ID: id, Class: ClassImage, Path: "img.png", Stored: data}); err != nil {
			t.Fatalf("AddObject: %v", err)
		}
	}
	if err := r.Finish(0); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	header, payload, err := ParseModule(r.object.modules[ModuleIDObjectManifest].stored)
	if err != nil {
		t.Fatalf("ParseModule(manifest): %v", err)
	}
	if header.Flags&FlagCommit == 0 {
		t.Error("the manifest was published without the commit flag")
	}
	manifest, err := ParseManifest(payload)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(manifest.Objects) != len(want) {
		t.Fatalf("manifest lists %d objects, want %d", len(manifest.Objects), len(want))
	}
	for _, o := range manifest.Objects {
		var joined []byte
		for _, p := range o.Parts {
			_, modulePayload, err := ParseModule(r.object.modules[p.ModuleID].stored)
			if err != nil {
				t.Fatalf("ParseModule(object %#04x): %v", p.ModuleID, err)
			}
			if got := r.object.modules[p.ModuleID].version; got != p.ModuleVersion {
				t.Errorf("object %d part %d says version %d, the carousel carries %d", o.ID, p.PartNumber, p.ModuleVersion, got)
			}
			joined = append(joined, modulePayload[p.Offset:uint32(p.Offset)+p.StoredLength]...)
		}
		if !bytes.Equal(joined, want[o.ID]) {
			t.Errorf("object %d reassembles to %d bytes, want %d", o.ID, len(joined), len(want[o.ID]))
		}
	}
}

func TestResendingTheSameObjectIsDeduplicated(t *testing.T) {
	r := newTestRecorder(t)
	data := bytes.Repeat([]byte{0x11}, 100)
	for range 5 {
		if err := r.AddObject(PackInput{ID: 1, Class: ClassApplicationItem, Stored: data}); err != nil {
			t.Fatalf("AddObject: %v", err)
		}
	}
	if got := r.Stats().Objects; got != 1 {
		t.Errorf("kept %d objects, want 1", got)
	}
	if got := r.Stats().ObjectBytes; got != len(data) {
		t.Errorf("kept %d object bytes, want %d", got, len(data))
	}
}

func TestAnObjectSetLargerThanTheCarouselFails(t *testing.T) {
	r := newTestRecorder(t)
	const chunk = MaxModuleSize - HeaderLength
	var err error
	for i := range uint64(MaxObjectModules + 2) {
		err = r.AddObject(PackInput{ID: i, Class: ClassGenericAsset, Stored: make([]byte, chunk)})
		if err != nil {
			break
		}
	}
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("AddObject past the carousel budget = %v, want ErrCapacityExceeded", err)
	}
	if r.Stats().LossEntries == 0 {
		t.Error("the capacity failure was not recorded as a loss")
	}
}

func TestTheRealtimeBootstrapDescribesTheInstalledModules(t *testing.T) {
	r := newTestRecorder(t)
	r.Observe(testNTPBase)
	r.AddRecord(RecordRawSignalling, 0, ntpAfter(10), nil, []byte("x"))
	r.SetCodecConfig(CodecConfig{ConfigID: 1, Kind: ConfigHEVC, OutputPID: 0x1011, Data: []byte{0x40}})
	r.Observe(ntpAfter(1200))
	if err := r.Emit(0, func(uint16, []byte) error { return nil }); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	_, payload, err := ParseModule(r.realtime.modules[ModuleIDBootstrap].stored)
	if err != nil {
		t.Fatalf("ParseModule(bootstrap): %v", err)
	}
	b, err := ParseBootstrap(payload)
	if err != nil {
		t.Fatalf("ParseBootstrap: %v", err)
	}
	if b.ServiceID != testService {
		t.Errorf("bootstrap service id = %#04x, want %#04x", b.ServiceID, testService)
	}
	if b.RealtimeDownload != realtimeDownloadPrefix|testService || b.ObjectDownload != objectDownloadPrefix|testService {
		t.Errorf("download ids = %#08x, %#08x", b.RealtimeDownload, b.ObjectDownload)
	}
	if b.SegmentDurationMS != DefaultSegmentDurationMS || b.LeadTimeMS != DefaultLeadTimeMS || b.PlayoutLimitMS != DefaultPlayoutLimitMS {
		t.Errorf("bootstrap profile = %d ms, lead %d, limit %d", b.SegmentDurationMS, b.LeadTimeMS, b.PlayoutLimitMS)
	}
	if !b.haveEntry(ModuleIDCodecConfig) || !b.haveEntry(TimedModuleID(0, 0)) {
		t.Errorf("bootstrap directory is missing modules: %+v", b.Entries)
	}
	for _, e := range b.Entries {
		if e.ModuleID == ModuleIDBootstrap {
			t.Error("the bootstrap listed itself")
		}
		m := r.realtime.modules[e.ModuleID]
		if m == nil {
			t.Errorf("directory names module %#04x which is not advertised", e.ModuleID)
			continue
		}
		if e.StoredSize != uint32(len(m.stored)) || e.Version != m.version {
			t.Errorf("directory entry for %#04x disagrees with the carousel", e.ModuleID)
		}
	}
}

func (b *Bootstrap) haveEntry(id uint16) bool {
	for _, e := range b.Entries {
		if e.ModuleID == id {
			return true
		}
	}
	return false
}

func TestSegmentDurationOutsideTheAllowedRangeIsRejected(t *testing.T) {
	for _, ms := range []uint32{100, 249, 1001, 5000} {
		if _, err := NewRecorder(Config{SegmentDurationMS: ms}); err == nil {
			t.Errorf("NewRecorder accepted a %d ms segment duration", ms)
		}
	}
	for _, ms := range []uint32{0, 250, 500, 1000} {
		if _, err := NewRecorder(Config{SegmentDurationMS: ms}); err != nil {
			t.Errorf("NewRecorder(%d ms) = %v", ms, err)
		}
	}
}

func TestNTPAndMillisecondsConvertBothWays(t *testing.T) {
	for _, ms := range []uint64{0, 1, 250, 500, 999, 1000, 123456} {
		if got := ntpMS(msToNTP(ms)); got != ms {
			t.Errorf("ntpMS(msToNTP(%d)) = %d", ms, got)
		}
	}
}

func TestACompressedObjectIsDescribedByItsExpandedBytes(t *testing.T) {
	original := bytes.Repeat([]byte("mmt2ts preservation payload "), 200)
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(original); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	stored := buf.Bytes()
	if len(stored) >= len(original) {
		t.Fatalf("the test payload did not compress: %d -> %d", len(original), len(stored))
	}

	r := newTestRecorder(t)
	err := r.AddObject(PackInput{
		ID: 1, Class: ClassApplicationItem, Compression: CompressionZlib,
		Path: "index.html", Stored: stored,
		OriginalSize: uint64(len(original)),
	})
	if err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if err := r.Finish(0); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	_, payload, err := ParseModule(r.object.modules[ModuleIDObjectManifest].stored)
	if err != nil {
		t.Fatalf("ParseModule: %v", err)
	}
	m, err := ParseManifest(payload)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	o := m.Objects[0]
	if o.OriginalSize != uint64(len(original)) {
		t.Errorf("original_size = %d, want %d", o.OriginalSize, len(original))
	}
	if want := sha256.Sum256(original); o.OriginalSHA256 != want {
		t.Errorf("original_sha256 describes the compressed bytes, not the expanded ones")
	}
	if want := sha256.Sum256(stored); o.Parts[0].StoredSHA256 != want {
		t.Errorf("part digest does not match the stored bytes")
	}
	if r.Stats().LossEntries != 0 {
		t.Errorf("a well formed object produced %d losses", r.Stats().LossEntries)
	}
}

func TestAnUnreadableCompressedObjectIsMarkedIncompleteRatherThanMisdescribed(t *testing.T) {
	r := newTestRecorder(t)
	err := r.AddObject(PackInput{
		ID: 1, Class: ClassApplicationItem, Compression: CompressionZlib,
		Stored: []byte("this is not zlib at all"),
	})
	if err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if r.Stats().LossEntries == 0 {
		t.Error("an object that cannot be expanded was accepted without a loss")
	}
	if got := r.objects[1]; got.Flags&ObjectIncomplete == 0 {
		t.Error("the object was not marked incomplete")
	}
	if got := r.objects[1]; got.OriginalSHA256 != [32]byte{} {
		t.Error("a digest was invented for bytes that could not be expanded")
	}
}

func TestSinglePartObjectsReuseTheDigestTakenOnArrival(t *testing.T) {
	data := bytes.Repeat([]byte{0x5a}, 4096)
	r := newTestRecorder(t)
	if err := r.AddObject(PackInput{ID: 7, Class: ClassImage, Stored: data}); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	if err := r.Finish(0); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	_, payload, err := ParseModule(r.object.modules[ModuleIDObjectManifest].stored)
	if err != nil {
		t.Fatalf("ParseModule: %v", err)
	}
	m, err := ParseManifest(payload)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	want := sha256.Sum256(data)
	if got := m.Objects[0].Parts[0].StoredSHA256; got != want {
		t.Errorf("part digest = %x, want %x", got, want)
	}
	if got := m.Objects[0].OriginalSHA256; got != want {
		t.Errorf("object digest = %x, want %x", got, want)
	}
}

func TestTheObjectDirectoryDigestMatchesTheModuleItDescribes(t *testing.T) {
	r := newTestRecorder(t)
	const capacity = MaxModuleSize - HeaderLength
	for i := range uint64(2) {
		data := bytes.Repeat([]byte{byte(i + 1)}, capacity+1000)
		if err := r.AddObject(PackInput{ID: i, Class: ClassGenericAsset, Stored: data}); err != nil {
			t.Fatalf("AddObject: %v", err)
		}
	}
	if err := r.Finish(0); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	_, payload, err := ParseModule(r.object.modules[ModuleIDBootstrap].stored)
	if err != nil {
		t.Fatalf("ParseModule(bootstrap): %v", err)
	}
	b, err := ParseBootstrap(payload)
	if err != nil {
		t.Fatalf("ParseBootstrap: %v", err)
	}
	checked := 0
	for _, e := range b.Entries {
		if e.Kind != KindStaticObject {
			continue
		}
		m := r.object.modules[e.ModuleID]
		if m == nil {
			t.Fatalf("directory names module %#04x which is not advertised", e.ModuleID)
		}
		_, modulePayload, err := ParseModule(m.stored)
		if err != nil {
			t.Fatalf("ParseModule(%#04x): %v", e.ModuleID, err)
		}
		if got := sha256.Sum256(modulePayload); got != e.SHA256 {
			t.Errorf("module %#04x directory digest %x does not match its payload %x",
				e.ModuleID, e.SHA256, got)
		}
		if e.StoredSize != uint32(len(m.stored)) {
			t.Errorf("module %#04x directory size %d, carousel has %d", e.ModuleID, e.StoredSize, len(m.stored))
		}
		checked++
	}
	if checked < 2 {
		t.Fatalf("only %d static object modules were checked", checked)
	}
}

func TestPreservedMediaMovesToTheShortWindow(t *testing.T) {
	r := newTestRecorder(t)
	if got := r.cfg.SegmentDurationMS; got != DefaultSegmentDurationMS {
		t.Fatalf("segment duration = %d, want the default", got)
	}
	r.Observe(testNTPBase)
	r.UseShortSegments()
	if got := r.cfg.SegmentDurationMS; got != minSegmentDurationMS {
		t.Errorf("segment duration = %d, want %d", got, minSegmentDurationMS)
	}
	if !r.Stats().ShortSegments {
		t.Error("the change was not reported")
	}

	r.AddRecord(RecordRawSignalling, 0, ntpAfter(10), nil, []byte("x"))
	r.Observe(ntpAfter(2000))
	before := r.cfg.SegmentDurationMS
	r.UseShortSegments()
	if r.cfg.SegmentDurationMS != before {
		t.Error("the window changed after a segment had already closed")
	}
}

func TestAWindowOfPreservedMediaIsSentOnce(t *testing.T) {
	r := newTestRecorder(t)
	r.Observe(testNTPBase)
	payload := make([]byte, 1400)
	for range 200 {
		r.AddRecord(RecordGenericTimedData, RecordRawExact, ntpAfter(10), nil, payload)
	}
	r.Observe(ntpAfter(1200))

	c := newCollector()
	now := int64(0)
	for range 6 {
		if err := r.Emit(now, c.write); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		now += SegmentInterval
	}
	if got := r.Stats().BulkSegments; got != 1 {
		t.Fatalf("bulk windows = %d, want 1", got)
	}
	m := r.realtime.modules[TimedModuleID(0, 0)]
	if m == nil {
		t.Fatal("the window is not advertised")
	}
	if m.sent != 1 {
		t.Errorf("the window was transmitted %d times, want once", m.sent)
	}

	r2 := newTestRecorder(t)
	r2.Observe(testNTPBase)
	r2.AddRecord(RecordRawSignalling, 0, ntpAfter(10), nil, []byte("section"))
	r2.Observe(ntpAfter(1200))
	now = 0
	for range 6 {
		if err := r2.Emit(now, func(uint16, []byte) error { return nil }); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		now += SegmentInterval
	}
	if got := r2.realtime.modules[TimedModuleID(0, 0)]; got == nil || got.sent < 2 {
		t.Errorf("a signalling window was not repeated: %+v", got)
	}
	if got := r2.Stats().BulkSegments; got != 0 {
		t.Errorf("a signalling window was counted as bulk: %d", got)
	}
}

func TestAWindowTooLargeForTheProfileIsReportedNotFatal(t *testing.T) {
	r := newTestRecorder(t)
	r.Observe(testNTPBase)
	payload := make([]byte, 1400)
	for range 6000 {
		r.AddRecord(RecordGenericTimedData, RecordRawExact, ntpAfter(10), nil, payload)
	}
	r.Observe(ntpAfter(1200))
	if err := r.Emit(0, func(uint16, []byte) error { return nil }); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if r.Stats().LossEntries == 0 {
		t.Fatal("an overflowing window produced no loss entry")
	}
	parts := 0
	for i := range MaxSegmentParts {
		if r.realtime.Has(TimedModuleID(0, i)) {
			parts++
		}
	}
	if parts != MaxSegmentParts {
		t.Errorf("%d parts were published, want the full %d", parts, MaxSegmentParts)
	}
}
