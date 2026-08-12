// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func mustModule(t *testing.T, h Header, payload []byte) []byte {
	t.Helper()
	m, err := BuildModule(h, payload)
	if err != nil {
		t.Fatalf("BuildModule: %v", err)
	}
	return m
}

func TestModuleHeaderRoundTripsThroughItsOwnChecksums(t *testing.T) {
	want := Header{
		Kind:       KindTimedSegment,
		Flags:      FlagRawExact,
		EpochID:    7,
		LogicalID:  0x0102030405060708,
		StartNTP:   0xebd8388000000000,
		DurationMS: 500,
	}
	payload := []byte("timed segment payload")
	module := mustModule(t, want, payload)
	if len(module) != HeaderLength+len(payload) {
		t.Fatalf("module is %d bytes, want %d", len(module), HeaderLength+len(payload))
	}

	got, gotPayload, err := ParseModule(module)
	if err != nil {
		t.Fatalf("ParseModule: %v", err)
	}
	if got != want {
		t.Errorf("header = %+v, want %+v", got, want)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload = %q, want %q", gotPayload, payload)
	}
}

func TestModuleParsingRejectsEveryFieldItChecks(t *testing.T) {
	base := mustModule(t, Header{Kind: KindCodecConfig}, []byte("abcd"))

	for _, tc := range []struct {
		name   string
		damage func(m []byte) []byte
		want   error
	}{
		{"magic", func(m []byte) []byte { m[0] = 'X'; return m }, errBadMagic},
		{"major version", func(m []byte) []byte { m[4] = 2; return m }, errBadVersion},
		{"header length", func(m []byte) []byte { binary.BigEndian.PutUint16(m[12:14], 40); return m }, errBadHeaderLen},
		{"header crc", func(m []byte) []byte { m[5] = byte(KindLossReport); return m }, errHeaderCRC},
		{"payload crc", func(m []byte) []byte { m[HeaderLength] ^= 0xff; return m }, errPayloadCRC},
		{"truncated payload", func(m []byte) []byte { return m[:len(m)-1] }, errPayloadLength},
		{"shorter than the header", func(m []byte) []byte { return m[:HeaderLength-1] }, errShortHeader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.damage(bytes.Clone(base))
			if _, _, err := ParseModule(m); !errors.Is(err, tc.want) {
				t.Errorf("ParseModule after damaging %s = %v, want %v", tc.name, err, tc.want)
			}
		})
	}
}

func TestModuleFlagCombinationsTheSpecForbidsAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    Header
	}{
		{"commit on a non-manifest", Header{Kind: KindTimedSegment, Flags: FlagCommit}},
		{"commit with incomplete", Header{Kind: KindObjectManifest, Flags: FlagCommit | FlagIncomplete}},
		{"undefined flag bit", Header{Kind: KindTimedSegment, Flags: 0x0008}},
		{"invalid kind", Header{Kind: 0x09}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildModule(tc.h, nil); err == nil {
				t.Errorf("BuildModule(%+v) succeeded, want an error", tc.h)
			}
		})
	}
}

func TestDIIAndDDBReachExactlyTheDeclaredMaximumSectionLengths(t *testing.T) {
	modules := make([]ModuleEntry, MaxModules)
	for i := range modules {
		modules[i] = ModuleEntry{ID: uint16(i), Size: MaxModuleSize, Version: byte(i)}
	}
	dii, err := BuildDII(0x4d520066, TransactionID(0), 1_000_000, modules)
	if err != nil {
		t.Fatalf("BuildDII: %v", err)
	}
	if got := len(dii) - 3; got != MaxDIISectionLength {
		t.Errorf("full DII section_length = %d, want %d", got, MaxDIISectionLength)
	}
	if got := int(binary.BigEndian.Uint16(dii[1:3]) & 0x0fff); got != MaxDIISectionLength {
		t.Errorf("DII section_length field = %d, want %d", got, MaxDIISectionLength)
	}

	ddb, err := BuildDDB(0x4d520066, 0x0100, 3, 0, 255, make([]byte, BlockSize))
	if err != nil {
		t.Fatalf("BuildDDB: %v", err)
	}
	if got := len(ddb) - 3; got != MaxDDBSectionLength {
		t.Errorf("full DDB section_length = %d, want %d", got, MaxDDBSectionLength)
	}
	if MaxDDBSectionLength > 4093 {
		t.Errorf("MaxDDBSectionLength = %d, which exceeds the 4093 the spec allows", MaxDDBSectionLength)
	}
}

func TestDIIRejectsWhatTheProfileCannotAdvertise(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modules []ModuleEntry
		cycle   uint32
	}{
		{"too many modules", make([]ModuleEntry, MaxModules+1), 1},
		{"zero module size", []ModuleEntry{{ID: 1, Size: 0}}, 1},
		{"oversized module", []ModuleEntry{{ID: 1, Size: MaxModuleSize + 1}}, 1},
		{"zero download scenario", []ModuleEntry{{ID: 1, Size: 1}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildDII(1, TransactionID(0), tc.cycle, tc.modules); err == nil {
				t.Error("BuildDII succeeded, want an error")
			}
		})
	}
}

func TestSplitModuleFillsEveryBlockButTheLast(t *testing.T) {
	module := make([]byte, BlockSize*2+17)
	for i := range module {
		module[i] = byte(i)
	}
	entry := ModuleEntry{ID: 0x0100, Size: uint32(len(module)), Version: 5}
	sections, err := SplitModule(0x4d520066, entry, module)
	if err != nil {
		t.Fatalf("SplitModule: %v", err)
	}
	if len(sections) != 3 {
		t.Fatalf("got %d blocks, want 3", len(sections))
	}

	var rebuilt []byte
	for i, s := range sections {
		if s[0] != 0x3c {
			t.Errorf("block %d table_id = %#02x, want 0x3c", i, s[0])
		}
		if got := int(s[6]); got != i {
			t.Errorf("block %d section_number = %d", i, got)
		}
		if got := int(s[7]); got != 2 {
			t.Errorf("block %d last_section_number = %d, want 2", i, got)
		}
		body := s[8+12 : len(s)-4]
		if got := binary.BigEndian.Uint16(body[4:6]); int(got) != i {
			t.Errorf("block %d blockNumber = %d", i, got)
		}
		block := body[6:]
		if i < 2 && len(block) != BlockSize {
			t.Errorf("block %d is %d bytes, want %d", i, len(block), BlockSize)
		}
		rebuilt = append(rebuilt, block...)
	}
	if !bytes.Equal(rebuilt, module) {
		t.Error("reassembled blocks do not reproduce the module")
	}
}

func TestTheLargestModuleUsesExactlyTheBlockLimit(t *testing.T) {
	if MaxModuleSize != BlockSize*MaxBlocks {
		t.Fatalf("MaxModuleSize = %d, want %d", MaxModuleSize, BlockSize*MaxBlocks)
	}
	if BlockCount(MaxModuleSize) != MaxBlocks {
		t.Errorf("BlockCount(MaxModuleSize) = %d, want %d", BlockCount(MaxModuleSize), MaxBlocks)
	}
	if BlockCount(MaxModuleSize+1) <= MaxBlocks {
		t.Error("a module past the limit still fits in the block budget")
	}
	if _, err := BuildModule(Header{Kind: KindStaticObject}, make([]byte, MaxModuleSize-HeaderLength+1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Errorf("BuildModule past the limit = %v, want ErrCapacityExceeded", err)
	}
}

func TestBootstrapDirectoryRoundTripsInTheRequiredOrder(t *testing.T) {
	want := &Bootstrap{
		ServiceID: 0x0066, TransportStreamID: 0x4010, OriginalNetworkID: 0x0004,
		EpochID: 3, Generation: 1, UpdateNumber: 9,
		SegmentDurationMS: 500, LeadTimeMS: 2000, PlayoutLimitMS: 3000,
		RealtimeDownload: 0x4d520066, ObjectDownload: 0x4d530066,
		LatestComplete: 42,
		Entries: []DirectoryEntry{
			{Role: RoleRealtime, ModuleID: 0x0301, Version: 2, Kind: KindAVMPUMap, PartCount: 1, StoredSize: 100},
			{Role: RoleRealtime, ModuleID: 0x0100, Required: true, Kind: KindTimedSegment, PartCount: 4, StoredSize: 60, LogicalID: 42},
		},
	}
	payload, err := want.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(payload) != bootstrapFixedLength+directoryEntryLength*len(want.Entries) {
		t.Fatalf("bootstrap payload is %d bytes", len(payload))
	}
	got, err := ParseBootstrap(payload)
	if err != nil {
		t.Fatalf("ParseBootstrap: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("bootstrap = %+v, want %+v", got, want)
	}
	if got.Entries[0].ModuleID != 0x0100 {
		t.Errorf("directory was not sorted by module id: first entry is %#04x", got.Entries[0].ModuleID)
	}
}

func TestBootstrapParsingRejectsAnUnsortedDirectory(t *testing.T) {
	b := &Bootstrap{Entries: []DirectoryEntry{
		{Role: RoleRealtime, ModuleID: 0x0100, Kind: KindTimedSegment, PartCount: 1},
		{Role: RoleRealtime, ModuleID: 0x0301, Kind: KindAVMPUMap, PartCount: 1},
	}}
	payload, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	first := bootstrapFixedLength
	second := first + directoryEntryLength
	swapped := bytes.Clone(payload)
	copy(swapped[first:second], payload[second:])
	copy(swapped[second:], payload[first:second])
	if _, err := ParseBootstrap(swapped); err == nil {
		t.Error("ParseBootstrap accepted an unsorted directory")
	}
}

func TestBootstrapRefusesToListItself(t *testing.T) {
	b := &Bootstrap{Entries: []DirectoryEntry{{Role: RoleRealtime, Kind: KindBootstrapManifest, PartCount: 1}}}
	if _, err := b.Encode(); err == nil {
		t.Error("Encode accepted a bootstrap entry for the bootstrap")
	}
}

func TestDirectoryEntryValidityIsAHalfOpenIntervalWithNoExpiry(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry DirectoryEntry
		ntp   uint64
		want  bool
	}{
		{"before the start", DirectoryEntry{ValidFrom: 10, ValidUntil: 20}, 9, false},
		{"at the start", DirectoryEntry{ValidFrom: 10, ValidUntil: 20}, 10, true},
		{"at the end", DirectoryEntry{ValidFrom: 10, ValidUntil: 20}, 20, false},
		{"never expires", DirectoryEntry{ValidFrom: 10}, 1 << 40, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.entry.Valid(tc.ntp); got != tc.want {
				t.Errorf("Valid(%d) = %v, want %v", tc.ntp, got, tc.want)
			}
		})
	}
}

func TestSegmentRecordsRoundTripWithTheirMetadata(t *testing.T) {
	var meta Metadata
	meta.AddU16(MetaPacketID, 0xf100)
	meta.AddU32(MetaMPUSequence, 12)
	meta.AddU8(MetaSignallingKind, SignallingM2Section)
	meta.AddTableIdentity(0x8000, 0x8b, 0x0066, 3, true, 0, 1)
	meta.AddU64(MetaRelatedLogicalID, 1)
	meta.AddU64(MetaRelatedLogicalID, 2)
	meta.AddText(MetaPath, "app/index.html")

	anchor := TimelineAnchor{OutputPID: 0x1011, ClockKind: ClockPresentation, PTS90k: 900000, SourceNTP: 1 << 40, EpochID: 3}
	want := []Record{
		{Kind: RecordRawSignalling, Flags: RecordRawExact | RecordRequired, Order: 0, SourceNTP: 5, Metadata: meta, Payload: []byte("section")},
		{Kind: RecordTimelineAnchor, Order: 1, SourceNTP: 6, Payload: anchor.Encode()},
	}
	payload, err := EncodeSegment(want)
	if err != nil {
		t.Fatalf("EncodeSegment: %v", err)
	}
	got, err := ParseSegment(payload)
	if err != nil {
		t.Fatalf("ParseSegment: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	if !reflect.DeepEqual(got[0].Metadata, want[0].Metadata) {
		t.Errorf("metadata = %+v, want %+v", got[0].Metadata, want[0].Metadata)
	}
	back, err := ParseTimelineAnchor(got[1].Payload)
	if err != nil {
		t.Fatalf("ParseTimelineAnchor: %v", err)
	}
	if back != anchor {
		t.Errorf("anchor = %+v, want %+v", back, anchor)
	}
}

func TestSegmentEncodingRequiresConsecutiveRecordOrder(t *testing.T) {
	_, err := EncodeSegment([]Record{
		{Kind: RecordRawSignalling, Order: 0},
		{Kind: RecordRawSignalling, Order: 5},
	})
	if err == nil {
		t.Error("EncodeSegment accepted a gap in the record order")
	}
}

func TestOnlyTheRelatedLogicalIDMetadataMayRepeat(t *testing.T) {
	var repeated Metadata
	repeated.AddU16(MetaPacketID, 1)
	repeated.AddU16(MetaPacketID, 2)
	if err := repeated.validate(); err == nil {
		t.Error("validate accepted a repeated packet id")
	}

	var allowed Metadata
	allowed.AddU64(MetaRelatedLogicalID, 1)
	allowed.AddU64(MetaRelatedLogicalID, 2)
	if err := allowed.validate(); err != nil {
		t.Errorf("validate rejected repeated logical ids: %v", err)
	}
}

func TestMetadataWithAWrongFixedLengthIsRejected(t *testing.T) {
	bad := Metadata{{Type: MetaPacketID, Value: []byte{1, 2, 3}}}
	if err := bad.validate(); err == nil {
		t.Error("validate accepted a three-byte packet id")
	}
	raw := binary.BigEndian.AppendUint16(nil, uint16(MetaPacketID))
	raw = binary.BigEndian.AppendUint16(raw, 3)
	raw = append(raw, 1, 2, 3)
	if _, err := ParseMetadata(raw); err == nil {
		t.Error("ParseMetadata accepted a three-byte packet id")
	}
}

func TestUnknownMetadataIsSkippedByLengthAndKept(t *testing.T) {
	raw := binary.BigEndian.AppendUint16(nil, 0x7fff)
	raw = binary.BigEndian.AppendUint16(raw, 3)
	raw = append(raw, 9, 9, 9)
	raw = binary.BigEndian.AppendUint16(raw, uint16(MetaOutputPID))
	raw = binary.BigEndian.AppendUint16(raw, 2)
	raw = binary.BigEndian.AppendUint16(raw, 0x1011)

	got, err := ParseMetadata(raw)
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}
	if len(got) != 2 || got[0].Type != 0x7fff || got[1].Type != MetaOutputPID {
		t.Fatalf("metadata = %+v", got)
	}
	if err := got.validate(); err == nil {
		t.Error("validate accepted an unknown metadata type for writing")
	}
}

func TestObjectManifestRoundTrips(t *testing.T) {
	var meta Metadata
	meta.AddApplicationIdentity(1, 0x0000fffe, 0x0001)
	want := &Manifest{Generation: 2, UpdateNumber: 7, Objects: []ManifestObject{
		{
			ID: 20, Class: ClassImage, Flags: ObjectRequired, Compression: CompressionNone,
			Path: "img/logo.png", MediaType: "image/png", OriginalSize: 30,
			Parts: []ObjectPart{{ModuleID: 0x0100, ModuleVersion: 1, PartNumber: 0, Offset: 10, StoredLength: 30}},
		},
		{
			ID: 10, Class: ClassApplicationItem, Compression: CompressionZlib,
			Path: "index.html", MediaType: "text/html", Metadata: meta, OriginalSize: 100,
			Parts: []ObjectPart{
				{ModuleID: 0x0100, ModuleVersion: 1, PartNumber: 0, Offset: 0, StoredLength: 10},
				{ModuleID: 0x0101, ModuleVersion: 1, PartNumber: 1, Offset: 0, StoredLength: 5},
			},
		},
	}}
	payload, err := want.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := ParseManifest(payload)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("manifest = %+v, want %+v", got, want)
	}
	if got.Objects[0].ID != 10 {
		t.Errorf("objects were not sorted by id: first is %d", got.Objects[0].ID)
	}
}

func TestPackObjectsFillsModulesEndToEndWithoutPadding(t *testing.T) {
	const capacity = MaxModuleSize - HeaderLength
	big := bytes.Repeat([]byte{0xa5}, capacity+100)
	small := bytes.Repeat([]byte{0x5a}, 40)

	modules, manifest, err := PackObjects([]PackInput{
		{ID: 1, Class: ClassApplicationItem, Stored: big, OriginalSize: uint64(len(big))},
		{ID: 2, Class: ClassImage, Stored: small, OriginalSize: uint64(len(small))},
	}, 0x0100, 254)
	if err != nil {
		t.Fatalf("PackObjects: %v", err)
	}
	if len(modules) != 2 {
		t.Fatalf("got %d modules, want 2", len(modules))
	}
	if len(modules[0].Payload) != capacity {
		t.Errorf("first module is %d bytes, want a full %d", len(modules[0].Payload), capacity)
	}
	if want := 100 + len(small); len(modules[1].Payload) != want {
		t.Errorf("second module is %d bytes, want %d with no padding", len(modules[1].Payload), want)
	}
	if modules[0].ID != 0x0100 || modules[1].ID != 0x0101 {
		t.Errorf("module ids = %#04x, %#04x", modules[0].ID, modules[1].ID)
	}

	for _, o := range manifest.Objects {
		var joined []byte
		for _, p := range o.Parts {
			payload := modules[p.ModuleID-0x0100].Payload
			run := payload[p.Offset : uint32(p.Offset)+p.StoredLength]
			if sha256.Sum256(run) != p.StoredSHA256 {
				t.Errorf("object %d part %d hash mismatch", o.ID, p.PartNumber)
			}
			joined = append(joined, run...)
		}
		if uint64(len(joined)) != o.OriginalSize {
			t.Errorf("object %d reassembles to %d bytes, want %d", o.ID, len(joined), o.OriginalSize)
		}
	}
}

func TestPackObjectsFailsWhenTheObjectCarouselIsFull(t *testing.T) {
	const capacity = MaxModuleSize - HeaderLength
	_, _, err := PackObjects([]PackInput{
		{ID: 1, Class: ClassGenericAsset, Stored: make([]byte, capacity*3)},
	}, 0x0100, 2)
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Errorf("PackObjects = %v, want ErrCapacityExceeded", err)
	}
}

func TestObjectPathsThatEscapeTheOriginAreRejected(t *testing.T) {
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{"index.html", true},
		{"a/b/c.png", true},
		{"", true},
		{"/etc/passwd", false},
		{`\windows\system32`, false},
		{"C:/x", false},
		{"../secret", false},
		{"a/../../b", false},
		{"a\x00b", false},
	} {
		err := ValidatePath(tc.path)
		if (err == nil) != tc.ok {
			t.Errorf("ValidatePath(%q) = %v, want ok=%v", tc.path, err, tc.ok)
		}
	}
}

func TestCodecConfigRoundTripsInConfigIDOrder(t *testing.T) {
	want := []CodecConfig{
		{ConfigID: 2, AssetType: [4]byte{'m', 'p', '4', 'a'}, PacketID: 0xf110, OutputPID: 0x1100, Kind: ConfigAudioSpecific, Flags: ConfigRawExact, EffectiveFrom: 9, AssetID: []byte("audio"), Data: []byte{0x12, 0x10}},
		{ConfigID: 1, AssetType: [4]byte{'h', 'e', 'v', '1'}, PacketID: 0xf100, OutputPID: 0x1011, Kind: ConfigHEVC, Data: []byte{0x40, 0x01}},
	}
	payload, err := EncodeCodecConfigs(want)
	if err != nil {
		t.Fatalf("EncodeCodecConfigs: %v", err)
	}
	got, err := ParseCodecConfigs(payload)
	if err != nil {
		t.Fatalf("ParseCodecConfigs: %v", err)
	}
	if got[0].ConfigID != 1 || got[1].ConfigID != 2 {
		t.Fatalf("entries are not in config id order: %d, %d", got[0].ConfigID, got[1].ConfigID)
	}
	if !reflect.DeepEqual(got[0], want[1]) || !reflect.DeepEqual(got[1], want[0]) {
		t.Errorf("codec configs = %+v", got)
	}
}

func TestAVMapRoundTripsAndRejectsMisorderedEntries(t *testing.T) {
	want := []AVMapEntry{
		{PacketID: 0xf100, OutputPID: 0x1011, AssetType: [4]byte{'h', 'e', 'v', '1'}, MPUSequence: 2, FirstAUOrdinal: 30, AUCount: 30, StartNTP: 200, EndNTP: 300, AssetID: []byte("v")},
		{PacketID: 0xf100, OutputPID: 0x1011, AssetType: [4]byte{'h', 'e', 'v', '1'}, MPUSequence: 1, FirstAUOrdinal: 0, AUCount: 30, Flags: MapRandomAccess, StartNTP: 100, EndNTP: 200, AssetID: []byte("v")},
	}
	payload, err := EncodeAVMap(want)
	if err != nil {
		t.Fatalf("EncodeAVMap: %v", err)
	}
	got, err := ParseAVMap(payload)
	if err != nil {
		t.Fatalf("ParseAVMap: %v", err)
	}
	if got[0].StartNTP != 100 || got[1].StartNTP != 200 {
		t.Fatalf("entries are not in start NTP order: %d, %d", got[0].StartNTP, got[1].StartNTP)
	}
	if !reflect.DeepEqual(got[0], want[1]) {
		t.Errorf("entry = %+v, want %+v", got[0], want[1])
	}

	const entryLen = 2 + 2 + 4 + 4 + 8 + 4 + 2 + 2 + 8 + 8 + 1
	swapped := bytes.Clone(payload)
	copy(swapped[4:4+entryLen], payload[4+entryLen:])
	copy(swapped[4+entryLen:], payload[4:4+entryLen])
	if _, err := ParseAVMap(swapped); err == nil {
		t.Error("ParseAVMap accepted misordered entries")
	}
}

func TestLossEntriesRoundTripAndValidateTheirEnumerations(t *testing.T) {
	var meta Metadata
	meta.AddU16(MetaPacketID, 0xf140)
	want := []LossEntry{{
		Scope: ScopeObject, Reason: ReasonCapacityExceeded, Severity: SeverityUnrecoverable,
		EpochID: 1, LogicalID: 77, StartNTP: 10, EndNTP: 20, InputOffset: 4096,
		ExpectedSize: 100, ReceivedSize: 40, Message: "オブジェクトが入らない", Metadata: meta,
	}}
	payload, err := EncodeLossReport(want)
	if err != nil {
		t.Fatalf("EncodeLossReport: %v", err)
	}
	got, err := ParseLossReport(payload)
	if err != nil {
		t.Fatalf("ParseLossReport: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("loss report = %+v, want %+v", got, want)
	}

	for _, tc := range []struct {
		name  string
		entry LossEntry
	}{
		{"scope", LossEntry{Scope: 9, Reason: ReasonInputMissing, Severity: SeverityPartial}},
		{"reason", LossEntry{Scope: ScopeSegment, Reason: 9, Severity: SeverityPartial}},
		{"severity", LossEntry{Scope: ScopeSegment, Reason: ReasonInputMissing, Severity: 9}},
		{"flags", LossEntry{Scope: ScopeSegment, Reason: ReasonInputMissing, Severity: SeverityPartial, Flags: 1}},
	} {
		if _, err := tc.entry.Encode(); err == nil {
			t.Errorf("Encode accepted an invalid %s", tc.name)
		}
	}
}

func TestTransactionIDCarriesTheProfileTopBits(t *testing.T) {
	for _, tc := range []struct{ in, want uint32 }{
		{0, 0x80000000},
		{1, 0x80000001},
		{0x3fffffff, 0xbfffffff},
		{0x40000000, 0x80000000},
	} {
		if got := TransactionID(tc.in); got != tc.want {
			t.Errorf("TransactionID(%#x) = %#x, want %#x", tc.in, got, tc.want)
		}
	}
}

func TestTheEncodedSizeOfARecordMatchesWhatIsWritten(t *testing.T) {
	var meta Metadata
	meta.AddU16(MetaPacketID, 0xf300)
	meta.AddU32(MetaPacketSequence, 12)
	meta.AddBytes(MetaAssetType, []byte("hev1"))
	meta.AddText(MetaPath, "a/rather/longer/path.html")

	for _, tc := range []struct {
		name    string
		records []Record
	}{
		{"none", nil},
		{"one bare record", []Record{{Kind: RecordRawSignalling}}},
		{"one full record", []Record{{Kind: RecordCAData, Metadata: meta, Payload: make([]byte, 1500)}}},
		{"several", []Record{
			{Kind: RecordRawSignalling, Order: 0, Metadata: meta, Payload: make([]byte, 17)},
			{Kind: RecordGenericTimedData, Order: 1, Payload: make([]byte, 4096)},
			{Kind: RecordTimelineAnchor, Order: 2, Metadata: meta},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := EncodeSegment(tc.records)
			if err != nil {
				t.Fatalf("EncodeSegment: %v", err)
			}
			if got := SegmentSize(tc.records); got != len(b) {
				t.Errorf("SegmentSize = %d, encoded %d bytes", got, len(b))
			}
		})
	}
}

func TestAWindowFullOfRecordsSplitsIntoParts(t *testing.T) {
	r := newTestRecorder(t)
	r.Observe(testNTPBase)
	const records = 2000
	payload := make([]byte, 1400)
	for i := range records {
		var meta Metadata
		meta.AddU16(MetaPacketID, 0xf300)
		meta.AddU32(MetaPacketSequence, uint32(i))
		r.AddRecord(RecordGenericTimedData, RecordRawExact, ntpAfter(10), meta, payload)
	}
	r.Observe(ntpAfter(1200))
	if err := r.Emit(0, func(uint16, []byte) error { return nil }); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	parts := 0
	var carried int
	for i := range MaxSegmentParts {
		m := r.realtime.modules[TimedModuleID(0, i)]
		if m == nil {
			continue
		}
		parts++
		_, payload, err := ParseModule(m.stored)
		if err != nil {
			t.Fatalf("ParseModule(part %d): %v", i, err)
		}
		recs, err := ParseSegment(payload)
		if err != nil {
			t.Fatalf("ParseSegment(part %d): %v", i, err)
		}
		carried += len(recs)
		if len(m.stored) > MaxModuleSize {
			t.Errorf("part %d is %d bytes, over the module limit", i, len(m.stored))
		}
	}
	if parts < 2 {
		t.Fatalf("the window was carried in %d part(s); it should not have fitted in one", parts)
	}
	if carried != records {
		t.Errorf("%d records reached the carousel, want %d", carried, records)
	}
}
