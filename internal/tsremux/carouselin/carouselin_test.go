// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package carouselin

import (
	"crypto/sha256"
	"testing"

	"mmt2ts/internal/preservation"
)

const testServiceID = 0x1234

func pushModule(t *testing.T, r *Reader, pid uint16, downloadID uint32, moduleID uint16, h preservation.Header, payload []byte) {
	pushModuleVersion(t, r, pid, downloadID, moduleID, 0, h, payload)
}

func pushModuleVersion(t *testing.T, r *Reader, pid uint16, downloadID uint32, moduleID uint16, version byte, h preservation.Header, payload []byte) {
	t.Helper()
	module, err := preservation.BuildModule(h, payload)
	if err != nil {
		t.Fatalf("BuildModule: %v", err)
	}
	entry := preservation.ModuleEntry{ID: moduleID, Size: uint32(len(module)), Version: version}
	dii, err := preservation.BuildDII(downloadID, 1, 1_000_000, []preservation.ModuleEntry{entry})
	if err != nil {
		t.Fatalf("BuildDII: %v", err)
	}
	r.Push(pid, dii)
	blocks, err := preservation.SplitModule(downloadID, entry, module)
	if err != nil {
		t.Fatalf("SplitModule: %v", err)
	}
	for _, b := range blocks {
		r.Push(pid, b)
	}
}

func pushObjectGeneration(t *testing.T, r *Reader, downloadID uint32, generation uint32, version byte, object []byte) {
	t.Helper()
	pushModuleVersion(t, r, 0x1d01, downloadID, 0x0100, version,
		preservation.Header{Kind: preservation.KindStaticObject}, object)
	sha := sha256.Sum256(object)
	m := &preservation.Manifest{Generation: generation, UpdateNumber: generation,
		Objects: []preservation.ManifestObject{{ID: 1, Class: preservation.ClassGenericAsset,
			Path: "item.bin", OriginalSize: uint64(len(object)), OriginalSHA256: sha,
			Parts: []preservation.ObjectPart{{ModuleID: 0x0100, ModuleVersion: version,
				PartNumber: 0, StoredLength: uint32(len(object)), StoredSHA256: sha}}}}}
	payload, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pushModuleVersion(t, r, 0x1d01, downloadID, 0x0001, version,
		preservation.Header{Kind: preservation.KindObjectManifest, Flags: preservation.FlagCommit}, payload)
}

func TestBootstrapRoundTrip(t *testing.T) {
	r := New()
	downloadID := uint32(downloadRealtime)<<16 | testServiceID
	b := &preservation.Bootstrap{
		ServiceID: testServiceID, TransportStreamID: 1, OriginalNetworkID: 1,
		EpochID: 1, SegmentDurationMS: 500, LatestComplete: preservation.NoSegment,
		Entries: []preservation.DirectoryEntry{
			{Role: preservation.RoleRealtime, ModuleID: 0x0300, Kind: preservation.KindCodecConfig, PartCount: 1},
		},
	}
	payload, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pushModule(t, r, 0x1d00, downloadID, 0x0000, preservation.Header{Kind: preservation.KindBootstrapManifest}, payload)

	if r.Realtime.Bootstrap == nil {
		t.Fatal("bootstrap not decoded")
	}
	if r.Realtime.Bootstrap.ServiceID != testServiceID {
		t.Errorf("ServiceID = %#04x, want %#04x", r.Realtime.Bootstrap.ServiceID, testServiceID)
	}
	if len(r.Problems) > 0 {
		t.Errorf("unexpected problems: %v", r.Problems)
	}
}

func TestSegmentRoundTrip(t *testing.T) {
	r := New()
	downloadID := uint32(downloadRealtime)<<16 | testServiceID
	records := []preservation.Record{
		{Kind: preservation.RecordRawSignalling, Order: 0, SourceNTP: 100, Payload: []byte("PA message bytes")},
		{Kind: preservation.RecordTimelineAnchor, Order: 1, SourceNTP: 100,
			Payload: preservation.TimelineAnchor{OutputPID: 0x1011, ClockKind: preservation.ClockPresentation, PTS90k: 900, SourceNTP: 100, EpochID: 1}.Encode()},
	}
	payload, err := preservation.EncodeSegment(records)
	if err != nil {
		t.Fatal(err)
	}
	pushModule(t, r, 0x1d00, downloadID, 0x0100, preservation.Header{Kind: preservation.KindTimedSegment, LogicalID: 7}, payload)

	got, ok := r.Realtime.Segments[7]
	if !ok {
		t.Fatal("segment 7 not decoded")
	}
	if len(got) != 2 || got[0].Kind != preservation.RecordRawSignalling {
		t.Fatalf("segment records = %+v", got)
	}
	if seqs := r.Realtime.SegmentSequences(); len(seqs) != 1 || seqs[0] != 7 {
		t.Errorf("SegmentSequences = %v", seqs)
	}
}

func TestAVMapAndCodecConfigAndLossRoundTrip(t *testing.T) {
	r := New()
	downloadID := uint32(downloadRealtime)<<16 | testServiceID

	av := []preservation.AVMapEntry{
		{PacketID: 1, OutputPID: 0x1011, MPUSequence: 1, FirstAUOrdinal: 0, AUCount: 30, StartNTP: 0, EndNTP: 1000},
	}
	avPayload, err := preservation.EncodeAVMap(av)
	if err != nil {
		t.Fatal(err)
	}
	pushModule(t, r, 0x1d00, downloadID, 0x0301, preservation.Header{Kind: preservation.KindAVMPUMap}, avPayload)
	if len(r.Realtime.AVMap) != 1 || r.Realtime.AVMap[0].OutputPID != 0x1011 {
		t.Fatalf("AVMap = %+v", r.Realtime.AVMap)
	}

	cfgs := []preservation.CodecConfig{
		{ConfigID: 1, Kind: preservation.ConfigHEVC, Data: []byte{0x01, 0x02}},
	}
	cfgPayload, err := preservation.EncodeCodecConfigs(cfgs)
	if err != nil {
		t.Fatal(err)
	}
	pushModule(t, r, 0x1d00, downloadID, 0x0300, preservation.Header{Kind: preservation.KindCodecConfig}, cfgPayload)
	if len(r.Realtime.CodecConfigs) != 1 || r.Realtime.CodecConfigs[0].Kind != preservation.ConfigHEVC {
		t.Fatalf("CodecConfigs = %+v", r.Realtime.CodecConfigs)
	}

	loss := []preservation.LossEntry{
		{Scope: preservation.ScopeAVMPU, Reason: preservation.ReasonInputMissing, Severity: preservation.SeverityPartial, LogicalID: 42},
	}
	lossPayload, err := preservation.EncodeLossReport(loss)
	if err != nil {
		t.Fatal(err)
	}
	pushModule(t, r, 0x1d00, downloadID, 0x0200, preservation.Header{Kind: preservation.KindLossReport, LogicalID: 0}, lossPayload)
	if len(r.Realtime.LossEntries) != 1 || r.Realtime.LossEntries[0].LogicalID != 42 {
		t.Fatalf("LossEntries = %+v", r.Realtime.LossEntries)
	}
}

func TestObjectCarouselRoundTrip(t *testing.T) {
	r := New()
	downloadID := uint32(downloadObject)<<16 | testServiceID

	object := []byte("hello, this is a static object payload")
	pushModule(t, r, 0x1d01, downloadID, 0x0100, preservation.Header{Kind: preservation.KindStaticObject}, object)

	sha := sha256.Sum256(object)
	m := &preservation.Manifest{
		Generation: 1, UpdateNumber: 1,
		Objects: []preservation.ManifestObject{
			{
				ID: 1, Class: preservation.ClassGenericAsset, Path: "item.bin",
				OriginalSize: uint64(len(object)), OriginalSHA256: sha,
				Parts: []preservation.ObjectPart{
					{ModuleID: 0x0100, PartNumber: 0, Offset: 0, StoredLength: uint32(len(object)), StoredSHA256: sha},
				},
			},
		},
	}
	manifestPayload, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pushModule(t, r, 0x1d01, downloadID, 0x0001, preservation.Header{Kind: preservation.KindObjectManifest, Flags: preservation.FlagCommit}, manifestPayload)

	if r.Object.Manifest == nil {
		t.Fatal("manifest not decoded")
	}
	if got := r.Object.Objects[0x0100]; string(got) != string(object) {
		t.Fatalf("object bytes = %q, want %q", got, object)
	}
}

func TestCommittedObjectGenerationsRemainResolvable(t *testing.T) {
	r := New()
	downloadID := uint32(downloadObject)<<16 | testServiceID
	pushObjectGeneration(t, r, downloadID, 1, 0, []byte("old generation"))
	pushObjectGeneration(t, r, downloadID, 2, 1, []byte("new generation"))

	if got := len(r.Object.Snapshots); got != 2 {
		t.Fatalf("snapshots = %d, want 2", got)
	}
	if got := string(r.Object.Snapshots[0].Objects[1].Data); got != "old generation" {
		t.Fatalf("old snapshot = %q", got)
	}
	if got := string(r.Object.Snapshots[1].Objects[1].Data); got != "new generation" {
		t.Fatalf("new snapshot = %q", got)
	}
}
