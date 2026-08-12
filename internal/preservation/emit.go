// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"errors"
	"fmt"
)

const commitInterval = 5 * 90000

func (r *Recorder) oldestOpen() *segment {
	var out *segment
	for _, s := range r.open {
		if out == nil || s.sequence < out.sequence {
			out = s
		}
	}
	return out
}

func (r *Recorder) Emit(now int64, write func(pid uint16, section []byte) error) error {
	if err := r.install(now); err != nil {
		return err
	}
	if err := r.realtime.Emit(now, write); err != nil {
		return err
	}
	return r.object.Emit(now, write)
}

func (r *Recorder) install(now int64) error {
	if r.installErr != nil {
		return r.installErr
	}
	for _, u := range r.pending {
		if u.Kind == 0 {
			r.realtime.Remove(u.ID, now)
			continue
		}
		if err := r.realtime.Set(u, now); err != nil {
			return err
		}
	}
	r.pending = r.pending[:0]

	if err := r.installLosses(now); err != nil {
		return err
	}
	if r.codecDirty {
		if err := r.installCodecConfig(now); err != nil {
			return err
		}
	}
	if r.avmapDirty && now-r.lastAVMap >= SegmentInterval {
		if err := r.installAVMap(now); err != nil {
			return err
		}
		r.lastAVMap = now
	}
	if r.objectsDirty && now-r.lastCommit >= commitInterval {
		if err := r.commitObjects(now); err != nil {
			return err
		}
	}
	return r.refreshBootstraps(now)
}

func (r *Recorder) installLosses(now int64) error {
	if len(r.losses) == 0 {
		return nil
	}
	payload, err := EncodeLossReport(r.losses)
	if err != nil {
		return err
	}
	id := LossModuleID(r.lossSeq)
	err = r.realtime.Set(Update{
		ID: id, Kind: KindLossReport, EpochID: r.epochID, LogicalID: r.lossSeq,
		Payload: payload, Interval: ObjectInterval, Priority: PriorityContent,
	}, now)
	if err != nil {
		return err
	}
	r.lossSeq++
	r.losses = r.losses[:0]
	return nil
}

func (r *Recorder) installCodecConfig(now int64) error {
	entries := make([]CodecConfig, 0, len(r.codec))
	for _, c := range r.codec {
		entries = append(entries, c)
	}
	payload, err := EncodeCodecConfigs(entries)
	if err != nil {
		return err
	}
	r.codecDirty = false
	return r.realtime.Set(Update{
		ID: ModuleIDCodecConfig, Kind: KindCodecConfig, EpochID: r.epochID,
		LogicalID: uint64(r.generation), Payload: payload, Required: true,
		Interval: DIIInterval, Priority: PriorityContent,
	}, now)
}

func (r *Recorder) installAVMap(now int64) error {
	payload, err := EncodeAVMap(r.avmap)
	if err != nil {
		return err
	}
	r.avmapDirty = false
	return r.realtime.Set(Update{
		ID: ModuleIDAVMap, Kind: KindAVMPUMap, EpochID: r.epochID,
		LogicalID: r.latestComplete, Payload: payload,
		Interval: SegmentInterval, Priority: PriorityContent,
	}, now)
}

func (r *Recorder) commitObjects(now int64) error {
	inputs := make([]PackInput, 0, len(r.objects))
	for _, o := range r.objects {
		inputs = append(inputs, o)
	}
	modules, manifest, err := PackObjects(inputs, moduleIDObjectBase, MaxObjectModules)
	if err != nil {
		if errors.Is(err, ErrCapacityExceeded) {
			r.AddLoss(LossEntry{
				Scope: ScopeObject, Reason: ReasonCapacityExceeded, Severity: SeverityUnrecoverable,
				Message: err.Error(),
			})
		}
		return err
	}

	r.updateNumber++
	manifest.Generation, manifest.UpdateNumber = r.generation, r.updateNumber

	for id := moduleIDObjectBase + uint16(len(modules)); r.object.Has(id); id++ {
		r.object.Remove(id, now)
	}
	for _, pm := range modules {
		err := r.object.Set(Update{
			ID: pm.ID, Kind: KindStaticObject, EpochID: ObjectEpoch,
			LogicalID: uint64(pm.ID), Payload: pm.Payload, Required: true,
			SHA256: pm.SHA256, HaveSHA256: true,
			Interval: ObjectInterval, Priority: PriorityContent,
		}, now)
		if err != nil {
			return err
		}
		manifest.SetModuleVersion(pm.ID, r.object.modules[pm.ID].version)
	}

	payload, err := manifest.Encode()
	if err != nil {
		return err
	}
	err = r.object.Set(Update{
		ID: ModuleIDObjectManifest, Kind: KindObjectManifest, Flags: FlagCommit,
		EpochID: ObjectEpoch, LogicalID: uint64(r.generation)<<32 | uint64(r.updateNumber),
		Payload: payload, Required: true, Interval: ObjectInterval, Priority: PriorityManifest,
	}, now)
	if err != nil {
		return err
	}
	r.objectsDirty = false
	r.lastCommit = now
	r.stats.Commits++
	return nil
}

func (r *Recorder) refreshBootstraps(now int64) error {
	latest := r.latestComplete
	if !r.haveComplete {
		latest = NoSegment
	}
	if r.haveBootstraps && r.realtime.Revision() == r.rtRevision &&
		r.object.Revision() == r.objRevision && latest == r.bootstrapLatest {
		return nil
	}
	defer func() {
		r.haveBootstraps = true
		r.rtRevision, r.objRevision = r.realtime.Revision(), r.object.Revision()
		r.bootstrapLatest = latest
	}()

	rt := &Bootstrap{
		ServiceID: r.cfg.ServiceID, TransportStreamID: r.cfg.TransportStreamID,
		OriginalNetworkID: r.cfg.OriginalNetworkID,
		EpochID:           r.epochID, Generation: r.generation, UpdateNumber: r.updateNumber,
		SegmentDurationMS: r.cfg.SegmentDurationMS,
		LeadTimeMS:        r.cfg.LeadTimeMS, PlayoutLimitMS: r.cfg.PlayoutLimitMS,
		RealtimeDownload: r.realtime.DownloadID, ObjectDownload: r.object.DownloadID,
		LatestComplete: NoSegment,
		Entries:        r.realtime.Entries(),
	}
	if r.haveComplete {
		rt.LatestComplete = r.latestComplete
	}
	payload, err := rt.Encode()
	if err != nil {
		return err
	}
	if string(payload) != string(r.rtBootstrap) {
		r.rtBootstrap = payload
		err := r.realtime.Set(Update{
			ID: ModuleIDBootstrap, Kind: KindBootstrapManifest, EpochID: r.epochID,
			Payload: payload, Required: true, Interval: DIIInterval, Priority: PriorityBootstrap,
		}, now)
		if err != nil {
			return err
		}
	}

	obj := &Bootstrap{
		ServiceID: r.cfg.ServiceID, TransportStreamID: r.cfg.TransportStreamID,
		OriginalNetworkID: r.cfg.OriginalNetworkID,
		EpochID:           ObjectEpoch, Generation: r.generation, UpdateNumber: r.updateNumber,
		SegmentDurationMS: r.cfg.SegmentDurationMS,
		LeadTimeMS:        r.cfg.LeadTimeMS, PlayoutLimitMS: r.cfg.PlayoutLimitMS,
		RealtimeDownload: r.realtime.DownloadID, ObjectDownload: r.object.DownloadID,
		LatestComplete: NoSegment,
		Entries:        r.object.Entries(),
	}
	payload, err = obj.Encode()
	if err != nil {
		return err
	}
	if len(obj.Entries) > 0 && string(payload) != string(r.objBootstrap) {
		r.objBootstrap = payload
		return r.object.Set(Update{
			ID: ModuleIDBootstrap, Kind: KindBootstrapManifest, EpochID: ObjectEpoch,
			Payload: payload, Required: true, Interval: DIIInterval, Priority: PriorityBootstrap,
		}, now)
	}
	return nil
}

func (r *Recorder) Finish(now int64) error {
	r.flushOpen()
	if r.installErr != nil {
		return r.installErr
	}
	if len(r.objects) > 0 {
		r.objectsDirty = true
		r.lastCommit = -1 << 62
	}
	r.lastAVMap = -1 << 62
	return r.install(now)
}

func (r *Recorder) Stats() Stats {
	s := r.stats
	s.SegmentDurationMS = r.cfg.SegmentDurationMS
	s.Objects = len(r.objects)
	s.ObjectBytes = r.objectBytes
	s.AVMapEntries = len(r.avmap)
	s.CodecConfigs = len(r.codec)
	s.RealtimeDII, s.RealtimeDDB = r.realtime.DIISections, r.realtime.DDBSections
	s.ObjectDII, s.ObjectDDB = r.object.DIISections, r.object.DDBSections
	s.CarouselBytes = r.realtime.Bytes + r.object.Bytes
	s.RealtimeModule = r.realtime.ModuleCount()
	s.ObjectModule = r.object.ModuleCount()
	return s
}

func (r *Recorder) Describe() string {
	return fmt.Sprintf("realtime pid %#04x download %#08x, object pid %#04x download %#08x",
		r.cfg.RealtimePID, r.realtime.DownloadID, r.cfg.ObjectPID, r.object.DownloadID)
}
