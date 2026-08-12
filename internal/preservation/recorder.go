// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
)

const (
	realtimeDownloadPrefix = 0x4d520000
	objectDownloadPrefix   = 0x4d530000
)

const (
	DefaultSegmentDurationMS = 500
	DefaultLeadTimeMS        = 2000
	DefaultPlayoutLimitMS    = 3000
	minSegmentDurationMS     = 250
	maxSegmentDurationMS     = 1000

	retainedSegments = timedRingSegments
)

func (r *Recorder) repeatWindow() uint64 {
	limit := uint64(r.cfg.PlayoutLimitMS)
	n := (limit+uint64(r.cfg.SegmentDurationMS)-1)/uint64(r.cfg.SegmentDurationMS) + 1
	return min(max(n, 3), timedRingSegments)
}

type Config struct {
	ServiceID         uint16
	TransportStreamID uint16
	OriginalNetworkID uint16

	RealtimePID uint16
	ObjectPID   uint16
	RealtimeTag byte
	ObjectTag   byte

	SegmentDurationMS uint32
	LeadTimeMS        uint16
	PlayoutLimitMS    uint16
}

type Stats struct {
	Segments          uint64
	Records           uint64
	Objects           int
	ObjectBytes       int
	AVMapEntries      int
	CodecConfigs      int
	LossEntries       uint64
	Commits           uint64
	RealtimeDII       uint64
	RealtimeDDB       uint64
	ObjectDII         uint64
	ObjectDDB         uint64
	CarouselBytes     uint64
	RealtimeModule    int
	ObjectModule      int
	SegmentDurationMS uint32
	ShortSegments     bool
	BulkSegments      uint64
}

type segment struct {
	sequence uint64
	startNTP uint64
	records  []Record
	bulk     int
}

type Recorder struct {
	cfg      Config
	realtime *Carousel
	object   *Carousel

	epochID    uint32
	epochBase  uint64
	haveEpoch  bool
	latestNTP  uint64
	nextSeq    uint64
	open       map[uint64]*segment
	pending    []Update
	installErr error

	latestComplete uint64
	haveComplete   bool

	avmap      []AVMapEntry
	avmapDirty bool
	lastAVMap  int64
	codec      map[uint64]CodecConfig
	codecDirty bool

	losses  []LossEntry
	lossSeq uint64

	objects      map[uint64]PackInput
	objectBytes  int
	objectsDirty bool
	generation   uint32
	updateNumber uint32
	lastCommit   int64

	rtBootstrap     []byte
	objBootstrap    []byte
	rtRevision      uint64
	objRevision     uint64
	bootstrapLatest uint64
	haveBootstraps  bool

	stats Stats
}

func NewRecorder(cfg Config) (*Recorder, error) {
	if cfg.SegmentDurationMS == 0 {
		cfg.SegmentDurationMS = DefaultSegmentDurationMS
	}
	if cfg.SegmentDurationMS < minSegmentDurationMS || cfg.SegmentDurationMS > maxSegmentDurationMS {
		return nil, fmt.Errorf("preservation: segment duration %d ms is outside %d–%d",
			cfg.SegmentDurationMS, minSegmentDurationMS, maxSegmentDurationMS)
	}
	if cfg.LeadTimeMS == 0 {
		cfg.LeadTimeMS = DefaultLeadTimeMS
	}
	if cfg.PlayoutLimitMS == 0 {
		cfg.PlayoutLimitMS = DefaultPlayoutLimitMS
	}
	r := &Recorder{
		cfg:     cfg,
		open:    make(map[uint64]*segment),
		codec:   make(map[uint64]CodecConfig),
		objects: make(map[uint64]PackInput),
		realtime: NewCarousel(RoleRealtime, cfg.RealtimePID, cfg.RealtimeTag,
			realtimeDownloadPrefix|uint32(cfg.ServiceID)),
		object: NewCarousel(RoleObject, cfg.ObjectPID, cfg.ObjectTag,
			objectDownloadPrefix|uint32(cfg.ServiceID)),
		lastCommit: -1 << 62,
		lastAVMap:  -1 << 62,
	}
	return r, nil
}

func (r *Recorder) PIDs() (realtimePID, objectPID uint16, realtimeTag, objectTag byte) {
	return r.cfg.RealtimePID, r.cfg.ObjectPID, r.cfg.RealtimeTag, r.cfg.ObjectTag
}

func ntpMS(ntp uint64) uint64 {
	return (ntp>>32)*1000 + ((ntp&0xffffffff)*1000+1<<31)>>32
}

func msToNTP(ms uint64) uint64 {
	return (ms/1000)<<32 | ((ms%1000)<<32)/1000
}

func (r *Recorder) sequenceOf(ntp uint64) uint64 {
	if ntp <= r.epochBase {
		return 0
	}
	return (ntpMS(ntp) - ntpMS(r.epochBase)) / uint64(r.cfg.SegmentDurationMS)
}

func (r *Recorder) segmentStart(seq uint64) uint64 {
	return r.epochBase + msToNTP(seq*uint64(r.cfg.SegmentDurationMS))
}

func (r *Recorder) Observe(ntp uint64) {
	if ntp == 0 {
		return
	}
	if !r.haveEpoch {
		r.epochBase, r.haveEpoch, r.latestNTP = ntp, true, ntp
		return
	}
	if ntp > r.latestNTP {
		r.latestNTP = ntp
	}
	r.closeElapsed()
}

func (r *Recorder) NewEpoch(ntp uint64) {
	r.flushOpen()
	r.epochID++
	r.epochBase, r.haveEpoch, r.latestNTP = ntp, true, ntp
	r.nextSeq = 0
	r.haveComplete = false
}

func (r *Recorder) UseShortSegments() {
	if r.nextSeq != 0 || r.cfg.SegmentDurationMS <= minSegmentDurationMS {
		return
	}
	r.cfg.SegmentDurationMS = minSegmentDurationMS
	for seq := range r.open {
		delete(r.open, seq)
	}
	r.stats.ShortSegments = true
}

func (r *Recorder) EpochID() uint32 { return r.epochID }

func (r *Recorder) closeElapsed() {
	r.closeUpTo(r.sequenceOf(r.latestNTP))
}

func (r *Recorder) flushOpen() {
	r.closeUpTo(^uint64(0))
}

func (r *Recorder) closeUpTo(limit uint64) {
	due := make([]uint64, 0, len(r.open))
	for seq := range r.open {
		if seq < limit {
			due = append(due, seq)
		}
	}
	slices.Sort(due)
	for _, seq := range due {
		r.closeSegment(r.open[seq])
		delete(r.open, seq)
	}
}

func (r *Recorder) AddRecord(kind RecordKind, flags byte, sourceNTP uint64, meta Metadata, payload []byte) {
	if !r.haveEpoch {
		if sourceNTP == 0 {
			return
		}
		r.epochBase, r.haveEpoch, r.latestNTP = sourceNTP, true, sourceNTP
	}
	if sourceNTP == 0 {
		sourceNTP = r.latestNTP
	}
	seq := r.sequenceOf(sourceNTP)
	s := r.open[seq]
	if s == nil {
		if seq < r.nextSeq {
			s = r.oldestOpen()
		}
		if s == nil {
			s = &segment{sequence: seq, startNTP: r.segmentStart(seq)}
			r.open[seq] = s
		}
	}
	rec := Record{
		Kind: kind, Flags: flags, Order: uint32(len(s.records)),
		SourceNTP: sourceNTP, Metadata: meta, Payload: payload,
	}
	if kind == RecordGenericTimedData {
		s.bulk += rec.EncodedSize()
	}
	s.records = append(s.records, rec)
	r.stats.Records++
}

func (r *Recorder) closeSegment(s *segment) {
	if len(s.records) == 0 {
		return
	}
	parts, dropped, err := r.splitSegment(s)
	if err != nil {
		r.note(err)
		return
	}
	if dropped > 0 {
		r.AddLoss(LossEntry{
			Scope: ScopeSegment, Reason: ReasonCapacityExceeded, Severity: SeverityUnrecoverable,
			LogicalID: s.sequence, StartNTP: s.startNTP,
			EndNTP:       s.startNTP + msToNTP(uint64(r.cfg.SegmentDurationMS)),
			ExpectedSize: uint64(SegmentSize(s.records)),
			ReceivedSize: uint64(SegmentSize(s.records[:len(s.records)-dropped])),
			Message: fmt.Sprintf("%d of %d records did not fit the %d ms window",
				dropped, len(s.records), r.cfg.SegmentDurationMS),
		})
	}
	once := s.bulk*2 > SegmentSize(s.records)
	if once {
		r.stats.BulkSegments++
	}
	for i, payload := range parts {
		r.pending = append(r.pending, Update{
			ID:            TimedModuleID(s.sequence, i),
			Kind:          KindTimedSegment,
			EpochID:       r.epochID,
			LogicalID:     s.sequence,
			StartNTP:      s.startNTP,
			DurationMS:    r.cfg.SegmentDurationMS,
			Payload:       payload,
			Required:      true,
			PartNumber:    uint16(i),
			PartCount:     uint16(len(parts)),
			ValidFrom:     s.startNTP,
			ValidUntil:    s.startNTP + msToNTP(uint64(r.cfg.SegmentDurationMS)),
			Interval:      int64(r.cfg.PlayoutLimitMS) * 90,
			RetryCount:    1,
			RetryInterval: SegmentInterval,
			Once:          once,
			Priority:      PriorityContent,
		})
	}
	for i := len(parts); i < MaxSegmentParts; i++ {
		r.pending = append(r.pending, Update{ID: TimedModuleID(s.sequence, i), Kind: 0})
	}
	if window := r.repeatWindow(); s.sequence >= window {
		old := s.sequence - window
		for i := range MaxSegmentParts {
			r.pending = append(r.pending, Update{ID: TimedModuleID(old, i), Kind: 0})
		}
	}
	r.latestComplete, r.haveComplete = s.sequence, true
	r.nextSeq = s.sequence + 1
	r.stats.Segments++
	r.trimAVMap()
}

func (r *Recorder) splitSegment(s *segment) (parts [][]byte, dropped int, err error) {
	const capacity = MaxModuleSize - HeaderLength
	if SegmentSize(s.records) <= capacity {
		whole, err := EncodeSegment(s.records)
		if err != nil {
			return nil, 0, err
		}
		return [][]byte{whole}, 0, nil
	}
	start := 0
	for start < len(s.records) {
		size := segmentHeaderLength
		end := start
		for end < len(s.records) {
			n := s.records[end].EncodedSize()
			if end > start && size+n > capacity {
				break
			}
			size += n
			end++
		}
		if size > capacity {
			return nil, 0, fmt.Errorf("%w: segment %d holds a record larger than one module",
				ErrCapacityExceeded, s.sequence)
		}
		b, err := EncodeSegment(renumber(s.records[start:end]))
		if err != nil {
			return nil, 0, err
		}
		parts = append(parts, b)
		start = end
		if len(parts) == MaxSegmentParts && start < len(s.records) {
			return parts, len(s.records) - start, nil
		}
	}
	return parts, 0, nil
}

func renumber(in []Record) []Record {
	out := slices.Clone(in)
	for i := range out {
		out[i].Order = uint32(i)
	}
	return out
}

func (r *Recorder) AddAVMapEntry(e AVMapEntry) {
	r.avmap = append(r.avmap, e)
	r.avmapDirty = true
}

func (r *Recorder) trimAVMap() {
	if !r.haveComplete || r.latestComplete < retainedSegments {
		return
	}
	oldest := r.segmentStart(r.latestComplete - retainedSegments)
	kept := r.avmap[:0]
	for _, e := range r.avmap {
		if e.EndNTP == 0 || e.EndNTP >= oldest {
			kept = append(kept, e)
		}
	}
	if len(kept) != len(r.avmap) {
		r.avmapDirty = true
	}
	r.avmap = kept
}

func (r *Recorder) SetCodecConfig(c CodecConfig) {
	c.SHA256 = sha256.Sum256(c.Data)
	if old, ok := r.codec[c.ConfigID]; ok && old.SHA256 == c.SHA256 && old.OutputPID == c.OutputPID {
		return
	}
	r.codec[c.ConfigID] = c
	r.codecDirty = true
}

func (r *Recorder) AddLoss(e LossEntry) {
	e.EpochID = r.epochID
	r.losses = append(r.losses, e)
	r.stats.LossEntries++
}

func (r *Recorder) AddObject(o PackInput) error {
	if err := ValidatePath(o.Path); err != nil {
		return err
	}
	if old, ok := r.objects[o.ID]; ok {
		o.storedDigest()
		if old.haveStored && old.StoredSHA256 == o.StoredSHA256 {
			return nil
		}
		r.objectBytes -= len(old.Stored)
	}
	if err := r.describeOriginal(&o); err != nil {
		return err
	}
	const budget = MaxObjectModules * (MaxModuleSize - HeaderLength)
	if r.objectBytes+len(o.Stored) > budget {
		r.AddLoss(LossEntry{
			Scope: ScopeObject, Reason: ReasonCapacityExceeded, Severity: SeverityUnrecoverable,
			LogicalID: o.ID, ExpectedSize: o.OriginalSize,
			Message: "object carousel is full", Metadata: metaForPath(o.Path),
		})
		return fmt.Errorf("%w: object set would reach %d bytes, the object carousel holds %d",
			ErrCapacityExceeded, r.objectBytes+len(o.Stored), budget)
	}
	r.objects[o.ID] = o
	r.objectBytes += len(o.Stored)
	r.objectsDirty = true
	return nil
}

func metaForPath(path string) Metadata {
	var m Metadata
	if path != "" {
		m.AddText(MetaPath, path)
	}
	return m
}

func (r *Recorder) note(err error) {
	if r.installErr == nil {
		r.installErr = err
	}
}

func (r *Recorder) describeOriginal(o *PackInput) error {
	switch o.Compression {
	case CompressionNone:
		o.storedDigest()
		o.OriginalSHA256 = o.StoredSHA256
		o.OriginalSize = uint64(len(o.Stored))
		return nil
	case CompressionZlib:
		size, sum, err := expandedDigest(o.Stored)
		if err != nil {
			o.Flags |= ObjectIncomplete
			o.OriginalSHA256 = [32]byte{}
			r.AddLoss(LossEntry{
				Scope: ScopeObject, Reason: ReasonInvalidSyntax, Severity: SeverityPartial,
				LogicalID: o.ID, ReceivedSize: uint64(len(o.Stored)),
				Message:  "compressed object could not be expanded: " + err.Error(),
				Metadata: metaForPath(o.Path),
			})
			return nil
		}
		if o.OriginalSize != 0 && o.OriginalSize != size {
			r.AddLoss(LossEntry{
				Scope: ScopeObject, Reason: ReasonInvalidSyntax, Severity: SeverityInformational,
				LogicalID: o.ID, ExpectedSize: o.OriginalSize, ReceivedSize: size,
				Message:  "declared uncompressed size differs from the expanded bytes",
				Metadata: metaForPath(o.Path),
			})
		}
		o.OriginalSize, o.OriginalSHA256 = size, sum
		return nil
	}
	return fmt.Errorf("preservation: object %d uses compression %d", o.ID, o.Compression)
}

func expandedDigest(stored []byte) (uint64, [32]byte, error) {
	var sum [32]byte
	zr, err := zlib.NewReader(bytes.NewReader(stored))
	if err != nil {
		return 0, sum, err
	}
	defer zr.Close()
	h := sha256.New()
	n, err := io.Copy(h, zr)
	if err != nil {
		return 0, sum, err
	}
	h.Sum(sum[:0])
	return uint64(n), sum, nil
}

func (r *Recorder) SetService(serviceID, transportStreamID, originalNetworkID uint16) {
	if r.realtime.ModuleCount() > 0 || r.object.ModuleCount() > 0 {
		return
	}
	if serviceID != 0 {
		r.cfg.ServiceID = serviceID
		r.realtime.DownloadID = realtimeDownloadPrefix | uint32(serviceID)
		r.object.DownloadID = objectDownloadPrefix | uint32(serviceID)
	}
	if transportStreamID != 0 {
		r.cfg.TransportStreamID = transportStreamID
	}
	if originalNetworkID != 0 {
		r.cfg.OriginalNetworkID = originalNetworkID
	}
}
