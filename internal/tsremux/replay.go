// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"container/heap"
	"fmt"
	"io"
	"time"

	"mmt2ts/internal/preservation"
	"mmt2ts/internal/tsdemux"
	"mmt2ts/internal/tsremux/carouselin"
	"mmt2ts/internal/tsremux/mmtwrite"
	"mmt2ts/internal/tsremux/tlvwrite"
)

// 保存情報は元の時刻より遅れて TS に現れる。timed segment は閉じてから、AV 対応表は
// MPU が閉じてから、静的 object は commit（5 秒周期）とカルーセルの一周（5 秒）の後。
const DefaultWindow = 20 * time.Second

// activation が窓の外へ出たあとも、object はこれだけ待つ。
const objectGrace = uint64(60) << 32

type Options struct {
	Window time.Duration // 0 なら DefaultWindow
}

// 出力 PID ごとの access unit。AV 対応表は通し番号で指すので、書いた分を前から捨てる。
type auQueue struct {
	base uint64
	pes  []tsdemux.PES
}

func (q *auQueue) push(p tsdemux.PES) { q.pes = append(q.pes, p) }

func (q *auQueue) end() uint64 { return q.base + uint64(len(q.pes)) }

func (q *auQueue) payloads(start, end uint64) [][]byte {
	out := make([][]byte, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, q.pes[i-q.base].Payload)
	}
	return out
}

func (q *auQueue) dropBefore(ordinal uint64) {
	if ordinal <= q.base {
		return
	}
	n := min(int(ordinal-q.base), len(q.pes))
	for i := range n {
		q.pes[i] = tsdemux.PES{}
	}
	q.pes = q.pes[n:]
	q.base += uint64(n)
	if cap(q.pes) > 64 && len(q.pes) < cap(q.pes)/2 {
		q.pes = append([]tsdemux.PES(nil), q.pes...)
	}
}

type replayEvent struct {
	ntp      uint64
	priority byte
	order    uint64
	// object が未着なら false。final なら書けるものだけ書いて true。
	write func(final bool) (bool, error)
}

type eventHeap []*replayEvent

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	a, b := h[i], h[j]
	if a.ntp != b.ntp {
		return a.ntp < b.ntp
	}
	if a.priority != b.priority {
		return a.priority < b.priority
	}
	return a.order < b.order
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)   { *h = append(*h, x.(*replayEvent)) }
func (h *eventHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return x
}

type replayFlow struct {
	ntp              uint64
	src, dst         tlvwrite.Endpoint
	srcPort, dstPort uint16
}

func flowFromMeta(meta preservation.Metadata, ntp uint64) replayFlow {
	src, dst := endpointOrDefault(meta, nil, nil)
	sp, dp := portsOrDefault(meta, 0, 0)
	return replayFlow{ntp: ntp, src: src, dst: dst, srcPort: sp, dstPort: dp}
}

func (f replayFlow) or(d replayFlow) replayFlow {
	if f.src == nil {
		f.src = d.src
	}
	if f.dst == nil {
		f.dst = d.dst
	}
	if f.srcPort == 0 {
		f.srcPort = d.srcPort
	}
	if f.dstPort == 0 {
		f.dstPort = d.dstPort
	}
	return f
}

type captionBatch struct {
	ntp       uint64
	packetID  uint16
	flow      replayFlow
	resources []captionActivation
}

type captionActivation struct {
	objectID uint64
	resource CaptionResource
}

// carouselReplay は届いた record を、window の分だけ先を見てから元の時刻順で書く。
type carouselReplay struct {
	w      io.Writer
	report *Report
	window uint64
	seq    *mmtwrite.Sequencer

	streamType map[uint16]byte
	aus        map[uint16]*auQueue
	objects    *carouselin.State

	def     replayFlow
	haveDef bool

	flows              map[uint16][]replayFlow
	rawApplicationPIDs map[uint16]bool
	captionBatches     map[string]*captionBatch

	events    eventHeap
	order     uint64
	frontier  uint64
	flushedTo uint64
	deferred  []*replayEvent
	late      int
	lastSeq   uint64
	lastEpoch uint32
	haveSeq   bool
	backwards int
}

func newCarouselReplay(w io.Writer, report *Report, window time.Duration,
	streamType map[uint16]byte, aus map[uint16]*auQueue, objects *carouselin.State) *carouselReplay {
	if window <= 0 {
		window = DefaultWindow
	}
	return &carouselReplay{
		w: w, report: report, seq: mmtwrite.NewSequencer(),
		window:     uint64(window.Seconds() * (1 << 32)),
		streamType: streamType, aus: aus, objects: objects,
		flows:              make(map[uint16][]replayFlow),
		rawApplicationPIDs: make(map[uint16]bool),
		captionBatches:     make(map[string]*captionBatch),
	}
}

func (r *carouselReplay) push(ntp uint64, priority byte, order uint64, write func(final bool) (bool, error)) {
	if r.flushedTo > 0 && ntp <= r.flushedTo {
		r.late++
		r.report.LateRecords++
		if r.late <= 5 {
			r.report.problem("record at NTP %#016x arrived %.1f s after its window closed; written out of order",
				ntp, float64(r.flushedTo-ntp)/(1<<32))
		}
	}
	heap.Push(&r.events, &replayEvent{ntp: ntp, priority: priority, order: order, write: write})
}

func (r *carouselReplay) nextOrder() uint64 {
	r.order++
	return r.order
}

func (r *carouselReplay) drain(realtime *carouselin.State) {
	for _, seg := range realtime.TakeSegments() {
		r.segment(seg)
	}
	for _, e := range realtime.TakeAVMap() {
		r.avEntry(e)
	}
}

func (r *carouselReplay) segment(seg carouselin.CompletedSegment) {
	r.report.Segments++
	if r.haveSeq && seg.Epoch != r.lastEpoch {
		r.report.Epochs++
	} else if r.haveSeq && seg.Sequence != r.lastSeq+1 {
		r.report.SegmentGaps++
	}
	r.lastSeq, r.lastEpoch, r.haveSeq = seg.Sequence, seg.Epoch, true
	for i := range seg.Records {
		rec := seg.Records[i]
		if rec.SourceNTP > r.frontier {
			r.frontier = rec.SourceNTP
		} else if r.frontier-rec.SourceNTP > 2<<32 {
			r.backwards++
			if r.backwards <= 5 {
				r.report.problem("segment %d: record at NTP %#016x is %.1f s behind the newest record so far",
					seg.Sequence, rec.SourceNTP, float64(r.frontier-rec.SourceNTP)/(1<<32))
			}
		}
		switch rec.Kind {
		case preservation.RecordRawSignalling, preservation.RecordCAData:
			r.report.SignallingRecords++
			r.noteEndpoint(rec)
			r.push(rec.SourceNTP, 0, r.nextOrder(), func(bool) (bool, error) {
				d := r.def
				return true, replaySignallingRecordAt(r.w, rec, r.seq, d.src, d.dst, d.srcPort, d.dstPort)
			})
		case preservation.RecordGenericTimedData:
			if assetType, ok := metaBytes(rec.Metadata, preservation.MetaAssetType, 4); ok && string(assetType) == "aapp" {
				if packetID, ok := metaU16(rec.Metadata, preservation.MetaPacketID); ok {
					r.rawApplicationPIDs[packetID] = true
				}
			}
			r.push(rec.SourceNTP, 1, r.nextOrder(), func(bool) (bool, error) {
				d := r.def
				return true, replayGenericRecordAt(r.w, rec, r.seq, d.src, d.dst, d.srcPort, d.dstPort)
			})
		case preservation.RecordTimelineAnchor:
			r.anchor(rec)
		case preservation.RecordObjectActivation:
			r.activation(rec)
		}
	}
}

func (r *carouselReplay) noteEndpoint(rec preservation.Record) {
	if r.haveDef {
		return
	}
	kind, ok := metaU8(rec.Metadata, preservation.MetaSignallingKind)
	if !ok || kind == preservation.SignallingNTP || kind == preservation.SignallingTLVSI {
		return
	}
	if metaIP(rec.Metadata, preservation.MetaIPSource) == nil {
		return
	}
	r.def, r.haveDef = flowFromMeta(rec.Metadata, 0), true
}

func (r *carouselReplay) anchor(rec preservation.Record) {
	anchor, err := preservation.ParseTimelineAnchor(rec.Payload)
	if err != nil || anchor.ClockKind != preservation.ClockPresentation {
		return
	}
	flows := r.flows[anchor.OutputPID]
	flow := flowFromMeta(rec.Metadata, anchor.SourceNTP)
	i := len(flows)
	for i > 0 && flows[i-1].ntp > flow.ntp {
		i--
	}
	flows = append(flows, replayFlow{})
	copy(flows[i+1:], flows[i:])
	flows[i] = flow
	r.flows[anchor.OutputPID] = flows
}

func (r *carouselReplay) activation(rec preservation.Record) {
	activation, err := preservation.ParseObjectActivation(rec.Payload)
	if err != nil || activation.Action == preservation.ObjectDeactivate {
		return
	}
	packetID, havePacketID := metaU16(rec.Metadata, preservation.MetaPacketID)
	flow := flowFromMeta(rec.Metadata, rec.SourceNTP)
	if subtitle, ok := metaBytes(rec.Metadata, preservation.MetaSubtitleID, 6); ok {
		if !havePacketID {
			r.report.problem("caption activation: object %#016x has no packet id", activation.ObjectID)
			return
		}
		tag, _ := metaU16(rec.Metadata, preservation.MetaComponentTag)
		mpuSeq, _ := metaU32(rec.Metadata, preservation.MetaMPUSequence)
		header := metaVariable(rec.Metadata, preservation.MetaCaptionHeader)
		key := fmt.Sprintf("%d/%d/%d/%d/%d", rec.SourceNTP, packetID, tag, mpuSeq, subtitle[1])
		batch := r.captionBatches[key]
		if batch == nil {
			batch = &captionBatch{ntp: rec.SourceNTP, packetID: packetID, flow: flow}
			r.captionBatches[key] = batch
			r.push(batch.ntp, 2, r.nextOrder(), func(final bool) (bool, error) {
				return r.writeCaptions(key, batch, final)
			})
		}
		batch.resources = append(batch.resources, captionActivation{objectID: activation.ObjectID,
			resource: CaptionResource{
				ComponentTag: tag, MPUSequence: mpuSeq, Tag: subtitle[0], SequenceNumber: subtitle[1],
				Number: subtitle[2], DataType: subtitle[4], Header: header,
			}})
		return
	}
	itemID, isItem := metaU32(rec.Metadata, preservation.MetaItemID)
	if !isItem {
		return
	}
	r.report.ApplicationItems++
	if !havePacketID {
		return
	}
	mpuSequence, _ := metaU32(rec.Metadata, preservation.MetaMPUSequence)
	ntp := rec.SourceNTP
	r.push(ntp, 2, r.nextOrder(), func(final bool) (bool, error) {
		if r.rawApplicationPIDs[packetID] {
			return true, nil
		}
		resolved, ok := r.objects.Resolved[activation.ObjectID]
		if !ok {
			if !final {
				return false, nil
			}
			r.report.problem("object activation: object %#016x is not in a committed snapshot", activation.ObjectID)
			return true, nil
		}
		item := ApplicationItem{ID: itemID, MPUSequence: mpuSequence, Data: resolved.Data}
		f := flow.or(r.def)
		return true, replayApplicationItemsAt(r.w, []ApplicationItem{item}, packetID, r.seq, f.src, f.dst, f.srcPort, f.dstPort, ntp)
	})
}

func (r *carouselReplay) writeCaptions(key string, b *captionBatch, final bool) (bool, error) {
	resources := make([]CaptionResource, 0, len(b.resources))
	for _, a := range b.resources {
		resolved, ok := r.objects.Resolved[a.objectID]
		if !ok {
			if !final {
				return false, nil
			}
			r.report.problem("object activation: object %#016x is not in a committed snapshot", a.objectID)
			continue
		}
		res := a.resource
		res.Data = resolved.Data
		resources = append(resources, res)
	}
	delete(r.captionBatches, key)
	if len(resources) == 0 {
		return true, nil
	}
	f := b.flow.or(r.def)
	r.report.CaptionUnits += len(resources)
	resolver := func(uint16) (uint16, bool) { return b.packetID, true }
	return true, replayCaptionResourcesAt(r.w, resources, resolver, r.seq, f.src, f.dst, f.srcPort, f.dstPort, b.ntp)
}

func (r *carouselReplay) avEntry(e preservation.AVMapEntry) {
	order := uint64(e.OutputPID)<<32 | uint64(e.MPUSequence)
	r.push(e.StartNTP, 3, order, func(bool) (bool, error) {
		q := r.aus[e.OutputPID]
		have := uint64(0)
		if q != nil {
			have = q.end()
		}
		start := e.FirstAUOrdinal
		end := start + uint64(e.AUCount)
		if start > have {
			r.report.problem("AV map: output PID %#04x wants AUs %d-%d but only %d were demultiplexed", e.OutputPID, start, end, have)
			return true, nil
		}
		if q == nil {
			return true, nil
		}
		if start < q.base {
			r.report.problem("AV map: output PID %#04x wants AUs %d-%d but AUs before %d were already written", e.OutputPID, start, end, q.base)
			start = q.base
		}
		end = min(end, have)
		st, ok := r.streamType[e.OutputPID]
		if !ok {
			r.report.problem("AV map: output PID %#04x was never declared in the PMT", e.OutputPID)
			return true, nil
		}
		segment := q.payloads(start, end)
		flow := flowAt(r.flows[e.OutputPID], e.StartNTP).or(r.def)
		if err := ReplayAV(r.w, e, st, segment, r.seq, flow.src, flow.dst, flow.srcPort, flow.dstPort); err != nil {
			r.report.problem("AV map: output PID %#04x: %v", e.OutputPID, err)
		} else {
			r.report.AVAccessUnits += len(segment)
		}
		q.dropBefore(end)
		return true, nil
	})
}

func flowAt(flows []replayFlow, ntp uint64) replayFlow {
	var out replayFlow
	for _, flow := range flows {
		if flow.ntp > ntp {
			break
		}
		out = flow
	}
	return out
}

func (r *carouselReplay) flush(final bool) error {
	watermark := ^uint64(0)
	if !final {
		if r.frontier < r.window {
			return nil
		}
		watermark = r.frontier - r.window
	}
	for r.events.Len() > 0 && r.events[0].ntp <= watermark {
		ev := heap.Pop(&r.events).(*replayEvent)
		if err := r.emit(ev, final); err != nil {
			return err
		}
	}
	if !final {
		r.flushedTo = watermark
	}
	kept := r.deferred[:0]
	for _, ev := range r.deferred {
		giveUp := final || ev.ntp+objectGrace < watermark
		ok, err := ev.write(giveUp)
		if err != nil {
			return err
		}
		if !ok {
			kept = append(kept, ev)
		}
	}
	for i := len(kept); i < len(r.deferred); i++ {
		r.deferred[i] = nil
	}
	r.deferred = kept
	if !final {
		r.trimFlows(watermark)
	}
	return nil
}

func (r *carouselReplay) emit(ev *replayEvent, final bool) error {
	ok, err := ev.write(final)
	if err != nil {
		return err
	}
	if !ok {
		r.deferred = append(r.deferred, ev)
	}
	return nil
}

func (r *carouselReplay) trimFlows(watermark uint64) {
	for pid, flows := range r.flows {
		i := 0
		for i+1 < len(flows) && flows[i+1].ntp <= watermark {
			i++
		}
		if i > 0 {
			r.flows[pid] = append([]replayFlow(nil), flows[i:]...)
		}
	}
}
