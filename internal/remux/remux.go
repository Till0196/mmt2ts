// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package remux はTLVの解析からTS多重化までの変換処理を統括する。
package remux

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"mmt2ts/internal/caption"
	"mmt2ts/internal/codec"
	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/mpu"
	"mmt2ts/internal/pes"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/remux/appdata"
	"mmt2ts/internal/si"
	"mmt2ts/internal/siconv"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/timeline"
	"mmt2ts/internal/tlv"
)

type Options struct {
	ServiceID         uint16
	TSID              uint16
	PMTPID            uint16
	ReorderWindow     int64
	Preroll           int64
	PSIInterval       int64
	PCRInterval       int64
	TextMode          siconv.TextMode
	ResumeWithoutIRAP bool
	SegmentDurationMS uint32
	Carousel          bool
}

func DefaultOptions() Options {
	return Options{
		ServiceID:     0,
		TSID:          0,
		PMTPID:        0x0100,
		ReorderWindow: 3 * timeline.Hz,
		Preroll:       timeline.Hz,
		PSIInterval:   timeline.Hz / 10,
		PCRInterval:   timeline.Hz / 25,
		TextMode:      siconv.TextARIB,
		Carousel:      true,
	}
}

const (
	MinPMTPID = 0x0020
	MaxPMTPID = 0x1ffe
)

func (o Options) Validate() error {
	if o.PCRInterval <= 0 {
		return fmt.Errorf("PCRInterval must be positive, got %d", o.PCRInterval)
	}
	if o.PSIInterval <= 0 {
		return fmt.Errorf("PSIInterval must be positive, got %d", o.PSIInterval)
	}
	if o.ReorderWindow < 0 {
		return fmt.Errorf("ReorderWindow must not be negative, got %d", o.ReorderWindow)
	}
	if err := ValidatePMTPID(o.PMTPID); err != nil {
		return err
	}
	if o.SegmentDurationMS != 0 && (o.SegmentDurationMS < 250 || o.SegmentDurationMS > 1000) {
		return fmt.Errorf("SegmentDurationMS must be 0 or between 250 and 1000, got %d", o.SegmentDurationMS)
	}
	return nil
}

func ValidatePMTPID(pid uint16) error {
	if pid < MinPMTPID || pid > MaxPMTPID {
		return fmt.Errorf("PMTPID %#04x is outside the usable range %#04x-%#04x", pid, MinPMTPID, MaxPMTPID)
	}
	if mpegts.IsFixedSIPID(pid) {
		return fmt.Errorf("PMTPID %#04x is reserved for a fixed PSI/SI table", pid)
	}
	return nil
}

const (
	videoPIDBase   = 0x1011
	videoTagBase   = 0x0000
	videoTagLast   = 0x000f
	audioPIDBase   = 0x1100
	audioTagBase   = 0x0010
	audioTagLast   = 0x0017
	captionPIDBase = 0x1200
	captionTagBase = 0x0030
	captionTagLast = 0x003f
)

type converter struct {
	opts   Options
	reader *tlv.Reader
	si     *si.State
	sitext *siconv.Text
	sidesc *siconv.Converter
	sigen  *siconv.Generator
	app    *appdata.Store
	mux    *muxer
	base   timeline.Base

	flows     map[flowKey]*flow
	flowOrder []*flow
	packages  []*pkg
	byPackage map[string]*pkg
	cur       *flow

	byRoute   map[route]*stream
	usedPID   map[uint16]bool
	unconvPID map[route]*UnconvertedAsset
	sigPIDs   map[uint16]bool
	appPIDs   map[route]bool
	appByPID  map[route]*appdata.Store

	pres *preserver

	reservedTags map[byte]bool

	descriptors    map[uint16]*DescriptorStat
	pmtDirty       bool
	patDirty       bool
	report         Report
	scratch        []byte
	networkID      uint16
	hasNetworkID   bool
	currentNTP     uint64
	haveCurrentNTP bool
	curPacket      tlv.Packet
	curDatagram    tlv.Datagram
	haveDatagram   bool
}

func Run(r io.Reader, w io.Writer, opts Options) (Report, error) {
	if err := opts.Validate(); err != nil {
		return Report{}, err
	}
	c := &converter{
		opts:      opts,
		reader:    tlv.NewReader(r),
		si:        si.NewState(),
		app:       appdata.New(),
		flows:     make(map[flowKey]*flow),
		byPackage: make(map[string]*pkg),
		byRoute:   make(map[route]*stream),
		usedPID:   map[uint16]bool{opts.PMTPID: true},
		unconvPID: make(map[route]*UnconvertedAsset),
		appPIDs:   make(map[route]bool),
		appByPID:  make(map[route]*appdata.Store),
		sigPIDs:   map[uint16]bool{signaling.PacketIDPA: true},
	}
	for _, pid := range si.SignalingPacketIDs() {
		c.sigPIDs[pid] = true
	}
	c.si.DataTable = func(sec si.Section) {
		c.app.PushTable(sec)
		for _, store := range c.appByPID {
			store.PushTable(sec)
		}
	}
	c.si.NewAIT = func(ait *si.AIT) {
		c.app.PushAIT(ait)
		for _, store := range c.appByPID {
			store.PushAIT(ait)
		}
	}
	c.sitext = siconv.NewText(opts.TextMode)
	c.sidesc = siconv.NewConverter(c.sitext, tagMapperFunc(c.primaryTSTag))
	c.sigen = siconv.NewGenerator(c.sidesc, c.si)
	c.sigen.ServiceID = opts.ServiceID
	c.sigen.TSID = opts.TSID
	if opts.Carousel {
		p, err := c.newPreserver()
		if err != nil {
			return Report{}, err
		}
		c.pres = p
		c.pmtDirty = true
	}
	c.mux = newMuxer(mpegts.NewWriter(w), c)
	if err := c.run(); err != nil {
		return c.report, err
	}
	if err := c.flushStreams(); err != nil {
		return c.report, err
	}
	if err := c.mux.drain(true); err != nil {
		return c.report, err
	}
	if len(c.packages) > 0 {
		if err := c.mux.idle(c.mux.lastPSI); err != nil {
			return c.report, err
		}
	}
	if err := c.finishCarousel(); err != nil {
		return c.report, err
	}
	if err := c.mux.w.Flush(); err != nil {
		return c.report, err
	}
	c.finishReport()
	return c.report, nil
}

func (c *converter) run() error {
	for {
		pkt, err := c.reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if pkt.Type == tlv.TypeControl {
			c.si.PushTLVSection(pkt.Payload)
			if networkID, ok := tlv.NetworkID(pkt.Payload); ok {
				c.networkID = networkID
				c.hasNetworkID = true
			}
			if c.pres != nil {
				c.pres.addTLVSection(pkt, c.currentNTP)
			}
		}
		datagram, ok := c.reader.Datagram(pkt)
		c.curPacket, c.curDatagram, c.haveDatagram = pkt, datagram, ok
		if !ok {
			continue
		}
		c.cur = c.flowFor(datagram)
		if datagram.IsNTP() {
			c.report.NTPPackets++
			if len(datagram.Payload) >= 48 {
				c.currentNTP = binary.BigEndian.Uint64(datagram.Payload[40:48])
				c.haveCurrentNTP = true
				c.base.Set(c.currentNTP)
				if c.pres != nil {
					c.pres.observeNTP(c.transportMeta(), c.currentNTP, datagram.Payload)
				}
				if len(c.packages) > 0 {
					if err := c.mux.idle(c.base.To90k(c.currentNTP)); err != nil {
						return err
					}
				}
			}
			continue
		}
		m, err := mmtp.Parse(datagram.Payload)
		if err != nil {
			c.report.MMTPParseErrors++
			continue
		}
		c.report.MMTPPackets++
		if m.Scrambled && c.pres != nil && c.opts.SegmentDurationMS == 0 {
			c.pres.rec.UseShortSegments()
		}
		switch m.PayloadType {
		case mmtp.PayloadTypeMPU:
			if err := c.handleMedia(m); err != nil {
				return err
			}
		case mmtp.PayloadTypeSignaling:
			if !c.sigPIDs[m.PacketID] {
				c.report.UnannouncedSignaling++
			}
			c.handleSignaling(m)
		case mmtp.PayloadTypeRepair:
			c.report.RepairPackets++
			if c.pres != nil {
				c.pres.addGenericTimedData(c.transportMeta(), m, "afec", 0, false, c.currentNTP)
			}
		default:
			c.report.OtherPayloads++
		}
	}
}

func (c *converter) flowFor(d tlv.Datagram) *flow {
	key := datagramFlow(d)
	f := c.flows[key]
	if f == nil {
		f = &flow{
			index: uint16(len(c.flowOrder)),
			sig:   signaling.NewReassembler(),
			asm:   mpu.New(),
		}
		c.flows[key] = f
		c.flowOrder = append(c.flowOrder, f)
	}
	return f
}

func (c *converter) handleSignaling(m mmtp.Packet) {
	for _, msg := range c.cur.sig.Push(m.PacketID, m.Payload) {
		if c.pres != nil {
			c.pres.addSignalling(c.transportMeta(), m, msg, c.currentNTP)
		}
		if msg.ID != signaling.MessageIDPA {
			c.si.PushMessage(msg.ID, msg.Version, msg.Payload)
			continue
		}
		for _, table := range msg.Tables {
			switch {
			case table.PLT != nil:
				for _, e := range table.PLT.Entries {
					c.sigPIDs[e.Location.PacketID] = true
				}
			case table.MPT != nil:
				c.applyMPT(table.MPT)
			}
		}
	}
}

func (c *converter) packageFor(mpt *signaling.MPT, f *flow) *pkg {
	id := hex.EncodeToString(mpt.PackageID)
	if p := c.byPackage[id]; p != nil {
		p.flow = f.index
		return p
	}
	p := newPkg(len(c.packages), mpt.PackageID)
	p.flow = f.index
	if len(c.packages) == 0 {
		for tag := range c.reservedTags {
			p.usedTag[tag] = true
		}
	}
	p.serviceID = mpt.ServiceID()
	if p.index == 0 && c.opts.ServiceID != 0 {
		p.serviceID = c.opts.ServiceID
	}
	p.pmtPID = c.allocatePMTPID(p.index)
	p.sidesc = siconv.NewConverter(c.sitext, p)
	p.sigen = siconv.NewGenerator(p.sidesc, c.si)
	p.sigen.ServiceID = p.serviceID
	c.byPackage[id] = p
	c.packages = append(c.packages, p)
	c.patDirty, c.pmtDirty, p.dirty = true, true, true
	if p.index == 0 {
		c.opts.ServiceID = p.serviceID
		c.sigen.ServiceID = p.serviceID
		c.report.ServiceID = p.serviceID
	}
	return p
}

func (c *converter) allocatePMTPID(index int) uint16 {
	if index == 0 {
		return c.opts.PMTPID
	}
	for pid := c.opts.PMTPID + 1; pid <= MaxPMTPID; pid++ {
		if !c.usedPID[pid] && !mpegts.IsFixedSIPID(pid) {
			c.usedPID[pid] = true
			return pid
		}
	}
	return 0
}

func (c *converter) applyMPT(mpt *signaling.MPT) {
	c.report.MPTUpdates++
	f := c.cur
	p := c.packageFor(mpt, f)
	graph := signaling.BuildAssetGraph(mpt)
	p.decodeOrder = append(p.decodeOrder[:0], graph.Order...)
	p.graphIssues = append(p.graphIssues[:0], graph.Issues...)
	p.mptDescriptors = mpt.Descriptors
	c.noteDescriptors(mpt.Descriptors)
	if c.opts.TSID == 0 {
		if id := c.si.Identity(c.opts.ServiceID); id.HaveTLVStreamID {
			c.opts.TSID = id.TLVStreamID
			c.sigen.TSID = c.opts.TSID
		}
	}
	p.sigen.TSID = c.opts.TSID
	if c.pres != nil {
		c.pres.rec.SetService(c.opts.ServiceID, c.opts.TSID, c.networkID)
	}
	seen := make(map[*stream]bool, len(mpt.Assets))
	for i := range mpt.Assets {
		asset := &mpt.Assets[i]
		c.noteDescriptors(asset.Descriptors)
		kind := assetKind(asset.Type)
		packetID, hasPacketID := asset.LocalPacketID()
		r := route{flow: f.index, packetID: packetID}
		if kind == KindApplication {
			if hasPacketID {
				c.appPIDs[r] = true
				if c.appByPID[r] == nil {
					c.appByPID[r] = appdata.New()
				}
				c.trackUnconverted(p, asset, r)
			}
			continue
		}
		if kind == KindUnsupported {
			if hasPacketID {
				c.trackUnconverted(p, asset, r)
			}
			continue
		}
		if !hasPacketID {
			c.trackUnconverted(p, asset, route{})
			continue
		}
		key := asset.Key()
		s := p.byKey[key]
		if s == nil {
			s = newStream(key, kind, asset.Type)
			s.pkg = p
			s.builder.mpuEnd = func(seq, count uint32, trusted bool) { c.checkMPU(s, seq, count, trusted) }
			p.byKey[key] = s
			p.order = append(p.order, s)
			c.pmtDirty, p.dirty = true, true
		}
		if s.packetID != packetID && s.packetID != 0 {
			delete(c.byRoute, route{flow: s.flow, packetID: s.packetID})
			s.stat.PacketIDMoves++
			s.discontinuity = true
		}
		previousType := s.streamType
		previousTag := s.tsTag
		s.applyAsset(asset)
		if c.pres != nil && s.caption != nil {
			s.caption.KeepResourceBytes = true
		}
		s.flow = f.index
		c.byRoute[r] = s
		s.streamType = streamTypeFor(s.kind, s.audio)
		if s.streamType != previousType || s.tsTag != previousTag {
			c.pmtDirty, p.dirty = true, true
		}
		if previousType != 0 && s.streamType != previousType {
			s.stat.StreamTypeChanges++
		}
		if !s.present {
			s.present = true
			c.pmtDirty, p.dirty = true, true
		}
		seen[s] = true
	}
	for _, s := range p.order {
		if s.present && !seen[s] {
			s.present = false
			c.pmtDirty, p.dirty = true, true
		}
	}
}

func (c *converter) trackUnconverted(p *pkg, a *signaling.Asset, r route) {
	key := a.Key()
	u := p.unconv[key]
	if u == nil {
		u = &UnconvertedAsset{Type: a.Type, PacketID: r.packetID, ServiceID: p.serviceID,
			key: a.Key(), idScheme: a.IDScheme, assetID: clone(a.ID)}
		if a.ComponentTag != nil {
			u.Tag, u.HasTag = *a.ComponentTag, true
		}
		p.unconv[key] = u
	}
	if r.packetID != 0 {
		u.PacketID = r.packetID
		c.unconvPID[r] = u
	}
}

func (c *converter) allocatePID(s *stream) uint16 {
	preferred := s.pkg.pidBase(s.kind)
	switch s.kind {
	case KindVideo:
		if s.hasMMTTag && s.mmtTag > videoTagBase && s.mmtTag <= videoTagLast {
			preferred += s.mmtTag - videoTagBase
		}
	case KindAudio:
		if s.hasMMTTag && s.mmtTag >= audioTagBase && s.mmtTag <= audioTagLast {
			preferred += s.mmtTag - audioTagBase
		}
	case KindCaption:
		if s.hasMMTTag && s.mmtTag >= captionTagBase && s.mmtTag <= captionTagLast {
			preferred += s.mmtTag - captionTagBase
		}
	}
	base := preferred
	for pid := preferred; pid < 0x1fff; pid++ {
		if !c.usedPID[pid] {
			c.usedPID[pid] = true
			return pid
		}
	}
	for pid := base; pid > 0x0100; pid-- {
		if !c.usedPID[pid] {
			c.usedPID[pid] = true
			return pid
		}
	}
	return 0
}

func (c *converter) allocateTag(s *stream) byte {
	used := s.pkg.usedTag
	want := byte(s.mmtTag)
	if !s.hasMMTTag {
		want = byte(s.pid)
	}
	if !used[want] {
		used[want] = true
		return want
	}
	for i := range 256 {
		candidate := byte((int(want) + i + 1) & 0xff)
		if !used[candidate] {
			used[candidate] = true
			return candidate
		}
	}
	return want
}

func (c *converter) handleMedia(m mmtp.Packet) error {
	r := route{flow: c.cur.index, packetID: m.PacketID}
	if u := c.unconvPID[r]; u != nil {
		u.Payloads++
		u.Bytes += uint64(len(m.Payload))
		if c.appPIDs[r] {
			if c.pres != nil {
				c.pres.addGenericTimedData(c.transportMeta(), m, u.Type, u.Tag, u.HasTag, c.currentNTP)
			}
			c.handleApplication(r, m, u)
			return nil
		}
		if c.pres != nil {
			c.pres.addGenericTimedData(c.transportMeta(), m, u.Type, u.Tag, u.HasTag, c.currentNTP)
		}
		return nil
	}
	s := c.byRoute[r]
	if s == nil {
		c.report.UnroutedPackets++
		return nil
	}
	c.preserveRawMedia(s, m, c.curDatagram.Payload)
	if m.Scrambled {
		s.stat.ScrambledPackets++
	}
	for _, u := range c.cur.asm.Push(m) {
		if s.kind == KindCaption {
			if err := c.handleCaptionUnit(s, u); err != nil {
				return err
			}
			continue
		}
		if u.Loss {
			s.stat.LossEvents++
			s.carryLoss += u.LostPackets
			s.discontinuity = true
			if s.kind == KindVideo {
				s.awaitingIRAP = true
			}
		}
		if err := s.builder.push(u, func(au accessUnit) error { return c.handleAU(s, au) }); err != nil {
			return err
		}
	}
	return nil
}

func (c *converter) handleApplication(r route, m mmtp.Packet, owner *UnconvertedAsset) {
	store := c.appByPID[r]
	if store == nil {
		store = c.app
	}
	for _, u := range c.cur.asm.Push(m) {
		if u.Loss || u.Timed {
			continue
		}
		store.PushItemData(u.MPUSequence, u.Sample, u.Data)
		if store != c.app {
			c.app.PushItemData(u.MPUSequence, u.Sample, u.Data)
		}
		if c.pres != nil {
			if it := store.Item(u.Sample); it != nil && it.Complete() {
				if err := c.pres.addApplicationItem(it, owner, applicationForItem(store, it), c.currentNTP, c.transportMeta()); err != nil {
					c.pres.addLoss(preservation.ScopeObject, preservation.ReasonCapacityExceeded,
						preservation.SeverityUnrecoverable, uint64(it.ID), err.Error(), nil)
				}
			}
		}
	}
}

func applicationForItem(store *appdata.Store, it *appdata.Item) *appdata.Application {
	full := it.Path + it.Name
	for _, app := range store.Applications() {
		if app.Location == full || app.Location == it.Name ||
			(it.Name != "" && strings.HasSuffix(app.Location, "/"+it.Name)) {
			return app
		}
	}
	return nil
}

func (c *converter) handleCaptionUnit(s *stream, u mpu.Unit) error {
	if s.caption == nil {
		s.stat.UnitsDiscarded++
		return nil
	}
	if u.Loss {
		s.stat.LossEvents++
		s.carryLoss += u.LostPackets
		s.discontinuity = true
		return nil
	}
	if c.haveCurrentNTP {
		if _, seen := s.captionArrivals.get(u.MPUSequence); !seen {
			s.captionArrivals.put(u.MPUSequence, c.currentNTP)
		}
	}
	done, ok := s.caption.Push(u.MPUSequence, u.Data)
	if !ok {
		return nil
	}
	return c.emitCaption(s, done)
}

func (c *converter) emitCaption(s *stream, done *caption.MPU) error {
	if c.pres != nil {
		ntp, ok := s.times.get(done.Sequence)
		if !ok {
			ntp = c.currentNTP
		}
		if err := c.pres.addCaptionResources(s, done, ntp, c.transportMeta()); err != nil {
			return err
		}
	}
	timing, ok := c.captionTiming(s, done.Sequence)
	if !ok {
		s.stat.AUsNoTiming++
	}
	out, err := s.caption.Convert(done, timing)
	if err != nil {
		s.stat.AUsCodecError++
		return nil
	}
	for _, o := range out {
		s.stat.AUsIn++
		if !o.HasPTS {
			o.PTS = timing.MPUPresentation
		}
		item := queued{
			stream:        s,
			dts:           o.PTS,
			pts:           o.PTS,
			streamID:      pes.StreamIDPrivate1,
			payload:       c.mux.take(o.Payload),
			noPTS:         !o.HasPTS,
			discontinuity: s.discontinuity,
			carryLoss:     s.carryLoss,
		}
		if o.HasPTS {
			item.privateData = []byte{
				'C', 'C', 'I', 'S', 0x01, 0x3f,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			}
			item.stuffing = 1
		}
		s.discontinuity = false
		s.carryLoss = 0
		c.assignOutput(s)
		if err := c.mux.push(item); err != nil {
			return err
		}
	}
	return nil
}

func (c *converter) captionTiming(s *stream, mpuSeq uint32) (caption.Timing, bool) {
	ntp, ok := s.times.get(mpuSeq)
	if !ok {
		s.stat.MPUsSenderClock++
		ntp, ok = s.captionArrivals.get(mpuSeq)
		if !ok {
			if !c.haveCurrentNTP {
				return caption.Timing{}, false
			}
			ntp = c.currentNTP
		}
	}
	c.base.Set(ntp)
	t := caption.Timing{MPUPresentation: c.base.To90k(ntp), HasMPU: true}
	seconds := ntp >> 32
	if seconds > 0 {
		midnight := (seconds / 86400) * 86400
		t.UTCOrigin, t.HasUTC = c.base.To90k(midnight<<32), true
	}
	if s.captionInfo != nil && s.captionInfo.HasReference {
		t.ReferenceStart, t.HasReference = c.base.To90k(s.captionInfo.ReferenceTime), true
	}
	if start, ok := c.eventStartNTP(s.pkg.serviceID); ok {
		t.EventStart, t.HasEvent = c.base.To90k(start), true
	}
	return t, true
}

func (c *converter) eventStartNTP(serviceID uint16) (uint64, bool) {
	_, event, ok := c.si.PresentEvent(serviceID)
	if !ok || !event.StartDefined() {
		return 0, false
	}
	unix, ok := timeline.MJDBCDToUnix(event.StartTime)
	if !ok {
		return 0, false
	}
	return timeline.UnixToNTP(unix), true
}

func (c *converter) flushStreams() error {
	for _, p := range c.packages {
		for _, s := range p.order {
			if s.kind == KindCaption && s.caption != nil {
				if done, ok := s.caption.Flush(); ok {
					if err := c.emitCaption(s, done); err != nil {
						return err
					}
				}
				continue
			}
			if s.builder == nil {
				continue
			}
			s.builder.finish()
		}
	}
	return nil
}

func (c *converter) handleAU(s *stream, au accessUnit) error {
	s.stat.AUsIn++
	dts, pts, ok := s.auTimes(&c.base, au.MPUSequence, au.Index)
	if !ok {
		s.stat.AUsNoTiming++
		s.discontinuity = true
		if s.kind == KindVideo {
			s.awaitingIRAP = true
		}
		return nil
	}

	var payload []byte
	audio := false
	streamID := byte(pes.StreamIDAudio)
	switch s.kind {
	case KindVideo:
		streamID = pes.StreamIDVideo
		converted, info, err := codec.HEVCAnnexB(c.scratch[:0], au.Data)
		if err != nil {
			s.stat.AUsCodecError++
			s.discontinuity = true
			s.awaitingIRAP = true
			return nil
		}
		c.scratch = converted
		if info.HasParameterSet {
			s.sawParameterSet = true
		}
		if s.awaitingIRAP {
			switch {
			case info.HasIRAP && s.sawParameterSet:
				s.awaitingIRAP = false
			case c.opts.ResumeWithoutIRAP:
				s.stat.AUsAfterLoss++
			default:
				s.stat.AUsWaitIRAP++
				return nil
			}
		}
		au.RAP = au.RAP || info.HasIRAP
		payload = converted
		if c.pres != nil && info.HasParameterSet {
			c.pres.noteVideoConfig(s, s.pid, au.Data, c.currentNTP)
		}
	case KindAudio:
		audio = true
		payload = au.Data
		if c.pres != nil {
			c.pres.noteAudioConfig(s, s.pid, au.Data, c.currentNTP)
		}
	default:
		return nil
	}
	c.assignOutput(s)

	if c.pres != nil {
		ntp, haveNTP := s.times.get(au.MPUSequence)
		if !haveNTP {
			ntp = c.currentNTP
		}
		c.pres.noteAU(s, s.pid, au.MPUSequence, au.RAP, ntp)
		c.pres.anchor(s.pid, s.packetID, pts, dts, ntp, c.transportMeta())
	}

	if s.haveLastDTS {
		switch {
		case dts < s.lastDTS:
			s.stat.DTSBackwards++
		case dts-s.lastDTS > timeline.Hz/2:
			s.stat.DTSGaps++
			if gap := dts - s.lastDTS; gap > s.stat.MaxGap90k {
				s.stat.MaxGap90k = gap
			}
			s.discontinuity = true
		}
	} else {
		s.stat.FirstDTS, s.stat.HaveDTS = dts, true
	}
	s.lastDTS, s.haveLastDTS = dts, true
	s.stat.LastDTS = dts

	item := queued{
		stream:        s,
		dts:           dts,
		pts:           pts,
		streamID:      streamID,
		payload:       c.mux.take(payload),
		randomAccess:  au.RAP,
		discontinuity: s.discontinuity,
		carryLoss:     s.carryLoss,
		audio:         audio,
	}
	s.discontinuity = false
	s.carryLoss = 0
	return c.mux.push(item)
}

func (c *converter) checkMPU(s *stream, seq, count uint32, trusted bool) {
	if !trusted {
		s.stat.MPUsUntrusted++
		return
	}
	entry, ok := s.extended.get(seq)
	if !ok {
		s.stat.MPUsUntrusted++
		return
	}
	s.stat.MPUsChecked++
	if int(count) == len(entry.AUs) {
		s.stat.MPUsAUMatch++
	} else {
		s.stat.MPUsAUDiffer++
	}
}

func (c *converter) finishCarousel() error {
	if c.pres == nil {
		return nil
	}
	c.pres.closeAllRuns()
	now := c.mux.lastPCR
	if err := c.pres.rec.Finish(now); err != nil {
		return err
	}
	return c.mux.writeCarousel(now)
}

func (c *converter) finishReport() {
	if c.pres != nil {
		c.report.Carousel = c.pres.rec.Stats()
		c.report.CarouselRealtimePID = c.pres.realtimePID
		c.report.CarouselObjectPID = c.pres.objectPID
	}
	c.report.TLV = c.reader.Stats()
	c.report.Signaling.UnknownTables = make(map[byte]uint64)
	for _, f := range c.flowOrder {
		c.report.Signaling = c.report.Signaling.Add(f.sig.Stats())
		c.report.MPU = c.report.MPU.Add(f.asm.Stats())
	}
	c.report.Flows = len(c.flowOrder)
	c.report.SI = c.si.Stats()
	c.report.SITableIDs = c.si.RawTables
	c.report.SITableErrors = c.si.ParseErrors
	c.report.SIState = SIStateStat{
		NIT: len(c.si.NIT), SDT: len(c.si.SDT), EIT: len(c.si.EIT),
		BIT: len(c.si.BIT), CDT: len(c.si.CDT), AIT: len(c.si.AIT),
	}
	c.report.SIText = c.sitext.Stats()
	c.report.SIDescriptors = make(map[siconv.TagKey]*siconv.TagStat, len(c.sidesc.Stats))
	mergeDescriptorStats(c.report.SIDescriptors, c.sidesc.Stats)
	c.report.SIDiagnostics = c.sigen.Diagnostics()
	c.report.InputBytes = c.report.TLV.Bytes
	c.mux.fillReport(&c.report)
	for _, p := range c.packages {
		c.report.Programs = append(c.report.Programs, ProgramStat{
			ServiceID: p.serviceID,
			PMTPID:    p.pmtPID,
			PCRPID:    p.pcrPID,
			Streams:   len(p.activeStreams()),
		})
		c.report.AssetDecodeOrder = append(c.report.AssetDecodeOrder, p.decodeOrder...)
		c.report.AssetGraphIssues = append(c.report.AssetGraphIssues, p.graphIssues...)
		c.report.SIDiagnostics = append(c.report.SIDiagnostics, p.sigen.Diagnostics()...)
		mergeDescriptorStats(c.report.SIDescriptors, p.sidesc.Stats)
		for _, s := range p.order {
			stat := s.stat
			stat.ServiceID = p.serviceID
			stat.AssetType = s.assetType
			stat.PacketID = s.packetID
			stat.PID = s.pid
			stat.MMTTag = s.mmtTag
			stat.TSTag = s.tsTag
			stat.StreamType = s.streamType
			stat.InPMT = s.emitted
			if s.audio != nil {
				stat.Language = s.audio.Language
			}
			stat.AUsDroppedAtEnd = s.builder.droppedAtEnd
			stat.UnitsNoAUStart = s.builder.unitsBeforeStart
			stat.UnitsDiscarded = s.builder.unitsUntrusted
			c.report.Streams = append(c.report.Streams, stat)
			if s.kind == KindCaption && s.caption != nil {
				c.report.Captions = append(c.report.Captions, CaptionStat{
					PID:             s.pid,
					ServiceID:       p.serviceID,
					MMTTag:          s.mmtTag,
					Language:        s.captionInfo.Language,
					Superimposition: s.captionInfo.Superimposition(),
					TMD:             s.captionInfo.TMD,
					DMF:             s.captionInfo.DMF,
					Stats:           s.caption.Stats(),
				})
			}
		}
		for _, u := range p.unconv {
			c.report.Unconverted = append(c.report.Unconverted, *u)
		}
	}
	slices.SortFunc(c.report.Unconverted, func(a, b UnconvertedAsset) int {
		if a.ServiceID != b.ServiceID {
			return int(a.ServiceID) - int(b.ServiceID)
		}
		if a.PacketID != b.PacketID {
			return int(a.PacketID) - int(b.PacketID)
		}
		return strings.Compare(a.Type, b.Type)
	})
	c.app.Finish()
	c.report.App = c.app.Stats()
	c.report.AppItems = c.app.Items()
	c.report.AppReferences = c.app.Graph()
	for _, st := range c.descriptors {
		c.report.Descriptors = append(c.report.Descriptors, *st)
	}
}

func mergeDescriptorStats(into, from map[siconv.TagKey]*siconv.TagStat) {
	for key, stat := range from {
		sum := into[key]
		if sum == nil {
			sum = &siconv.TagStat{}
			into[key] = sum
		}
		sum.Converted += stat.Converted
		sum.Unsupported += stat.Unsupported
		sum.Invalid += stat.Invalid
		if sum.Reason == "" {
			sum.Reason = stat.Reason
		}
	}
}

func (c *converter) primaryTSTag(mmtTag uint16) (byte, bool) {
	if len(c.packages) == 0 {
		return 0, false
	}
	return c.packages[0].TSTag(mmtTag)
}

type tagMapperFunc func(uint16) (byte, bool)

func (f tagMapperFunc) TSTag(mmtTag uint16) (byte, bool) { return f(mmtTag) }
