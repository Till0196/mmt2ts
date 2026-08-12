// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"mmt2ts/internal/caption"
	"mmt2ts/internal/codec"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/si"
	"mmt2ts/internal/siconv"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/timeline"
)

type Kind int

const (
	KindUnsupported Kind = iota
	KindVideo
	KindAudio
	KindCaption
	KindApplication
)

type stream struct {
	pkg        *pkg
	flow       uint16
	key        string
	kind       Kind
	assetType  string
	packetID   uint16
	pid        uint16
	streamType byte
	tsTag      byte
	mmtTag     uint16
	hasMMTTag  bool
	group      *signaling.AssetGroup
	video      *signaling.VideoComponent
	audio      *signaling.AudioComponent
	present    bool
	emitted    bool
	builder    *auBuilder
	adts       codec.ADTSConverter

	caption         *caption.Stream
	captionInfo     *caption.AdditionalInfo
	captionArrivals *boundedMap[uint64]

	timescale        uint32
	ptsOffsetType    byte
	defaultPTSOffset uint16
	haveTiming       bool
	times            *boundedMap[uint64]
	extended         *boundedMap[signaling.ExtendedEntry]

	awaitingIRAP    bool
	sawParameterSet bool
	discontinuity   bool
	carryLoss       uint32
	lastDTS         int64
	haveLastDTS     bool

	stat StreamStat

	rawMedia *rawMediaState
}

func newStream(key string, kind Kind, assetType string) *stream {
	return &stream{
		key:       key,
		kind:      kind,
		assetType: assetType,
		builder:   newAUBuilder(kind),
		times:     newBoundedMap[uint64](timingCacheEntries),
		extended:  newBoundedMap[signaling.ExtendedEntry](timingCacheEntries),

		captionArrivals: newBoundedMap[uint64](timingCacheEntries),
	}
}

const timingCacheEntries = 4096

const audioMode22_2ch = 0x11

func (s *stream) applyAsset(a *signaling.Asset) {
	s.assetType = a.Type
	if pid, ok := a.LocalPacketID(); ok {
		s.packetID = pid
	}
	if a.ComponentTag != nil {
		s.mmtTag, s.hasMMTTag = *a.ComponentTag, true
	}
	if a.Group != nil {
		s.group = a.Group
	}
	if a.Video != nil {
		s.video = a.Video
	}
	if a.Audio != nil {
		s.audio = a.Audio
	}
	if s.kind == KindCaption {
		s.applyCaptionDescriptors(a)
	}
	for _, t := range a.MPUTimestamps {
		if s.times.put(t.Sequence, t.NTP) {
			s.stat.MPUsDeclared++
		}
	}
	if e := a.Extended; e != nil && !e.Invalid {
		if e.HasTimescale {
			s.timescale = e.Timescale
		}
		s.ptsOffsetType = e.PTSOffsetType
		s.defaultPTSOffset = e.DefaultPTSOffset
		for _, entry := range e.Entries {
			s.extended.put(entry.Sequence, entry)
		}
		s.haveTiming = s.timescale != 0
	}
}

func (s *stream) applyCaptionDescriptors(a *signaling.Asset) {
	for _, d := range a.Descriptors {
		if d.Tag != si.TagMHDataComponent {
			continue
		}
		dc, ok := si.ParseDataComponent(d.Data)
		if !ok || dc.ComponentID != si.DataComponentCaption {
			continue
		}
		info, ok := caption.ParseAdditionalInfo(dc.AdditionalInfo)
		if !ok {
			continue
		}
		if s.captionInfo != nil && *s.captionInfo == *info {
			return
		}
		s.captionInfo = info
		s.caption = caption.NewStream(*info, caption.NewDRCS(nil))
		return
	}
}

func (s *stream) auTimes(base *timeline.Base, mpuSeq, sampleNumber uint32) (dts, pts int64, ok bool) {
	ntp, haveNTP := s.times.get(mpuSeq)
	entry, haveExt := s.extended.get(mpuSeq)
	if !haveNTP || !haveExt || !s.haveTiming {
		return 0, 0, false
	}
	if sampleNumber == 0 || int(sampleNumber) > len(entry.AUs) {
		return 0, 0, false
	}
	index := int(sampleNumber) - 1
	offset := -int64(entry.DecodingTimeOffset)
	if s.ptsOffsetType == 2 {
		for _, au := range entry.AUs[:index] {
			offset += int64(au.PTSOffset)
		}
	} else {
		offset += int64(index) * int64(s.defaultPTSOffset)
	}
	base.Set(ntp)
	origin := base.To90k(ntp)
	dts = origin + timeline.TicksTo90k(offset, s.timescale)
	pts = origin + timeline.TicksTo90k(offset+int64(entry.AUs[index].DTSPTSOffset), s.timescale)
	return dts, pts, true
}

type hierarchyPeer struct {
	pid         uint16
	highQuality bool
}

func (s *stream) esDescriptors(peer *hierarchyPeer) []byte {
	d := mpegts.StreamIdentifierDescriptor(s.tsTag)
	if s.kind == KindVideo {
		if s.video != nil {
			d = append(d, videoComponentDescriptor(s.video, s.tsTag)...)
		}
		return append(d, hierarchicalTransmissionDescriptor(peer)...)
	}
	switch {
	case s.kind == KindAudio && s.audio != nil:
		d = append(d, audioComponentDescriptor(s.audio, s.tsTag)...)
	case s.kind == KindCaption && s.captionInfo != nil:
		if b, ok := mpegts.DataComponentDescriptor(captionDataComponentID,
			[]byte{captionAdditionalInfo(s.captionInfo)}); ok {
			d = append(d, b...)
		}
	}
	return d
}

const captionDataComponentID = 0x0008

func captionAdditionalInfo(info *caption.AdditionalInfo) byte {
	timing := byte(0x00)
	if !info.Superimposition() {
		timing = 0x01
	}
	return descriptorDMF(info.DMF)<<4 | timing
}

func descriptorDMF(dmf byte) byte {
	dmf &= 0x0f
	if dmf>>2 == 0 || dmf&0x03 == 0 {
		return 0x03
	}
	return dmf
}

func hierarchicalTransmissionDescriptor(peer *hierarchyPeer) []byte {
	if peer == nil {
		return nil
	}
	b, ok := mpegts.HierarchicalTransmissionDescriptor(peer.highQuality, peer.pid)
	if !ok {
		return nil
	}
	return b
}

func videoComponentDescriptor(v *signaling.VideoComponent, tsTag byte) []byte {
	lang := v.Language
	if len(lang) != 3 {
		lang = "und"
	}
	b, ok := mpegts.ComponentDescriptor(siconv.VideoStreamContent, siconv.VideoComponentType(v), tsTag, lang, nil)
	if !ok {
		return nil
	}
	return b
}

func audioComponentDescriptor(a *signaling.AudioComponent, tsTag byte) []byte {
	d := make([]byte, 0, 16)
	d = append(d, mpegts.DescAudioComponent, 0)
	streamType := byte(mpegts.StreamTypeADTSAAC)
	if a.ComponentType&0x1f == audioMode22_2ch {
		streamType = mpegts.StreamTypeLATMAAC
	}
	d = append(d, 0xf2, a.ComponentType, tsTag, streamType, a.SimulcastGroupTag, a.Flags)
	lang := a.Language
	if len(lang) != 3 {
		lang = "und"
	}
	d = append(d, lang...)
	if a.MultiLingual() {
		lang2 := a.Language2
		if len(lang2) != 3 {
			lang2 = "und"
		}
		d = append(d, lang2...)
	}
	d = append(d, a.Text...)
	if len(d)-2 > 0xff {
		d = d[:2+0xff]
	}
	d[1] = byte(len(d) - 2)
	return d
}

func assetKind(assetType string) Kind {
	switch assetType {
	case "hev1", "hvc1":
		return KindVideo
	case "mp4a":
		return KindAudio
	case "stpp":
		return KindCaption
	case "aapp":
		return KindApplication
	default:
		return KindUnsupported
	}
}

func streamTypeFor(kind Kind, audio *signaling.AudioComponent) byte {
	switch kind {
	case KindVideo:
		return mpegts.StreamTypeHEVC
	case KindAudio:
		if audio != nil && audio.ComponentType&0x1f == audioMode22_2ch {
			return mpegts.StreamTypeLATMAAC
		}
		return mpegts.StreamTypeADTSAAC
	case KindCaption:
		return mpegts.StreamTypePES
	default:
		return 0
	}
}

func (p *pkg) hierarchyPeers() map[*stream]*hierarchyPeer {
	byGroup := make(map[byte][]*stream)
	for _, s := range p.activeStreams() {
		if s.kind != KindVideo || s.group == nil {
			continue
		}
		byGroup[s.group.Identification] = append(byGroup[s.group.Identification], s)
	}
	out := make(map[*stream]*hierarchyPeer)
	for _, group := range byGroup {
		if len(group) != 2 {
			continue
		}
		a, b := group[0], group[1]
		if a.group.SelectionLevel == b.group.SelectionLevel {
			continue
		}
		high, low := a, b
		if b.group.SelectionLevel < a.group.SelectionLevel {
			high, low = b, a
		}
		out[high] = &hierarchyPeer{pid: low.pid, highQuality: true}
		out[low] = &hierarchyPeer{pid: high.pid, highQuality: false}
	}
	return out
}

func (c *converter) assignOutput(s *stream) {
	if s.emitted {
		return
	}
	if s.pid == 0 {
		s.pid = c.allocatePID(s)
		s.tsTag = c.allocateTag(s)
	}
	s.emitted = true
	c.pmtDirty, s.pkg.dirty = true, true
}
