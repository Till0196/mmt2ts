// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"mmt2ts/internal/caption"
	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/remux/appdata"
	"mmt2ts/internal/si"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/tlv"
)

const (
	realtimeCarouselPID = 0x1d00
	objectCarouselPID   = 0x1d01
	realtimeCarouselTag = 0xe0
	objectCarouselTag   = 0xe1
)

const (
	objectNSApplication = uint64(1) << 56
	objectNSCaption     = uint64(2) << 56
)

type preserver struct {
	rec *preservation.Recorder

	realtimePID uint16
	objectPID   uint16
	realtimeTag byte
	objectTag   byte

	open     map[uint16]*preservation.AVMapEntry
	ordinal  map[uint16]uint64
	anchored map[uint16]uint64

	captionIDs   map[string]uint64
	applications map[string]applicationObjectState
	nextObject   uint64

	haveConfig map[uint16]bool
}

type applicationObjectState struct {
	id     uint64
	digest [32]byte
}

func (c *converter) newPreserver() (*preserver, error) {
	p := &preserver{
		open:         make(map[uint16]*preservation.AVMapEntry),
		ordinal:      make(map[uint16]uint64),
		anchored:     make(map[uint16]uint64),
		captionIDs:   make(map[string]uint64),
		applications: make(map[string]applicationObjectState),
		haveConfig:   make(map[uint16]bool),
	}
	p.realtimePID = c.reservePID(realtimeCarouselPID)
	p.objectPID = c.reservePID(objectCarouselPID)
	if p.realtimePID == 0 || p.objectPID == 0 {
		return nil, fmt.Errorf("no free PID for the preservation carousels")
	}
	p.realtimeTag = c.reserveTag(realtimeCarouselTag)
	p.objectTag = c.reserveTag(objectCarouselTag)

	rec, err := preservation.NewRecorder(preservation.Config{
		ServiceID:         c.opts.ServiceID,
		TransportStreamID: c.opts.TSID,
		SegmentDurationMS: c.opts.SegmentDurationMS,
		RealtimePID:       p.realtimePID,
		ObjectPID:         p.objectPID,
		RealtimeTag:       p.realtimeTag,
		ObjectTag:         p.objectTag,
	})
	if err != nil {
		return nil, err
	}
	p.rec = rec
	return p, nil
}

func (c *converter) reservePID(preferred uint16) uint16 {
	for pid := preferred; pid < 0x1fff; pid++ {
		if !c.usedPID[pid] && !mpegts.IsFixedSIPID(pid) {
			c.usedPID[pid] = true
			return pid
		}
	}
	return 0
}

func (c *converter) reserveTag(preferred byte) byte {
	if c.reservedTags == nil {
		c.reservedTags = make(map[byte]bool)
	}
	for i := range 256 {
		candidate := byte((int(preferred) + i) & 0xff)
		if !c.reservedTags[candidate] {
			c.reservedTags[candidate] = true
			return candidate
		}
	}
	return preferred
}

func (p *preserver) carouselStreams() []mpegts.ElementaryStream {
	return []mpegts.ElementaryStream{
		{StreamType: mpegts.StreamTypeDSMCC, PID: p.realtimePID, Descriptors: mpegts.StreamIdentifierDescriptor(p.realtimeTag)},
		{StreamType: mpegts.StreamTypeDSMCC, PID: p.objectPID, Descriptors: mpegts.StreamIdentifierDescriptor(p.objectTag)},
	}
}

func (p *preserver) observeNTP(meta preservation.Metadata, ntp uint64, packet []byte) {
	p.rec.Observe(ntp)
	meta.AddU8(preservation.MetaSignallingKind, preservation.SignallingNTP)
	p.rec.AddRecord(preservation.RecordRawSignalling, preservation.RecordRawExact, ntp, meta, clone(packet))
}

func tlvMeta(pkt tlv.Packet, d tlv.Datagram, haveDatagram bool) preservation.Metadata {
	var meta preservation.Metadata
	meta.AddU8(preservation.MetaTLVPacketType, pkt.Type)
	meta.AddU64(preservation.MetaInputOffset, uint64(pkt.Offset))
	if !haveDatagram {
		return meta
	}
	meta.AddIP(preservation.MetaIPSource, d.Src)
	meta.AddIP(preservation.MetaIPDestination, d.Dst)
	if len(d.Src) > 0 {
		meta.AddU8(preservation.MetaIPProtocol, protocolUDP)
	}
	if d.HasPort {
		meta.AddU16(preservation.MetaUDPSourcePort, d.SrcPort)
		meta.AddU16(preservation.MetaUDPDestPort, d.DstPort)
	}
	return meta
}

const protocolUDP = 17

func (c *converter) transportMeta() preservation.Metadata {
	return tlvMeta(c.curPacket, c.curDatagram, c.haveDatagram)
}

func (p *preserver) addTLVSection(pkt tlv.Packet, ntp uint64) {
	meta := tlvMeta(pkt, tlv.Datagram{}, false)
	meta.AddU8(preservation.MetaSignallingKind, preservation.SignallingTLVSI)
	p.rec.AddRecord(preservation.RecordRawSignalling, preservation.RecordRawExact|preservation.RecordRequired,
		ntp, meta, clone(pkt.Payload))
}

func (p *preserver) addSignalling(meta preservation.Metadata, m mmtp.Packet, msg signaling.Message, ntp uint64) {
	meta.AddU16(preservation.MetaPacketID, m.PacketID)
	meta.AddU32(preservation.MetaPacketSequence, m.SequenceNumber)
	kind := preservation.RecordRawSignalling
	switch msg.ID {
	case signaling.MessageIDPA:
		meta.AddU8(preservation.MetaSignallingKind, preservation.SignallingPA)
	case si.MessageIDCA:
		kind = preservation.RecordCAData
		meta.AddU8(preservation.MetaSignallingKind, preservation.SignallingCA)
	case si.MessageIDData:
		meta.AddU8(preservation.MetaSignallingKind, preservation.SignallingDataTransmission)
	default:
		meta.AddU8(preservation.MetaSignallingKind, preservation.SignallingM2Section)
	}
	raw := msg.Raw
	if len(raw) == 0 {
		raw = msg.Payload
	}
	p.rec.AddRecord(kind, preservation.RecordRawExact|preservation.RecordRequired, ntp, meta, clone(raw))
}

func (p *preserver) addGenericTimedData(meta preservation.Metadata, m mmtp.Packet, assetType string, tag uint16, hasTag bool, ntp uint64) {
	meta.AddU16(preservation.MetaPacketID, m.PacketID)
	meta.AddU32(preservation.MetaPacketSequence, m.SequenceNumber)
	if len(assetType) == 4 {
		meta.AddBytes(preservation.MetaAssetType, []byte(assetType))
	}
	if hasTag {
		meta.AddU16(preservation.MetaComponentTag, tag)
	}
	p.rec.AddRecord(preservation.RecordGenericTimedData, preservation.RecordRawExact, ntp, meta, clone(m.Payload))
}

func (p *preserver) anchor(pid uint16, packetID uint16, pts, dts int64, ntp uint64, transport preservation.Metadata) {
	segment := ntp >> 30
	if p.anchored[pid] == segment {
		return
	}
	p.anchored[pid] = segment
	a := preservation.TimelineAnchor{
		OutputPID: pid, ClockKind: preservation.ClockPresentation,
		PTS90k: uint64(pts), SourceNTP: ntp, EpochID: p.rec.EpochID(),
	}
	meta := copyMetadata(transport)
	meta.AddU16(preservation.MetaOutputPID, pid)
	meta.AddU16(preservation.MetaPacketID, packetID)
	p.rec.AddRecord(preservation.RecordTimelineAnchor, preservation.RecordRequired, ntp, meta, a.Encode())
	if dts != pts {
		d := a
		d.ClockKind = preservation.ClockDecode
		d.PTS90k = uint64(dts)
		p.rec.AddRecord(preservation.RecordTimelineAnchor, preservation.RecordRequired, ntp, meta, d.Encode())
	}
}

func (p *preserver) noteAU(s *stream, pid uint16, mpuSeq uint32, rap bool, ntp uint64) {
	e := p.open[pid]
	if e != nil && e.MPUSequence != mpuSeq {
		p.closeRun(pid, ntp)
		e = nil
	}
	if e == nil {
		e = &preservation.AVMapEntry{
			PacketID: s.packetID, OutputPID: pid, MPUSequence: mpuSeq,
			FirstAUOrdinal: p.ordinal[pid], StartNTP: ntp, AssetID: []byte(s.key),
		}
		copy(e.AssetType[:], s.assetType)
		if rap {
			e.Flags |= preservation.MapRandomAccess
		}
		p.open[pid] = e
	}
	e.AUCount++
	e.EndNTP = ntp
	p.ordinal[pid]++
}

func (p *preserver) closeRun(pid uint16, ntp uint64) {
	e := p.open[pid]
	if e == nil {
		return
	}
	if e.EndNTP <= e.StartNTP {
		e.EndNTP = ntp
	}
	p.rec.AddAVMapEntry(*e)
	delete(p.open, pid)
}

func (p *preserver) closeAllRuns() {
	for pid := range p.open {
		p.closeRun(pid, 0)
	}
}

func (p *preserver) noteVideoConfig(s *stream, pid uint16, sample []byte, ntp uint64) {
	if p.haveConfig[pid] {
		return
	}
	p.haveConfig[pid] = true
	p.rec.SetCodecConfig(preservation.CodecConfig{
		ConfigID: uint64(pid), PacketID: s.packetID, OutputPID: pid,
		Kind: preservation.ConfigHEVC, Flags: preservation.ConfigRawExact,
		EffectiveFrom: ntp, AssetID: []byte(s.key), Data: clone(sample),
		AssetType: assetTypeArray(s.assetType),
	})
}

func (p *preserver) noteAudioConfig(s *stream, pid uint16, ame []byte, ntp uint64) {
	if p.haveConfig[pid] || len(ame) == 0 || ame[0]&0x80 != 0 {
		return
	}
	p.haveConfig[pid] = true
	p.rec.SetCodecConfig(preservation.CodecConfig{
		ConfigID: uint64(pid), PacketID: s.packetID, OutputPID: pid,
		Kind: preservation.ConfigStreamMux, Flags: preservation.ConfigRawExact,
		EffectiveFrom: ntp, AssetID: []byte(s.key), Data: clone(ame),
		AssetType: assetTypeArray(s.assetType),
	})
}

func assetTypeArray(s string) [4]byte {
	var out [4]byte
	copy(out[:], s)
	return out
}

func (p *preserver) addCaptionResources(s *stream, mpu *caption.MPU, ntp uint64, transport preservation.Metadata) error {
	type resource struct {
		number, dataType byte
		data, header     []byte
	}
	resources := make([]resource, 0, len(mpu.Resources)+1)
	if len(mpu.TTML) > 0 {
		resources = append(resources, resource{number: 0, dataType: caption.DataTypeTTML, data: mpu.TTML, header: mpu.TTMLHeader})
	}
	for _, r := range mpu.Resources {
		resources = append(resources, resource{number: r.Number, dataType: r.DataType, data: r.Data, header: r.Header})
	}
	for _, r := range resources {
		if len(r.data) == 0 {
			continue
		}
		sum := sha256.Sum256(r.data)
		key := hex.EncodeToString(sum[:])
		id, ok := p.captionIDs[key]
		if !ok {
			p.nextObject++
			id = objectNSCaption | p.nextObject
			p.captionIDs[key] = id
		}
		var objectMeta preservation.Metadata
		err := p.rec.AddObject(preservation.PackInput{
			ID: id, Class: captionResourceClass(r.dataType), Flags: preservation.ObjectRawExact,
			MediaType: caption.DataTypeName(r.dataType), Metadata: objectMeta, Stored: clone(r.data),
		})
		if err != nil {
			return err
		}
		meta := copyMetadata(transport)
		meta.AddU16(preservation.MetaPacketID, s.packetID)
		meta.AddU16(preservation.MetaComponentTag, s.mmtTag)
		meta.AddU32(preservation.MetaMPUSequence, mpu.Sequence)
		flags := byte(0)
		if len(r.header) >= 5 {
			flags = r.header[4]
		}
		meta.AddBytes(preservation.MetaSubtitleID, []byte{
			mpu.SubtitleTag, mpu.SequenceNo, r.number, mpu.LastNumber, r.dataType, flags,
		})
		meta.AddBytes(preservation.MetaCaptionHeader, r.header)
		meta.AddBytes(preservation.MetaObjectSHA256, sum[:])
		activation := preservation.ObjectActivation{
			ObjectID: id, Generation: mpu.Sequence, Action: preservation.ObjectActivate,
		}
		p.rec.AddRecord(preservation.RecordObjectActivation, preservation.RecordRequired,
			ntp, meta, activation.Encode())
	}
	return nil
}

func captionResourceClass(t byte) preservation.ObjectClass {
	switch t {
	case caption.DataTypeTTML:
		return preservation.ClassTTML
	case caption.DataTypePNG, caption.DataTypeSVG:
		return preservation.ClassImage
	case caption.DataTypeSVGFont, caption.DataTypeWOFFFont:
		return preservation.ClassFont
	case caption.DataTypePCM, caption.DataTypeMP3, caption.DataTypeAAC:
		return preservation.ClassAudio
	}
	return preservation.ClassGenericAsset
}

func (p *preserver) addApplicationItem(it *appdata.Item, owner *UnconvertedAsset, app *appdata.Application,
	ntp uint64, transport preservation.Metadata) error {
	if it == nil || owner == nil || len(it.Data) == 0 {
		return nil
	}
	digest := sha256.Sum256(it.Data)
	key := fmt.Sprintf("%s/%08x", owner.key, it.ID)
	old, existed := p.applications[key]
	if existed && old.digest == digest {
		return nil
	}
	p.nextObject++
	id := objectNSApplication | p.nextObject
	var objectMeta preservation.Metadata
	objectMeta.AddU16(preservation.MetaPacketID, owner.PacketID)
	objectMeta.AddU32(preservation.MetaAssetIDScheme, owner.idScheme)
	objectMeta.AddBytes(preservation.MetaAssetID, owner.assetID)
	objectMeta.AddU32(preservation.MetaItemID, it.ID)
	objectMeta.AddU32(preservation.MetaMPUSequence, it.MPUSequence)
	if app != nil {
		objectMeta.AddApplicationIdentity(app.Type, app.OrganizationID, app.ApplicationID)
	}
	in := preservation.PackInput{
		ID: id, Class: preservation.ClassApplicationItem, Flags: preservation.ObjectRawExact,
		Path: sanitisePath(it.Path + it.Name), MediaType: "application/octet-stream",
		Metadata: objectMeta, Stored: clone(it.Data),
	}
	switch {
	case !it.Announced, it.Compression == appdata.CompressionNone:
	case it.Compression == appdata.CompressionZlib:
		in.Compression = preservation.CompressionZlib
		in.OriginalSize = uint64(it.OriginalSize)
	default:
		in.Flags |= preservation.ObjectIncomplete
		p.addLoss(preservation.ScopeObject, preservation.ReasonEncrypted,
			preservation.SeverityPartial, in.ID,
			fmt.Sprintf("item declares compression type %d, which this version cannot expand", it.Compression), objectMeta)
	}
	if err := p.rec.AddObject(in); err != nil {
		return err
	}
	meta := copyMetadata(transport)
	meta.AddU16(preservation.MetaPacketID, owner.PacketID)
	meta.AddU32(preservation.MetaAssetIDScheme, owner.idScheme)
	meta.AddBytes(preservation.MetaAssetID, owner.assetID)
	meta.AddU32(preservation.MetaItemID, it.ID)
	meta.AddU32(preservation.MetaMPUSequence, it.MPUSequence)
	if app != nil {
		meta.AddApplicationIdentity(app.Type, app.OrganizationID, app.ApplicationID)
	}
	action := byte(preservation.ObjectActivate)
	if existed {
		action = preservation.ObjectReplace
	}
	p.rec.AddRecord(preservation.RecordObjectActivation, preservation.RecordRequired, ntp, meta,
		preservation.ObjectActivation{ObjectID: id, Generation: uint32(it.Version), Action: action}.Encode())
	p.applications[key] = applicationObjectState{id: id, digest: digest}
	return nil
}

func sanitisePath(path string) string {
	if preservation.ValidatePath(path) != nil {
		return ""
	}
	return path
}

func (p *preserver) addLoss(scope, reason, severity byte, logicalID uint64, message string, meta preservation.Metadata) {
	p.rec.AddLoss(preservation.LossEntry{
		Scope: scope, Reason: reason, Severity: severity,
		LogicalID: logicalID, Message: message, Metadata: meta,
	})
}

func clone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

func (p *preserver) addRawMediaPacket(meta preservation.Metadata, m mmtp.Packet, s *stream, ntp uint64, raw []byte) {
	meta.AddU16(preservation.MetaPacketID, m.PacketID)
	meta.AddU32(preservation.MetaPacketSequence, m.SequenceNumber)
	if m.HasCounter {
		meta.AddU32(preservation.MetaPacketCounter, m.PacketCounter)
	}
	if len(s.assetType) == 4 {
		meta.AddBytes(preservation.MetaAssetType, []byte(s.assetType))
	}
	if s.hasMMTTag {
		meta.AddU16(preservation.MetaComponentTag, s.mmtTag)
	}
	meta.AddText(preservation.MetaMediaType, "application/mmtp")
	if len(raw) == 0 {
		raw = m.Payload
	}
	p.rec.AddRecord(preservation.RecordGenericTimedData,
		preservation.RecordRawExact|preservation.RecordRequired, ntp, meta, clone(raw))
}
