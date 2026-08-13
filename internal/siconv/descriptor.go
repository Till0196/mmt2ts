// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package siconv

import (
	"fmt"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/si"
)

type Status int

const (
	StatusConverted Status = iota
	StatusUnsupported
	StatusInvalid
)

func (s Status) String() string {
	switch s {
	case StatusConverted:
		return "converted"
	case StatusUnsupported:
		return "unsupported"
	default:
		return "invalid"
	}
}

type Result struct {
	Tag    uint16
	TLV    bool
	Status Status
	Reason string
	Bytes  []byte
	Raw    []byte
}

type TagMapper interface {
	TSTag(mmtTag uint16) (byte, bool)
}

type Converter struct {
	Text  *Text
	Tags  TagMapper
	Stats map[TagKey]*TagStat
}

type TagKey struct {
	TLV bool
	Tag uint16
}

type TagStat struct {
	Converted   uint64
	Unsupported uint64
	Invalid     uint64
	Reason      string
}

func NewConverter(text *Text, tags TagMapper) *Converter {
	return &Converter{Text: text, Tags: tags, Stats: make(map[TagKey]*TagStat)}
}

func (c *Converter) record(r Result) {
	key := TagKey{TLV: r.TLV, Tag: r.Tag}
	s := c.Stats[key]
	if s == nil {
		s = &TagStat{}
		c.Stats[key] = s
	}
	switch r.Status {
	case StatusConverted:
		s.Converted++
	case StatusUnsupported:
		s.Unsupported++
		s.Reason = r.Reason
	default:
		s.Invalid++
		s.Reason = r.Reason
	}
}

func (c *Converter) Loop(list []si.Descriptor, where Placement) ([]byte, []Result) {
	var out []byte
	results := make([]Result, 0, len(list))
	for _, d := range list {
		for _, r := range c.one(d, where) {
			c.record(r)
			results = append(results, r)
			out = append(out, r.Bytes...)
		}
	}
	return out, results
}

func (c *Converter) LoopTLV(list []si.Descriptor, where Placement) ([]byte, []Result) {
	var out []byte
	results := make([]Result, 0, len(list))
	for _, d := range list {
		var r Result
		switch d.Tag {
		case si.TagTLVNetworkName:
			name, _, _ := c.Text.EncodeLimit(string(d.Data), mpegts.MaxDescriptorBody)
			if b, ok := mpegts.NetworkNameDescriptor(name); ok {
				r = converted(d, b)
			} else {
				r = invalid(d)
			}
		case si.TagTLVServiceList:
			entries := si.ParseServiceList(d.Data)
			if len(entries) == 0 {
				r = invalid(d)
				break
			}
			list := make([]mpegts.ServiceListEntry, 0, len(entries))
			for _, e := range entries {
				list = append(list, mpegts.ServiceListEntry{ServiceID: e.ServiceID, Type: e.Type})
			}
			if b, ok := mpegts.ServiceListDescriptor(list); ok {
				r = converted(d, b)
			} else {
				r = invalid(d)
			}
		case si.TagTLVSystemManagement:
			sm, ok := si.ParseSystemManagement(d.Data)
			if !ok {
				r = invalid(d)
				break
			}
			if b, ok := mpegts.SystemManagementDescriptor(sm.SystemManagementID, sm.Additional); ok {
				r = converted(d, b)
			} else {
				r = invalid(d)
			}
		case si.TagTLVSatelliteSystem:
			r = unsupported(d, "the TLV satellite delivery system describes a carrier the transport stream no longer has")
		case si.TagTLVCableSystem:
			r = unsupported(d, "the TLV cable delivery system describes a carrier the transport stream no longer has")
		case si.TagTLVRemoteControlKey:
			if _, ok := si.ParseRemoteControlKey(d.Data); ok {
				// nit() converts an unambiguous service assignment to the
				// remote_control_key_id of each TS information descriptor.
				r = converted(d, nil)
			} else {
				r = invalid(d)
			}
		default:
			r = unsupported(d, "no converter for this TLV-SI tag")
		}
		r.TLV = true
		c.record(r)
		results = append(results, r)
		out = append(out, r.Bytes...)
	}
	return out, results
}

type Placement int

const (
	InEvent Placement = iota
	InService
	InNetwork
	InProgram
)

func unsupported(d si.Descriptor, reason string) Result {
	return Result{Tag: d.Tag, Status: StatusUnsupported, Reason: reason, Raw: d.Data}
}

func invalid(d si.Descriptor) Result {
	return Result{Tag: d.Tag, Status: StatusInvalid, Reason: "descriptor body did not parse", Raw: d.Data}
}

func converted(d si.Descriptor, b []byte) Result {
	return Result{Tag: d.Tag, Status: StatusConverted, Bytes: b, Raw: d.Data}
}

func convertedNote(d si.Descriptor, b []byte, reason string) Result {
	return Result{Tag: d.Tag, Status: StatusConverted, Bytes: b, Raw: d.Data, Reason: reason}
}

func (c *Converter) one(d si.Descriptor, where Placement) []Result {
	switch d.Tag {
	case si.TagMHShortEvent:
		return []Result{c.shortEvent(d)}
	case si.TagMHExtendedEvent:
		return c.extendedEvent(d)
	case si.TagMHService:
		return []Result{c.service(d)}
	case si.TagVideoComponent:
		return []Result{c.videoComponent(d)}
	case si.TagMHAudioComponent:
		return []Result{c.audioComponent(d)}
	case si.TagMHContent:
		return []Result{c.content(d)}
	case si.TagMHParentalRating:
		return []Result{c.parentalRating(d)}
	case si.TagMHSeries:
		return []Result{c.series(d)}
	case si.TagMHEventGroup:
		return []Result{c.eventGroup(d)}
	case si.TagContentCopyControl:
		return []Result{c.copyControl(d)}
	case si.TagMHLogoTransmission:
		return []Result{c.logoTransmission(d)}
	case si.TagMHBroadcasterName:
		return []Result{c.broadcasterName(d)}
	case si.TagMHDataComponent:
		return []Result{c.dataComponent(d, where)}
	case si.TagMHLocalTimeOffset:
		return []Result{c.localTimeOffset(d)}
	case si.TagMHSIParameter:
		return []Result{c.siParameter(d)}
	case si.TagMHStreamIdentifier:
		return []Result{unsupported(d, "component tag is carried by the PMT stream identifier descriptor")}
	case si.TagMHStuffing:
		return []Result{unsupported(d, "stuffing carries no information")}
	case si.TagMHBroadcastID, si.TagMHNetworkIdentification:
		return []Result{unsupported(d, "used for identity cross-checks, not written into an SI loop")}
	case si.TagContentUsageControl:
		return []Result{unsupported(d, "no transport stream descriptor preserves remote viewing and retention control")}
	case si.TagMHComponentGroup:
		return []Result{c.componentGroup(d)}
	case si.TagMHEmergencyInformation, si.TagEmergencyNews:
		return []Result{unsupported(d, "emergency signalling is preserved rather than reinterpreted")}
	default:
		return []Result{unsupported(d, "no converter for this tag")}
	}
}

func (c *Converter) shortEvent(d si.Descriptor) Result {
	se, ok := si.ParseShortEvent(d.Data)
	if !ok {
		return invalid(d)
	}
	name, _, _ := c.Text.EncodeLimit(se.Name, mpegts.MaxDescriptorBody-5)
	room := mpegts.MaxDescriptorBody - 5 - len(name)
	if room < 0 {
		room = 0
	}
	text, _, _ := c.Text.EncodeLimit(se.Text, room)
	b, ok := mpegts.ShortEventDescriptor(language(se.Language), name, text)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) extendedEvent(d si.Descriptor) []Result {
	ee, ok := si.ParseExtendedEvent(d.Data)
	if !ok {
		return []Result{invalid(d)}
	}
	lang := language(ee.Language)
	var groups [][]mpegts.ExtendedEventItem
	var current []mpegts.ExtendedEventItem
	used := 0
	for _, it := range ee.Items {
		desc, _, _ := c.Text.EncodeLimit(it.Description, 0xff)
		item, _, _ := c.Text.EncodeLimit(it.Item, 0xff)
		size := len(desc) + len(item) + 2
		if used+size > 0xf0 && len(current) > 0 {
			groups = append(groups, current)
			current, used = nil, 0
		}
		current = append(current, mpegts.ExtendedEventItem{Description: desc, Item: item})
		used += size
	}
	if len(current) > 0 || len(groups) == 0 {
		groups = append(groups, current)
	}
	text, _, _ := c.Text.EncodeLimit(ee.Text, 0xff-2)
	out := make([]Result, 0, len(groups))
	last := byte(len(groups) - 1)
	for i, g := range groups {
		var body []byte
		if i == len(groups)-1 {
			body = text
		}
		b, ok := mpegts.ExtendedEventDescriptor(byte(i), last, lang, g, body)
		if !ok {
			out = append(out, invalid(d))
			continue
		}
		out = append(out, converted(d, b))
	}
	return out
}

func (c *Converter) service(d si.Descriptor) Result {
	s, ok := si.ParseService(d.Data)
	if !ok {
		return invalid(d)
	}
	provider, _, _ := c.Text.EncodeLimit(s.Provider, 0x7f)
	name, _, _ := c.Text.EncodeLimit(s.Name, mpegts.MaxDescriptorBody-3-len(provider))
	b, ok := mpegts.ServiceDescriptor(s.Type, provider, name)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

const VideoStreamContent = 0x01

func VideoComponentType(v *si.VideoComponent) byte {
	resolution := [...]byte{0x00, 0xf0, 0xd0, 0xa0, 0xc0, 0xe0, 0x90, 0x80}
	if int(v.Resolution) >= len(resolution) {
		return 0
	}
	return resolution[v.Resolution] | v.AspectRatio&0x0f
}

func (c *Converter) videoComponent(d si.Descriptor) Result {
	v, ok := si.ParseVideoComponent(d.Data)
	if !ok {
		return invalid(d)
	}
	tag, ok := c.tag(v.ComponentTag)
	if !ok {
		return unsupported(d, fmt.Sprintf("component tag %#04x is not in the output", v.ComponentTag))
	}
	text, _, _ := c.Text.EncodeLimit(v.Text, mpegts.MaxDescriptorBody-6)
	b, ok := mpegts.ComponentDescriptor(VideoStreamContent, VideoComponentType(v), tag, language(v.Language), text)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) componentGroup(d si.Descriptor) Result {
	g, ok := si.ParseComponentGroup(d.Data)
	if !ok {
		return invalid(d)
	}
	dropped := 0
	groups := make([]mpegts.ComponentGroup, 0, len(g.Groups))
	for _, in := range g.Groups {
		out := mpegts.ComponentGroup{ID: in.ID, TotalBitRate: in.TotalBitRate}
		for _, u := range in.CAUnits {
			unit := mpegts.ComponentCAUnit{ID: u.ID}
			for _, mmtTag := range u.Tags {
				tag, ok := c.tag(mmtTag)
				if !ok {
					dropped++
					continue
				}
				unit.Tags = append(unit.Tags, tag)
			}
			if len(unit.Tags) > 0 {
				out.CAUnits = append(out.CAUnits, unit)
			}
		}
		if len(out.CAUnits) == 0 {
			dropped++
			continue
		}
		out.Text, _, _ = c.Text.EncodeLimit(in.Text, mpegts.MaxDescriptorBody-1)
		groups = append(groups, out)
	}
	if len(groups) == 0 {
		return unsupported(d, "no component of any group is present in the output")
	}
	b, ok := mpegts.ComponentGroupDescriptor(g.Type, g.HasTotalBitRate, groups)
	if !ok {
		return invalid(d)
	}
	if dropped > 0 {
		return convertedNote(d, b, fmt.Sprintf("%d component group entries are not in the output and were left out", dropped))
	}
	return converted(d, b)
}

func (c *Converter) audioComponent(d si.Descriptor) Result {
	a, ok := si.ParseAudioComponent(d.Data)
	if !ok {
		return invalid(d)
	}
	tag, ok := c.tag(a.ComponentTag)
	if !ok {
		return unsupported(d, fmt.Sprintf("component tag %#04x is not in the output", a.ComponentTag))
	}
	lang2 := a.Language2
	text, _, _ := c.Text.EncodeLimit(string(a.Text), mpegts.MaxDescriptorBody-12)
	streamType := byte(mpegts.StreamTypeADTSAAC)
	if a.ComponentType&0x1f == 0x11 {
		streamType = mpegts.StreamTypeLATMAAC
	}
	b, ok := mpegts.AudioComponentDescriptor(0x02, a.ComponentType, tag,
		streamType, a.SimulcastGroupTag, a.Flags, language(a.Language), lang2, text)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) content(d si.Descriptor) Result {
	nibbles := si.ParseContent(d.Data)
	if len(nibbles) == 0 {
		return invalid(d)
	}
	out := make([]mpegts.ContentNibble, 0, len(nibbles))
	for _, n := range nibbles {
		out = append(out, mpegts.ContentNibble{Level1: n.Level1, Level2: n.Level2, User1: n.User1, User2: n.User2})
	}
	b, ok := mpegts.ContentDescriptor(out)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) parentalRating(d si.Descriptor) Result {
	entries := si.ParseParentalRating(d.Data)
	if len(entries) == 0 {
		return invalid(d)
	}
	out := make([]mpegts.ParentalRatingEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, mpegts.ParentalRatingEntry{Country: e.Country, Rating: e.Rating})
	}
	b, ok := mpegts.ParentalRatingDescriptor(out)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) series(d si.Descriptor) Result {
	s, ok := si.ParseSeries(d.Data)
	if !ok {
		return invalid(d)
	}
	name, _, _ := c.Text.EncodeLimit(s.Name, mpegts.MaxDescriptorBody-8)
	b, ok := mpegts.SeriesDescriptor(s.SeriesID, s.RepeatLabel, s.ProgramPattern,
		s.ExpireDateValid, s.ExpireDate, s.EpisodeNumber, s.LastEpisodeNumber, name)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) eventGroup(d si.Descriptor) Result {
	g, ok := si.ParseEventGroup(d.Data)
	if !ok {
		return invalid(d)
	}
	if g.GroupType == 4 || g.GroupType == 5 {
		return unsupported(d, "other-network event groups reference streams that are not in the output")
	}
	events := make([]mpegts.EventGroupEntry, 0, len(g.Events))
	for _, e := range g.Events {
		events = append(events, mpegts.EventGroupEntry{ServiceID: e.ServiceID, EventID: e.EventID})
	}
	b, ok := mpegts.EventGroupDescriptor(g.GroupType, events, g.Private)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) copyControl(d si.Descriptor) Result {
	cc, ok := si.ParseCopyControl(d.Data)
	if !ok {
		return invalid(d)
	}
	components := make([]mpegts.DigitalCopyControlComponent, 0, len(cc.Components))
	for _, comp := range cc.Components {
		tag, ok := c.tag(comp.ComponentTag)
		if !ok {
			return unsupported(d, fmt.Sprintf("copy control names component tag %#04x, which is not in the output", comp.ComponentTag))
		}
		components = append(components, mpegts.DigitalCopyControlComponent{
			ComponentTag:     tag,
			RecordingControl: comp.RecordingControl,
			MaximumBitrate:   comp.MaximumBitrate,
			HasBitrate:       comp.HasBitrate,
		})
	}
	b, ok := mpegts.DigitalCopyControlDescriptor(cc.RecordingControl, cc.MaximumBitrate, cc.HasBitrate, components)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) logoTransmission(d si.Descriptor) Result {
	l, ok := si.ParseLogoTransmission(d.Data)
	if !ok {
		return invalid(d)
	}
	var text []byte
	if l.Type == 0x03 {
		text, _, _ = c.Text.EncodeLimit(l.Text, mpegts.MaxDescriptorBody-1)
	}
	b, ok := mpegts.LogoTransmissionDescriptor(l.Type, l.LogoID, l.LogoVersion, l.DownloadDataID, text)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) broadcasterName(d si.Descriptor) Result {
	name, _, _ := c.Text.EncodeLimit(string(d.Data), mpegts.MaxDescriptorBody)
	b, ok := mpegts.BroadcasterNameDescriptor(name)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) dataComponent(d si.Descriptor, where Placement) Result {
	dc, ok := si.ParseDataComponent(d.Data)
	if !ok {
		return invalid(d)
	}
	if where != InProgram {
		return unsupported(d, "the data coding system descriptor belongs in the PMT elementary stream loop")
	}
	b, ok := mpegts.DataComponentDescriptor(dc.ComponentID, dc.AdditionalInfo)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) localTimeOffset(d si.Descriptor) Result {
	entries := si.ParseLocalTimeOffset(d.Data)
	if len(entries) == 0 {
		return invalid(d)
	}
	out := make([]mpegts.LocalTimeOffsetEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, mpegts.LocalTimeOffsetEntry{
			Country:      e.Country,
			RegionID:     e.RegionID,
			Negative:     e.Negative,
			OffsetBCD:    e.OffsetBCD,
			TimeOfChange: e.TimeOfChange,
			NextBCD:      e.NextOffsetBCD,
		})
	}
	b, ok := mpegts.LocalTimeOffsetDescriptor(out)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func (c *Converter) siParameter(d si.Descriptor) Result {
	p, ok := si.ParseSIParameter(d.Data)
	if !ok {
		return invalid(d)
	}
	tables := make([]mpegts.SIParameterTable, 0, len(p.Tables))
	for _, t := range p.Tables {
		id, ok := TSTableID(t.TableID)
		if !ok {
			// MMT-SI also advertises tables which have no MPEG-2 TS
			// counterpart (for example AMT, table_id 0xfe).  Omit only
			// those entries; a supported entry in the same descriptor is
			// still useful in the TS SI parameter descriptor.
			continue
		}
		tables = append(tables, mpegts.SIParameterTable{TableID: id, Description: t.Description})
	}
	if len(tables) == 0 {
		return unsupported(d, "SI parameter names only MMT tables without a transport stream counterpart")
	}
	b, ok := mpegts.SIParameterDescriptor(p.Version, p.UpdateTime, tables)
	if !ok {
		return invalid(d)
	}
	return converted(d, b)
}

func TSTableID(mmt byte) (byte, bool) {
	switch {
	case mmt == si.TableIDMHEITPF:
		return mpegts.TableIDEITPFActual, true
	case mmt >= si.TableIDMHEITScheduleFirst && mmt <= si.TableIDMHEITScheduleLast:
		return mpegts.TableIDEITScheduleFirst + (mmt - si.TableIDMHEITScheduleFirst), true
	case mmt == si.TableIDMHSDTActual:
		return mpegts.TableIDSDTActual, true
	case mmt == si.TableIDMHSDTOther:
		return mpegts.TableIDSDTOther, true
	case mmt == si.TableIDMHTOT:
		return mpegts.TableIDTOT, true
	case mmt == si.TableIDMHBIT:
		return mpegts.TableIDBIT, true
	case mmt == si.TableIDMHCDT:
		return mpegts.TableIDCDT, true
	default:
		return 0, false
	}
}

func (c *Converter) tag(mmtTag uint16) (byte, bool) {
	if c.Tags == nil {
		return 0, false
	}
	return c.Tags.TSTag(mmtTag)
}

func language(s string) string {
	if len(s) != 3 {
		return "und"
	}
	return s
}
