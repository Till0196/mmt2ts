// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package siup はTSのPSI/SIをMMT側のテーブルと記述子へ写す。
package siup

import (
	"encoding/binary"
	"sort"

	"mmt2ts/internal/arib"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/si"
	"mmt2ts/internal/signaling"
)

type Converter struct {
	converted map[byte]int
	dropped   map[byte]int
	truncated map[byte]int
	outTag    map[byte]uint16
}

func New() *Converter {
	return &Converter{
		converted: map[byte]int{}, dropped: map[byte]int{},
		truncated: map[byte]int{}, outTag: map[byte]uint16{},
	}
}

type TagStat struct {
	TSTag     byte
	MHTag     uint16
	Converted int
	Dropped   int
	Truncated int
}

func (c *Converter) Stats() []TagStat {
	seen := map[byte]bool{}
	for tag := range c.converted {
		seen[tag] = true
	}
	for tag := range c.dropped {
		seen[tag] = true
	}
	out := make([]TagStat, 0, len(seen))
	for tag := range seen {
		out = append(out, TagStat{
			TSTag: tag, MHTag: c.outTag[tag],
			Converted: c.converted[tag], Dropped: c.dropped[tag], Truncated: c.truncated[tag],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Converted+a.Dropped != b.Converted+b.Dropped {
			return a.Converted+a.Dropped > b.Converted+b.Dropped
		}
		return a.TSTag < b.TSTag
	})
	return out
}

const (
	tsAudioStreamContent = 0x02
	mhAudioStreamContent = 0x03
)

var mhTag = map[byte]uint16{
	mpegts.DescService:            si.TagMHService,
	mpegts.DescShortEvent:         si.TagMHShortEvent,
	mpegts.DescExtendedEvent:      si.TagMHExtendedEvent,
	mpegts.DescComponent:          si.TagVideoComponent,
	mpegts.DescAudioComponent:     si.TagMHAudioComponent,
	mpegts.DescContent:            si.TagMHContent,
	mpegts.DescParentalRating:     si.TagMHParentalRating,
	mpegts.DescSeries:             si.TagMHSeries,
	mpegts.DescBroadcasterName:    si.TagMHBroadcasterName,
	mpegts.DescLocalTimeOffset:    si.TagMHLocalTimeOffset,
	mpegts.DescDigitalCopyControl: si.TagContentCopyControl,
	mpegts.DescSIParameter:        si.TagMHSIParameter,
	mpegts.DescLinkage:            si.TagMHLink,
}

func MHTableID(ts byte) (byte, bool) {
	switch {
	case ts == mpegts.TableIDEITPFActual:
		return si.TableIDMHEITPF, true
	case ts >= mpegts.TableIDEITScheduleFirst && ts <= mpegts.TableIDEITScheduleLast:
		return si.TableIDMHEITScheduleFirst + (ts - mpegts.TableIDEITScheduleFirst), true
	case ts == mpegts.TableIDSDTActual:
		return si.TableIDMHSDTActual, true
	case ts == mpegts.TableIDSDTOther:
		return si.TableIDMHSDTOther, true
	case ts == mpegts.TableIDTOT:
		return si.TableIDMHTOT, true
	case ts == mpegts.TableIDBIT:
		return si.TableIDMHBIT, true
	case ts == mpegts.TableIDCDT:
		return si.TableIDMHCDT, true
	default:
		return 0, false
	}
}

func (c *Converter) Descriptors(loop []byte) []byte {
	var out []byte
	for _, d := range splitTS(loop) {
		tag, ok := mhTag[d.tag]
		if !ok {
			c.dropped[d.tag]++
			continue
		}
		body, ok := c.body(d)
		if !ok {
			c.dropped[d.tag]++
			continue
		}
		if encoded, ok := appendMH(out, tag, body); ok {
			out = encoded
			c.converted[d.tag]++
			c.outTag[d.tag] = tag
		} else {
			c.dropped[d.tag]++
		}
	}
	return out
}

func (c *Converter) TLVDescriptors(loop []byte) []byte {
	var out []byte
	for _, d := range splitTS(loop) {
		var body []byte
		switch d.tag {
		case si.TagTLVNetworkName:
			body = c.text(d.body)
		case si.TagTLVServiceList, si.TagTLVSystemManagement,
			si.TagTLVSatelliteSystem, si.TagTLVCableSystem:
			body = d.body
		default:
			c.dropped[d.tag]++
			continue
		}
		if len(body) > 0xff {
			c.truncated[d.tag]++
			body = body[:0xff]
		}
		out = append(out, d.tag, byte(len(body)))
		out = append(out, body...)
		c.converted[d.tag]++
		c.outTag[d.tag] = uint16(d.tag)
	}
	return out
}

type remoteControlKey struct {
	keyID     byte
	serviceID uint16
}

func (c *Converter) remoteControlKeys(loop []byte) []remoteControlKey {
	var out []remoteControlKey
	for _, d := range splitTS(loop) {
		if d.tag != mpegts.DescTSInformation || len(d.body) < 2 {
			continue
		}
		c.converted[d.tag]++
		c.outTag[d.tag] = uint16(si.TagTLVRemoteControlKey)
		key := d.body[0]
		p := 2 + int(d.body[1]>>2)
		for range int(d.body[1] & 0x03) {
			if len(d.body) < p+2 {
				return out
			}
			count := int(d.body[p+1])
			p += 2
			for range count {
				if len(d.body) < p+2 {
					return out
				}
				out = append(out, remoteControlKey{key, binary.BigEndian.Uint16(d.body[p : p+2])})
				p += 2
			}
		}
	}
	return out
}

func appendRemoteControlKeyDescriptor(dst []byte, keys []remoteControlKey) []byte {
	seen := map[remoteControlKey]bool{}
	var body []byte
	for _, k := range keys {
		if seen[k] || len(body) >= 5*0xff {
			continue
		}
		seen[k] = true
		body = append(body, k.keyID)
		body = binary.BigEndian.AppendUint16(body, k.serviceID)
		body = append(body, 0xff, 0xff)
	}
	if len(body) == 0 {
		return dst
	}
	dst = append(dst, si.TagTLVRemoteControlKey, byte(len(body)+1), byte(len(body)/5))
	return append(dst, body...)
}

type tsDescriptor struct {
	tag  byte
	body []byte
}

func splitTS(loop []byte) []tsDescriptor {
	var out []tsDescriptor
	for len(loop) >= 2 {
		n := int(loop[1])
		if 2+n > len(loop) {
			break
		}
		out = append(out, tsDescriptor{tag: loop[0], body: loop[2 : 2+n]})
		loop = loop[2+n:]
	}
	return out
}

func appendMH(dst []byte, tag uint16, body []byte) ([]byte, bool) {
	dst = binary.BigEndian.AppendUint16(dst, tag)
	switch signaling.DescriptorLengthBytes(tag) {
	case 1:
		if len(body) > 0xff {
			return nil, false
		}
		dst = append(dst, byte(len(body)))
	case 2:
		if len(body) > 0xffff {
			return nil, false
		}
		dst = binary.BigEndian.AppendUint16(dst, uint16(len(body)))
	default:
		return nil, false
	}
	return append(dst, body...), true
}

func (c *Converter) text(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return []byte(arib.DecodeString(b).Text)
}

func (c *Converter) appendText8(dst []byte, tag byte, s []byte) []byte {
	if len(s) > 0xff {
		c.truncated[tag]++
		s = cutRunes(s, 0xff)
	}
	dst = append(dst, byte(len(s)))
	return append(dst, s...)
}

func cutRunes(s []byte, limit int) []byte {
	if len(s) <= limit {
		return s
	}
	for limit > 0 && s[limit]&0xc0 == 0x80 {
		limit--
	}
	return s[:limit]
}

func (c *Converter) body(d tsDescriptor) ([]byte, bool) {
	switch d.tag {
	case mpegts.DescService:
		return c.service(d.body)
	case mpegts.DescShortEvent:
		return c.shortEvent(d.body)
	case mpegts.DescExtendedEvent:
		return c.extendedEvent(d.body)
	case mpegts.DescComponent:
		return c.videoComponent(d.body)
	case mpegts.DescAudioComponent:
		return c.audioComponent(d.body)
	case mpegts.DescDigitalCopyControl:
		return c.copyControl(d.body)
	case mpegts.DescSeries:
		return c.series(d.body)
	case mpegts.DescSIParameter:
		return c.siParameter(d.body)
	case mpegts.DescLinkage:
		return c.linkage(d.body)
	case mpegts.DescBroadcasterName:
		return c.text(d.body), true
	case mpegts.DescContent, mpegts.DescParentalRating, mpegts.DescLocalTimeOffset:
		return d.body, true
	}
	return nil, false
}

func (c *Converter) service(b []byte) ([]byte, bool) {
	if len(b) < 3 {
		return nil, false
	}
	providerLen := int(b[1])
	if 2+providerLen >= len(b) {
		return nil, false
	}
	nameLen := int(b[2+providerLen])
	if 3+providerLen+nameLen > len(b) {
		return nil, false
	}
	out := []byte{b[0]}
	out = c.appendText8(out, mpegts.DescService, c.text(b[2:2+providerLen]))
	out = c.appendText8(out, mpegts.DescService, c.text(b[3+providerLen:3+providerLen+nameLen]))
	return out, true
}

func (c *Converter) shortEvent(b []byte) ([]byte, bool) {
	if len(b) < 5 {
		return nil, false
	}
	nameLen := int(b[3])
	if 4+nameLen >= len(b) {
		return nil, false
	}
	textLen := int(b[4+nameLen])
	if 5+nameLen+textLen > len(b) {
		return nil, false
	}
	out := append([]byte{}, b[0:3]...)
	out = c.appendText8(out, mpegts.DescShortEvent, c.text(b[4:4+nameLen]))
	text := c.text(b[5+nameLen : 5+nameLen+textLen])
	out = binary.BigEndian.AppendUint16(out, uint16(len(text)))
	return append(out, text...), true
}

func (c *Converter) extendedEvent(b []byte) ([]byte, bool) {
	if len(b) < 6 {
		return nil, false
	}
	itemsLen := int(b[4])
	if 5+itemsLen >= len(b) {
		return nil, false
	}
	var items []byte
	for in := b[5 : 5+itemsLen]; len(in) >= 2; {
		descLen := int(in[0])
		if 1+descLen >= len(in) {
			return nil, false
		}
		itemLen := int(in[1+descLen])
		if 2+descLen+itemLen > len(in) {
			return nil, false
		}
		items = c.appendText8(items, mpegts.DescExtendedEvent, c.text(in[1:1+descLen]))
		value := c.text(in[2+descLen : 2+descLen+itemLen])
		items = binary.BigEndian.AppendUint16(items, uint16(len(value)))
		items = append(items, value...)
		in = in[2+descLen+itemLen:]
	}
	textLen := int(b[5+itemsLen])
	if 6+itemsLen+textLen > len(b) {
		return nil, false
	}
	text := c.text(b[6+itemsLen : 6+itemsLen+textLen])
	if len(items) > 0xffff || len(text) > 0xffff {
		return nil, false
	}
	out := []byte{b[0]}
	out = append(out, b[1:4]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(items)))
	out = append(out, items...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(text)))
	return append(out, text...), true
}

type videoFormat struct {
	resolution  byte
	progressive bool
}

var videoFormats = map[byte]videoFormat{
	0x0: {resolution: 3},
	0x8: {resolution: 7, progressive: true},
	0x9: {resolution: 6, progressive: true},
	0xa: {resolution: 3, progressive: true},
	0xb: {resolution: 5},
	0xc: {resolution: 4, progressive: true},
	0xd: {resolution: 2, progressive: true},
	0xe: {resolution: 5, progressive: true},
	0xf: {resolution: 1, progressive: true},
}

func videoStreamContent(v byte) bool {
	return v == 0x1 || v == 0x5 || v == 0x9
}

func (c *Converter) videoComponent(b []byte) ([]byte, bool) {
	if len(b) < 6 || !videoStreamContent(b[0]&0x0f) {
		return nil, false
	}
	format, ok := videoFormats[b[1]>>4]
	if !ok {
		return nil, false
	}
	aspect := b[1] & 0x0f
	if aspect > 4 {
		aspect = 0
	}
	var scan byte
	if format.progressive {
		scan = 0x80
	}
	out := []byte{
		format.resolution<<4 | aspect,
		scan,
		0, b[2],
		0x0f,
	}
	out = append(out, b[3:6]...)
	return append(out, c.text(b[6:])...), true
}

func (c *Converter) copyControl(b []byte) ([]byte, bool) {
	if len(b) < 1 {
		return nil, false
	}
	hasBitrate := b[0]&0x20 != 0
	hasComponents := b[0]&0x10 != 0
	out := []byte{b[0] | 0x0f, 0xff}
	p := 1
	if hasBitrate {
		if len(b) < p+1 {
			return nil, false
		}
		out = append(out, b[p])
		p++
	}
	if !hasComponents {
		return out, true
	}
	if len(b) < p+1 {
		return nil, false
	}
	loopLen := int(b[p])
	p++
	if len(b) < p+loopLen {
		return nil, false
	}
	var loop []byte
	for in := b[p : p+loopLen]; len(in) >= 2; {
		entry := []byte{0, in[0], in[1] | 0x1f, 0xff}
		in = in[2:]
		if entry[2]&0x20 != 0 {
			if len(in) < 1 {
				return nil, false
			}
			entry = append(entry, in[0])
			in = in[1:]
		}
		loop = append(loop, entry...)
	}
	if len(loop) > 0xff {
		return nil, false
	}
	out = append(out, byte(len(loop)))
	return append(out, loop...), true
}

func (c *Converter) linkage(b []byte) ([]byte, bool) {
	if len(b) < 7 {
		return nil, false
	}
	return b, true
}

func (c *Converter) siParameter(b []byte) ([]byte, bool) {
	if len(b) < 3 {
		return nil, false
	}
	out := append([]byte{}, b[0:3]...)
	kept := false
	for p := 3; p+2 <= len(b); {
		length := int(b[p+1])
		if p+2+length > len(b) {
			return nil, false
		}
		if id, ok := MHTableID(b[p]); ok {
			out = append(out, id, b[p+1])
			out = append(out, b[p+2:p+2+length]...)
			kept = true
		}
		p += 2 + length
	}
	return out, kept
}

func (c *Converter) audioComponent(b []byte) ([]byte, bool) {
	if len(b) < 9 {
		return nil, false
	}
	streamContent := b[0] & 0x0f
	if streamContent == tsAudioStreamContent {
		streamContent = mhAudioStreamContent
	}
	out := []byte{b[0]&0xf0 | streamContent, b[1], 0, b[2]}
	out = append(out, b[3:9]...)
	p := 9
	if b[5]&0x80 != 0 {
		if len(b) < p+3 {
			return nil, false
		}
		out = append(out, b[p:p+3]...)
		p += 3
	}
	return append(out, c.text(b[p:])...), true
}

func (c *Converter) series(b []byte) ([]byte, bool) {
	if len(b) < 8 {
		return nil, false
	}
	out := append([]byte{}, b[0:8]...)
	return append(out, c.text(b[8:])...), true
}
