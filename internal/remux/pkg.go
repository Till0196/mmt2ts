// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"encoding/hex"

	"mmt2ts/internal/mpu"
	"mmt2ts/internal/siconv"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/tlv"
)

type flowKey struct {
	src, dst [16]byte
	ports    uint32
}

func datagramFlow(d tlv.Datagram) flowKey {
	var k flowKey
	copy(k.src[:], d.Src)
	copy(k.dst[:], d.Dst)
	k.ports = uint32(d.SrcPort)<<16 | uint32(d.DstPort)
	return k
}

type flow struct {
	index uint16
	sig   *signaling.Reassembler
	asm   *mpu.Reassembler
}

type route struct {
	flow     uint16
	packetID uint16
}

type pkg struct {
	index      int
	id         string
	flow       uint16
	serviceID  uint16
	pmtPID     uint16
	pcrPID     uint16
	pcrLocked  bool
	lastPCR    int64
	pmtVersion byte
	dirty      bool

	sidesc *siconv.Converter
	sigen  *siconv.Generator

	byKey   map[string]*stream
	order   []*stream
	usedTag map[byte]bool
	unconv  map[string]*UnconvertedAsset

	mptDescriptors []signaling.Descriptor
	decodeOrder    []string
	graphIssues    []string
}

func newPkg(index int, id []byte) *pkg {
	return &pkg{
		index:      index,
		id:         hex.EncodeToString(id),
		pmtVersion: 0x1f,
		byKey:      make(map[string]*stream),
		usedTag:    make(map[byte]bool),
		unconv:     make(map[string]*UnconvertedAsset),
	}
}

const (
	extraPIDBase       = 0x1800
	packagePIDStride   = 0x0100
	extraVideoOffset   = 0x0011
	extraAudioOffset   = 0x0040
	extraCaptionOffset = 0x0060
	maxExtraPackages   = (0x1f00 - extraPIDBase) / packagePIDStride
)

func (p *pkg) pidBase(kind Kind) uint16 {
	if p == nil || p.index == 0 {
		switch kind {
		case KindVideo:
			return videoPIDBase
		case KindAudio:
			return audioPIDBase
		case KindCaption:
			return captionPIDBase
		}
		return 0
	}
	n := p.index - 1
	if n >= maxExtraPackages {
		n = maxExtraPackages - 1
	}
	base := uint16(extraPIDBase + n*packagePIDStride)
	switch kind {
	case KindVideo:
		return base + extraVideoOffset
	case KindAudio:
		return base + extraAudioOffset
	case KindCaption:
		return base + extraCaptionOffset
	}
	return base
}

func (p *pkg) TSTag(mmtTag uint16) (byte, bool) {
	for _, s := range p.order {
		if s.hasMMTTag && s.mmtTag == mmtTag && s.emitted {
			return s.tsTag, true
		}
	}
	return 0, false
}

func (p *pkg) activeStreams() []*stream {
	out := make([]*stream, 0, len(p.order))
	for _, s := range p.order {
		if s.present && s.emitted && s.streamType != 0 {
			out = append(out, s)
		}
	}
	return out
}

func (p *pkg) programDescriptors() []byte {
	if len(p.mptDescriptors) == 0 {
		return nil
	}
	b, _ := p.sidesc.Loop(p.mptDescriptors, siconv.InProgram)
	return b
}
