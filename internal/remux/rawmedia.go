// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/preservation"
)

type rawMediaPacket struct {
	meta preservation.Metadata
	m    mmtp.Packet
	ntp  uint64
	raw  []byte
}

type rawMediaState struct {
	prefix   []rawMediaPacket
	poisoned bool
}

func copyMetadata(in preservation.Metadata) preservation.Metadata {
	out := make(preservation.Metadata, len(in))
	for i := range in {
		out[i] = preservation.Meta{Type: in[i].Type, Value: clone(in[i].Value)}
	}
	return out
}

func savedMediaPacket(meta preservation.Metadata, m mmtp.Packet, ntp uint64, raw []byte) rawMediaPacket {
	m.Payload = nil
	m.Extension = nil
	return rawMediaPacket{meta: copyMetadata(meta), m: m, ntp: ntp, raw: clone(raw)}
}

func (c *converter) preserveRawMedia(s *stream, m mmtp.Packet, raw []byte) {
	if c.pres == nil {
		return
	}
	if s.rawMedia == nil {
		s.rawMedia = &rawMediaState{}
	}
	st := s.rawMedia
	packet := savedMediaPacket(c.transportMeta(), m, c.currentNTP, raw)
	emit := func(p rawMediaPacket) { c.pres.addRawMediaPacket(p.meta, p.m, s, p.ntp, p.raw) }
	emitPrefix := func() {
		for _, p := range st.prefix {
			emit(p)
		}
		st.prefix = st.prefix[:0]
	}

	if m.Scrambled {
		emitPrefix()
		emit(packet)
		st.poisoned = true
		return
	}

	payload, err := mmtp.ParseMPU(m.Payload, nil)
	if err != nil || payload.FragmentType != mmtp.FragmentTypeMFU || !payload.Timed {
		if st.poisoned {
			emit(packet)
		}
		return
	}
	if payload.Aggregation || payload.Fragmentation == mmtp.FragmentIndicatorComplete {
		emitPrefix()
		st.poisoned = false
		return
	}
	switch payload.Fragmentation {
	case mmtp.FragmentIndicatorFirst:
		emitPrefix()
		st.poisoned = false
		st.prefix = append(st.prefix, packet)
	case mmtp.FragmentIndicatorMiddle:
		if st.poisoned {
			emit(packet)
		} else {
			st.prefix = append(st.prefix, packet)
		}
	case mmtp.FragmentIndicatorLast:
		if st.poisoned {
			emit(packet)
			st.poisoned = false
		} else {
			st.prefix = append(st.prefix, packet)
			st.prefix = st.prefix[:0]
		}
	}
}
