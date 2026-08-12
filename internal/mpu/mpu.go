// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package mpu は分割されたMMTPペイロードからMFUを再構成する。
package mpu

import (
	"reflect"

	"mmt2ts/internal/mmtp"
)

type Unit struct {
	PacketID    uint16
	MPUSequence uint32
	Data        []byte
	RAP         bool
	Loss        bool
	LostPackets uint32
	Sample      uint32
	Offset      uint32
	Timed       bool
}

type Stats struct {
	Payloads              uint64
	Units                 uint64
	SequenceGaps          uint64
	LostPackets           uint64
	OutOfOrderPackets     uint64
	MetadataFragments     uint64
	NonTimedUnits         uint64
	ParseErrors           uint64
	FragmentErrors        uint64
	NonZeroOffsets        uint64
	NonZeroSamples        uint64
	NonZeroMovieFragments uint64
	NonZeroPriorities     uint64
	NonZeroDependencies   uint64
	ScrambledPackets      uint64
}

func (s Stats) Add(o Stats) Stats {
	sum := reflect.ValueOf(&s).Elem()
	other := reflect.ValueOf(o)
	for i := range sum.NumField() {
		sum.Field(i).SetUint(sum.Field(i).Uint() + other.Field(i).Uint())
	}
	return sum.Interface().(Stats)
}

type assetState struct {
	expectSeq      uint32
	haveSeq        bool
	fragActive     bool
	orphanFragment bool
	fragUnit       mmtp.DataUnit
	fragMPU        uint32
	fragRAP        bool
	fragBuf        []byte
}

const MaxFragmentBytes = 64 << 20

type Reassembler struct {
	assets      map[uint16]*assetState
	stats       Stats
	units       []mmtp.DataUnit
	out         []Unit
	maxFragment int
}

func New() *Reassembler {
	return newWithFragmentLimit(MaxFragmentBytes)
}

func newWithFragmentLimit(limit int) *Reassembler {
	return &Reassembler{
		assets:      make(map[uint16]*assetState),
		units:       make([]mmtp.DataUnit, 0, 64),
		maxFragment: limit,
	}
}

func (r *Reassembler) Stats() Stats { return r.stats }

func (r *Reassembler) Push(p mmtp.Packet) []Unit {
	r.out = r.out[:0]
	st := r.assets[p.PacketID]
	if st == nil {
		st = &assetState{}
		r.assets[p.PacketID] = st
	}
	if !r.track(p, st) {
		return r.out
	}
	if p.Scrambled {
		r.stats.ScrambledPackets++
		r.loss(p.PacketID, st)
		return r.out
	}

	payload, err := mmtp.ParseMPU(p.Payload, r.units)
	if err != nil {
		r.stats.ParseErrors++
		r.loss(p.PacketID, st)
		return r.out
	}
	r.units = payload.Units[:0]
	r.stats.Payloads++
	if payload.FragmentType != mmtp.FragmentTypeMFU {
		r.stats.MetadataFragments++
		return r.out
	}
	if !payload.Timed {
		r.stats.NonTimedUnits += uint64(len(payload.Units))
		for _, u := range payload.Units {
			r.out = append(r.out, Unit{PacketID: p.PacketID, MPUSequence: payload.MPUSequence, Data: u.Data, Sample: u.Sample})
		}
		return r.out
	}

	if payload.Aggregation {
		r.dropFragment(p.PacketID, st)
		st.orphanFragment = false
		for _, u := range payload.Units {
			r.emit(p.PacketID, payload.MPUSequence, u, u.Data, p.RAP)
		}
		return r.out
	}
	u := payload.Units[0]
	switch payload.Fragmentation {
	case mmtp.FragmentIndicatorComplete:
		r.dropFragment(p.PacketID, st)
		st.orphanFragment = false
		r.emit(p.PacketID, payload.MPUSequence, u, u.Data, p.RAP)
	case mmtp.FragmentIndicatorFirst:
		r.dropFragment(p.PacketID, st)
		st.orphanFragment = false
		if r.fragmentOverflows(0, len(u.Data)) {
			r.overflowFragment(p.PacketID, st)
			return r.out
		}
		st.fragActive, st.fragUnit, st.fragMPU, st.fragRAP = true, u, payload.MPUSequence, p.RAP
		st.fragBuf = append(st.fragBuf[:0], u.Data...)
	case mmtp.FragmentIndicatorMiddle:
		if !st.fragActive {
			if !st.orphanFragment {
				r.stats.FragmentErrors++
				r.loss(p.PacketID, st)
				st.orphanFragment = true
			}
			return r.out
		}
		if r.fragmentOverflows(len(st.fragBuf), len(u.Data)) {
			r.overflowFragment(p.PacketID, st)
			return r.out
		}
		st.fragBuf = append(st.fragBuf, u.Data...)
	case mmtp.FragmentIndicatorLast:
		if !st.fragActive {
			if !st.orphanFragment {
				r.stats.FragmentErrors++
				r.loss(p.PacketID, st)
			}
			st.orphanFragment = false
			return r.out
		}
		if r.fragmentOverflows(len(st.fragBuf), len(u.Data)) {
			r.overflowFragment(p.PacketID, st)
			st.orphanFragment = false
			return r.out
		}
		st.fragBuf = append(st.fragBuf, u.Data...)
		st.fragActive = false
		r.emit(p.PacketID, st.fragMPU, st.fragUnit, st.fragBuf, st.fragRAP)
	}
	return r.out
}

func (r *Reassembler) track(p mmtp.Packet, st *assetState) bool {
	if !st.haveSeq {
		st.expectSeq, st.haveSeq = p.SequenceNumber+1, true
		return true
	}
	switch diff := p.SequenceNumber - st.expectSeq; {
	case diff == 0:
	case diff < 1<<31:
		r.stats.SequenceGaps++
		r.stats.LostPackets += uint64(diff)
		r.lostPackets(p.PacketID, st, diff)
	default:
		r.stats.OutOfOrderPackets++
		return false
	}
	st.expectSeq = p.SequenceNumber + 1
	return true
}

func (r *Reassembler) emit(pid uint16, mpuSeq uint32, u mmtp.DataUnit, data []byte, rap bool) {
	if u.MovieFragment != 0 {
		r.stats.NonZeroMovieFragments++
	}
	if u.Offset != 0 {
		r.stats.NonZeroOffsets++
	}
	if u.Sample != 0 {
		r.stats.NonZeroSamples++
	}
	if u.Priority != 0 {
		r.stats.NonZeroPriorities++
	}
	if u.DependencyCounter != 0 {
		r.stats.NonZeroDependencies++
	}
	r.stats.Units++
	r.out = append(r.out, Unit{
		PacketID:    pid,
		MPUSequence: mpuSeq,
		Data:        data,
		RAP:         rap,
		Sample:      u.Sample,
		Offset:      u.Offset,
		Timed:       true,
	})
}

func (r *Reassembler) loss(pid uint16, st *assetState) {
	r.lostPackets(pid, st, 0)
}

func (r *Reassembler) lostPackets(pid uint16, st *assetState, count uint32) {
	st.fragActive = false
	if n := len(r.out); n > 0 && r.out[n-1].Loss && r.out[n-1].PacketID == pid {
		r.out[n-1].LostPackets += count
		return
	}
	r.out = append(r.out, Unit{PacketID: pid, Loss: true, LostPackets: count})
}

func (r *Reassembler) fragmentOverflows(have, n int) bool {
	return have+n > r.maxFragment
}

func (r *Reassembler) overflowFragment(pid uint16, st *assetState) {
	r.stats.FragmentErrors++
	st.orphanFragment = true
	st.fragBuf = nil
	r.loss(pid, st)
}

func (r *Reassembler) dropFragment(pid uint16, st *assetState) {
	if st.fragActive {
		r.stats.FragmentErrors++
		st.fragActive = false
		r.out = append(r.out, Unit{PacketID: pid, Loss: true})
	}
}
