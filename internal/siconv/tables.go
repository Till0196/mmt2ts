// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package siconv はMMT-SIの意味を保ちながらTSのPSI/SIへ写す。
package siconv

import (
	"bytes"
	"fmt"
	"sort"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/si"
	"mmt2ts/internal/timeline"
)

type Table struct {
	Name     string
	PID      uint16
	Sections [][]byte
	Interval int64
}

const (
	IntervalNIT      = 10 * timeline.Hz
	IntervalSDT      = 2 * timeline.Hz
	IntervalEITPF    = 2 * timeline.Hz
	IntervalSchedule = 10 * timeline.Hz
	IntervalTOT      = 5 * timeline.Hz
	IntervalBIT      = 10 * timeline.Hz
	IntervalCDT      = 10 * timeline.Hz
)

type Generator struct {
	Conv  *Converter
	State *si.State

	ServiceID uint16
	TSID      uint16

	versions   map[string]byte
	signatures map[string][]byte
	notes      map[string]string
	order      []string
}

func NewGenerator(conv *Converter, state *si.State) *Generator {
	return &Generator{
		Conv:       conv,
		State:      state,
		versions:   make(map[string]byte),
		signatures: make(map[string][]byte),
		notes:      make(map[string]string),
	}
}

func (g *Generator) versioned(key string, build func(version byte) [][]byte) [][]byte {
	probe := flatten(build(0))
	if old, ok := g.signatures[key]; ok {
		if bytes.Equal(old, probe) {
			return build(g.versions[key])
		}
		g.versions[key] = (g.versions[key] + 1) & 0x1f
	}
	g.signatures[key] = probe
	return build(g.versions[key])
}

func lowestKeyed[V any](m map[uint16]*V) *V {
	var chosen *V
	var key uint16
	for k, v := range m {
		if chosen == nil || k < key {
			chosen, key = v, k
		}
	}
	return chosen
}

func flatten(sections [][]byte) []byte {
	var out []byte
	for _, s := range sections {
		out = append(out, s...)
	}
	return out
}

func (g *Generator) diagnose(key, format string, args ...any) {
	if _, ok := g.notes[key]; !ok {
		g.order = append(g.order, key)
	}
	g.notes[key] = fmt.Sprintf(format, args...)
}

func (g *Generator) resolved(key string) { delete(g.notes, key) }

func (g *Generator) Diagnostics() []string {
	var out []string
	for _, key := range g.order {
		if note, ok := g.notes[key]; ok {
			out = append(out, note)
		}
	}
	return out
}

func (g *Generator) Build() []Table {
	return append(g.BuildStream(), g.BuildService()...)
}

func (g *Generator) BuildStream() []Table {
	var out []Table
	if t, ok := g.nit(); ok {
		out = append(out, t)
	}
	if t, ok := g.sdt(); ok {
		out = append(out, t)
	}
	if t, ok := g.tot(); ok {
		out = append(out, t)
	}
	if t, ok := g.bit(); ok {
		out = append(out, t)
	}
	if t, ok := g.cdt(); ok {
		out = append(out, t)
	}
	return out
}

func (g *Generator) BuildService() []Table {
	var out []Table
	if t, ok := g.eitPF(); ok {
		out = append(out, t)
	}
	if t, ok := g.eitSchedule(); ok {
		out = append(out, t)
	}
	return out
}

func (g *Generator) nit() (Table, bool) {
	nit, ok := g.State.SelfNetwork()
	if !ok {
		g.diagnose("nit", "NIT: no current self-network TLV-NIT received yet")
		return Table{}, false
	}
	network, _ := g.Conv.LoopTLV(nit.Descriptors, InNetwork)
	streams := make([]mpegts.NITStream, 0, len(nit.Streams))
	for _, s := range nit.Streams {
		desc, _ := g.Conv.LoopTLV(s.Descriptors, InNetwork)
		streams = append(streams, mpegts.NITStream{
			TransportStreamID: g.TSID,
			OriginalNetworkID: s.OriginalNetworkID,
			Descriptors:       desc,
		})
	}
	sections := g.versioned("nit", func(v byte) [][]byte {
		return mpegts.BuildNIT(mpegts.TableIDNITActual, nit.NetworkID, v, network, streams)
	})
	g.resolved("nit")
	return Table{Name: "NIT", PID: mpegts.PIDNIT, Sections: sections, Interval: IntervalNIT}, true
}

func (g *Generator) sdt() (Table, bool) {
	sdt, ok := g.State.ActualSDT()
	if !ok {
		g.diagnose("sdt", "SDT: no current self-stream MH-SDT received yet")
		return Table{}, false
	}
	services := make([]mpegts.SDTService, 0, len(sdt.Services))
	for i := range sdt.Services {
		s := &sdt.Services[i]
		desc, _ := g.Conv.Loop(s.Descriptors, InService)
		services = append(services, mpegts.SDTService{
			ServiceID:        s.ServiceID,
			ScheduleFlag:     s.ScheduleFlag,
			PresentFollowing: s.PresentFollowing,
			RunningStatus:    s.RunningStatus,
			FreeCA:           s.FreeCA,
			Descriptors:      desc,
		})
	}
	sections := g.versioned("sdt", func(v byte) [][]byte {
		return mpegts.BuildSDT(mpegts.TableIDSDTActual, g.TSID, sdt.OriginalNetworkID, v, services)
	})
	g.resolved("sdt")
	return Table{Name: "SDT", PID: mpegts.PIDSDT, Sections: sections, Interval: IntervalSDT}, true
}

func (g *Generator) eitPF() (Table, bool) {
	var sections [][]byte
	build := func(v byte) [][]byte {
		var out [][]byte
		for number := byte(0); number <= 1; number++ {
			eit, ok := g.State.EIT[si.EITKey{TableID: si.TableIDMHEITPF, ServiceID: g.ServiceID, Section: number}]
			var events []mpegts.EITEvent
			var onID uint16
			if ok {
				events = g.events(eit.Events, false)
				onID = eit.OriginalNetworkID
			} else if id := g.State.Identity(g.ServiceID); id.HaveOriginalID {
				onID = id.OriginalNetworkID
			}
			sec, overflow := mpegts.BuildEIT(mpegts.EITSection{
				TableID:           mpegts.TableIDEITPFActual,
				ServiceID:         g.ServiceID,
				TransportStreamID: g.TSID,
				OriginalNetworkID: onID,
				Version:           v,
				Number:            number,
				LastNumber:        1,
				SegmentLast:       1,
				LastTableID:       mpegts.TableIDEITPFActual,
				Events:            events,
			})
			if len(overflow) > 0 {
				g.diagnose("eit-pf-overflow", "EIT p/f: %d events did not fit section %d", len(overflow), number)
			}
			out = append(out, sec)
		}
		return out
	}
	sections = g.versioned("eit-pf", build)
	if _, _, ok := g.State.PresentEvent(g.ServiceID); !ok {
		g.diagnose("eit-pf", "EIT p/f: no MH-EIT present/following for service %#04x yet", g.ServiceID)
	}
	g.resolved("eit-pf")
	return Table{Name: "EIT p/f", PID: mpegts.PIDEIT, Sections: sections, Interval: IntervalEITPF}, true
}

func (g *Generator) eitSchedule() (Table, bool) {
	type segment struct {
		index  byte
		events []mpegts.EITEvent
	}
	byTable := make(map[byte][]segment)
	var onID uint16
	for mmtID := byte(si.TableIDMHEITScheduleFirst); mmtID <= si.TableIDMHEITScheduleLast; mmtID++ {
		segments := make(map[byte][]mpegts.EITEvent)
		for number := 0; number < 256; number++ {
			eit, ok := g.State.EIT[si.EITKey{TableID: mmtID, ServiceID: g.ServiceID, Section: byte(number)}]
			if !ok {
				continue
			}
			onID = eit.OriginalNetworkID
			seg := byte(number) >> 3
			segments[seg] = append(segments[seg], g.events(eit.Events, true)...)
		}
		if len(segments) == 0 {
			continue
		}
		lastSegment := byte(0)
		for idx := range segments {
			if idx > lastSegment {
				lastSegment = idx
			}
		}
		list := make([]segment, 0, int(lastSegment)+1)
		for idx := byte(0); idx <= lastSegment; idx++ {
			ev := segments[idx]
			sort.SliceStable(ev, func(i, j int) bool { return bytes.Compare(ev[i].StartTime[:], ev[j].StartTime[:]) < 0 })
			list = append(list, segment{index: idx, events: ev})
		}
		byTable[mmtID] = list
	}
	if len(byTable) == 0 {
		return Table{}, false
	}
	lastTableID := byte(mpegts.TableIDEITScheduleFirst)
	for mmtID := range byTable {
		if id, ok := TSTableID(mmtID); ok && id > lastTableID {
			lastTableID = id
		}
	}
	build := func(v byte) [][]byte {
		var out [][]byte
		ids := make([]int, 0, len(byTable))
		for id := range byTable {
			ids = append(ids, int(id))
		}
		sort.Ints(ids)
		for _, rawID := range ids {
			mmtID := byte(rawID)
			segments := byTable[mmtID]
			tsID, ok := TSTableID(mmtID)
			if !ok {
				continue
			}
			type placed struct {
				number byte
				events []mpegts.EITEvent
			}
			var sections []placed
			last := byte(0)
			for _, seg := range segments {
				events := seg.events
				for slot := byte(0); slot < 8; slot++ {
					number := seg.index<<3 | slot
					_, overflow := mpegts.BuildEIT(mpegts.EITSection{
						TableID: tsID, ServiceID: g.ServiceID, Events: events,
					})
					sections = append(sections, placed{number: number, events: events[:len(events)-len(overflow)]})
					if number > last {
						last = number
					}
					events = overflow
					if len(events) == 0 {
						break
					}
				}
				if len(events) > 0 {
					g.diagnose("eit-schedule", "EIT schedule: %d events of segment %d did not fit its eight sections", len(events), seg.index)
				}
			}
			segLast := make(map[byte]byte)
			for _, p := range sections {
				if p.number > segLast[p.number>>3] {
					segLast[p.number>>3] = p.number
				}
			}
			for _, p := range sections {
				sec, _ := mpegts.BuildEIT(mpegts.EITSection{
					TableID:           tsID,
					ServiceID:         g.ServiceID,
					TransportStreamID: g.TSID,
					OriginalNetworkID: onID,
					Version:           v,
					Number:            p.number,
					LastNumber:        last,
					SegmentLast:       segLast[p.number>>3],
					LastTableID:       lastTableID,
					Events:            p.events,
				})
				out = append(out, sec)
			}
		}
		return out
	}
	sections := g.versioned("eit-schedule", build)
	if len(sections) == 0 {
		return Table{}, false
	}
	return Table{Name: "EIT schedule", PID: mpegts.PIDEIT, Sections: sections, Interval: IntervalSchedule}, true
}

func (g *Generator) events(in []si.Event, schedule bool) []mpegts.EITEvent {
	out := make([]mpegts.EITEvent, 0, len(in))
	for _, e := range in {
		desc, _ := g.Conv.Loop(e.Descriptors, InEvent)
		running := e.RunningStatus
		if schedule {
			running = 0
		}
		out = append(out, mpegts.EITEvent{
			EventID:       e.EventID,
			StartTime:     e.StartTime,
			Duration:      e.Duration,
			RunningStatus: running,
			FreeCA:        e.FreeCA,
			Descriptors:   desc,
		})
	}
	return out
}

func (g *Generator) tot() (Table, bool) {
	tot := g.State.TOT
	if tot == nil {
		g.diagnose("tot", "TOT: no MH-TOT received yet")
		return Table{}, false
	}
	desc, _ := g.Conv.Loop(tot.Descriptors, InNetwork)
	section := mpegts.BuildTOT(tot.JSTTime, desc)
	g.resolved("tot")
	return Table{Name: "TOT", PID: mpegts.PIDTOT, Sections: [][]byte{section}, Interval: IntervalTOT}, true
}

func (g *Generator) bit() (Table, bool) {
	chosen := lowestKeyed(g.State.BIT)
	if chosen == nil {
		return Table{}, false
	}
	first, _ := g.Conv.Loop(chosen.Descriptors, InNetwork)
	broadcasters := make([]mpegts.BITBroadcaster, 0, len(chosen.Broadcasters))
	for _, b := range chosen.Broadcasters {
		desc, _ := g.Conv.Loop(b.Descriptors, InNetwork)
		broadcasters = append(broadcasters, mpegts.BITBroadcaster{BroadcasterID: b.BroadcasterID, Descriptors: desc})
	}
	sections := g.versioned("bit", func(v byte) [][]byte {
		return mpegts.BuildBIT(chosen.OriginalNetworkID, v, chosen.ViewPropriety, first, broadcasters)
	})
	return Table{Name: "BIT", PID: mpegts.PIDBIT, Sections: sections, Interval: IntervalBIT}, true
}

func (g *Generator) cdt() (Table, bool) {
	chosen := lowestKeyed(g.State.CDT)
	if chosen == nil {
		return Table{}, false
	}
	desc, _ := g.Conv.Loop(chosen.Descriptors, InNetwork)
	sections := g.versioned("cdt", func(v byte) [][]byte {
		return mpegts.BuildCDT(chosen.DownloadDataID, v, chosen.OriginalNetworkID, chosen.DataType, desc, chosen.Module)
	})
	return Table{Name: "CDT", PID: mpegts.PIDCDT, Sections: sections, Interval: IntervalCDT}, true
}
