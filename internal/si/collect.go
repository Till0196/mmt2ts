// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package si

import "bytes"

type TableSet struct {
	TableID   byte
	Extension uint16
	Version   byte
	Sections  []Section
}

type setKey struct {
	TableID   byte
	Extension uint16
}

type pending struct {
	version     byte
	sections    map[byte]Section
	last        byte
	haveLast    bool
	segmentLast map[byte]byte
}

type Collector struct {
	building map[setKey]*pending
	current  map[setKey]*TableSet
	stats    Stats
}

func NewCollector() *Collector {
	return &Collector{
		building: make(map[setKey]*pending),
		current:  make(map[setKey]*TableSet),
		stats:    newStats(),
	}
}

func (c *Collector) Stats() Stats { return c.stats }

func (c *Collector) Current(tableID byte, extension uint16) (*TableSet, bool) {
	s, ok := c.current[setKey{tableID, extension}]
	return s, ok
}

func (c *Collector) Push(s Section) (*TableSet, bool) {
	c.stats.Sections++
	if !s.Syntax {
		c.stats.ShortSections++
		set := &TableSet{TableID: s.TableID, Extension: s.Extension, Sections: []Section{s}}
		c.current[setKey{s.TableID, s.Extension}] = set
		c.stats.CompletedTables++
		return set, true
	}
	if !s.Current {
		c.stats.NotCurrent++
		return nil, false
	}
	key := setKey{s.TableID, s.Extension}
	p := c.building[key]
	if p == nil || p.version != s.Version {
		if p != nil {
			c.stats.VersionChanges++
			c.stats.IncompleteTables++
		}
		p = &pending{version: s.Version, sections: make(map[byte]Section), segmentLast: make(map[byte]byte)}
		c.building[key] = p
	}
	if old, dup := p.sections[s.Number]; dup && !bytes.Equal(old.Raw, s.Raw) {
		c.stats.DuplicateMismatch++
	}
	p.sections[s.Number] = s
	p.last, p.haveLast = s.LastNumber, true
	if isEIT(s.TableID) && len(s.Body) >= 6 {
		p.segmentLast[s.Number>>3] = s.Body[4]
	}
	if !p.complete() {
		return nil, false
	}
	set := &TableSet{TableID: s.TableID, Extension: s.Extension, Version: s.Version}
	for n := 0; n <= int(p.last); n++ {
		if sec, ok := p.sections[byte(n)]; ok {
			set.Sections = append(set.Sections, sec)
		}
	}
	if prev, ok := c.current[key]; ok && sameSet(prev, set) {
		return nil, false
	}
	c.current[key] = set
	c.stats.CompletedTables++
	return set, true
}

func sameSet(a, b *TableSet) bool {
	if a.Version != b.Version || len(a.Sections) != len(b.Sections) {
		return false
	}
	for i := range a.Sections {
		if !bytes.Equal(a.Sections[i].Raw, b.Sections[i].Raw) {
			return false
		}
	}
	return true
}

func isEIT(tableID byte) bool {
	return tableID == TableIDMHEITPF ||
		(tableID >= TableIDMHEITScheduleFirst && tableID <= TableIDMHEITScheduleLast)
}

func (p *pending) complete() bool {
	if !p.haveLast {
		return false
	}
	for n := 0; n <= int(p.last); n++ {
		if _, ok := p.sections[byte(n)]; ok {
			continue
		}
		if last, ok := p.segmentLast[byte(n)>>3]; ok && byte(n) > last {
			continue
		}
		return false
	}
	return true
}
