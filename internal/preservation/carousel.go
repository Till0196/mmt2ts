// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"crypto/sha256"
	"fmt"
	"slices"
)

const (
	ModuleIDBootstrap = 0x0000

	moduleIDTimedBase = 0x0100
	timedRingSegments = 16
	timedRingParts    = 4

	moduleIDLossBase = 0x0200
	lossRingSlots    = 16

	ModuleIDCodecConfig = 0x0300
	ModuleIDAVMap       = 0x0301

	ModuleIDObjectManifest = 0x0001
	moduleIDObjectBase     = 0x0100
	MaxObjectModules       = 254

	MaxRealtimeModules = 1 + timedRingSegments*timedRingParts + lossRingSlots + 2
)

const MaxSegmentParts = timedRingParts

func TimedModuleID(sequence uint64, part int) uint16 {
	return uint16(moduleIDTimedBase + (sequence%timedRingSegments)*timedRingParts + uint64(part))
}

func LossModuleID(sequence uint64) uint16 {
	return uint16(moduleIDLossBase + sequence%lossRingSlots)
}

const neverAgain = int64(1) << 62

const staleGuard = 10 * 90000

const (
	DIIInterval     = 90000 / 2
	SegmentInterval = 90000 / 2
	ObjectInterval  = 5 * 90000
)

type Update struct {
	ID         uint16
	Kind       Kind
	Flags      uint16
	EpochID    uint32
	LogicalID  uint64
	StartNTP   uint64
	DurationMS uint32
	Payload    []byte

	Required     bool
	PartNumber   uint16
	PartCount    uint16
	OriginalSize uint64
	ValidFrom    uint64
	ValidUntil   uint64

	SHA256     [32]byte
	HaveSHA256 bool

	Interval      int64
	RetryCount    uint8
	RetryInterval int64
	Once          bool
	Priority      int
}

const (
	PriorityContent   = 0
	PriorityManifest  = 1
	PriorityBootstrap = 2
)

type module struct {
	id            uint16
	version       byte
	kind          Kind
	stored        []byte
	sections      [][]byte
	entry         DirectoryEntry
	interval      int64
	retryInterval int64
	once          bool
	priority      int
	initial       int64
	next          int64
	sent          uint64
	retries       uint8
	assigned      bool
}

type Carousel struct {
	Role       Role
	PID        uint16
	Tag        byte
	DownloadID uint32

	transaction uint32
	modules     map[uint16]*module
	order       []uint16
	retired     map[uint32]int64
	lastVersion map[uint16]byte

	dii      []byte
	diiLast  int64
	dirty    bool
	revision uint64

	DIISections uint64
	DDBSections uint64
	Bytes       uint64
}

func NewCarousel(role Role, pid uint16, tag byte, downloadID uint32) *Carousel {
	return &Carousel{
		Role:        role,
		PID:         pid,
		Tag:         tag,
		DownloadID:  downloadID,
		modules:     make(map[uint16]*module),
		retired:     make(map[uint32]int64),
		lastVersion: make(map[uint16]byte),
		diiLast:     -DIIInterval,
		dirty:       true,
	}
}

func retiredKey(id uint16, version byte) uint32 { return uint32(id)<<8 | uint32(version) }

func (c *Carousel) maxModules() int {
	if c.Role == RoleObject {
		return MaxModules
	}
	return MaxRealtimeModules
}

func (c *Carousel) Set(u Update, now int64) error {
	if u.Kind == KindBootstrapManifest && u.ID != ModuleIDBootstrap {
		return fmt.Errorf("preservation: bootstrap must use module id %#04x", ModuleIDBootstrap)
	}
	if u.PartCount == 0 {
		u.PartCount = 1
	}
	header := Header{
		Kind: u.Kind, Flags: u.Flags, EpochID: u.EpochID,
		LogicalID: u.LogicalID, StartNTP: u.StartNTP, DurationMS: u.DurationMS,
	}
	stored, err := BuildModule(header, u.Payload)
	if err != nil {
		return err
	}

	m := c.modules[u.ID]
	if m == nil {
		if len(c.modules) >= c.maxModules() {
			return fmt.Errorf("%w: %s carousel already holds %d modules", ErrCapacityExceeded, c.Role, len(c.modules))
		}
		m = &module{id: u.ID}
		if last, seen := c.lastVersion[u.ID]; seen {
			m.version = (last + 1) & 0xff
			m.assigned = true
		}
		c.modules[u.ID] = m
		c.order = append(c.order, u.ID)
	} else {
		if len(m.stored) == len(stored) && string(m.stored) == string(stored) &&
			m.interval == u.Interval && m.retries == u.RetryCount && m.retryInterval == u.RetryInterval &&
			m.once == u.Once {
			return nil
		}
		c.retired[retiredKey(m.id, m.version)] = now
		m.version = (m.version + 1) & 0xff
		m.assigned = true
	}
	if m.assigned {
		if at, ok := c.retired[retiredKey(m.id, m.version)]; ok && now-at < staleGuard {
			return fmt.Errorf("preservation: module %#04x version %d was retired %d ticks ago, less than the stale guard",
				m.id, m.version, now-at)
		}
	}
	m.assigned = true
	delete(c.retired, retiredKey(m.id, m.version))
	c.lastVersion[m.id] = m.version

	sum := u.SHA256
	if !u.HaveSHA256 {
		sum = sha256.Sum256(u.Payload)
	}
	m.kind = u.Kind
	m.stored = stored
	m.sections = nil
	m.interval = u.Interval
	m.retryInterval = u.RetryInterval
	m.once = u.Once
	m.retries = u.RetryCount
	m.priority = u.Priority
	m.initial = now
	m.next = now
	m.sent = 0
	c.sortOrder()
	m.entry = DirectoryEntry{
		Role: c.Role, Required: u.Required, ModuleID: u.ID, Version: m.version, Kind: u.Kind,
		PartNumber: u.PartNumber, PartCount: u.PartCount, LogicalID: u.LogicalID,
		StoredSize: uint32(len(stored)), OriginalSize: u.OriginalSize,
		ValidFrom: u.ValidFrom, ValidUntil: u.ValidUntil, SHA256: sum,
	}
	if m.entry.OriginalSize == 0 {
		m.entry.OriginalSize = uint64(len(u.Payload))
	}
	c.dirty, c.revision = true, c.revision+1
	return nil
}

func (c *Carousel) sortOrder() {
	slices.SortFunc(c.order, func(a, b uint16) int {
		if p := c.modules[a].priority - c.modules[b].priority; p != 0 {
			return p
		}
		return int(a) - int(b)
	})
}

func (c *Carousel) Remove(id uint16, now int64) {
	m := c.modules[id]
	if m == nil {
		return
	}
	c.retired[retiredKey(m.id, m.version)] = now
	delete(c.modules, id)
	c.order = slices.DeleteFunc(c.order, func(v uint16) bool { return v == id })
	c.dirty, c.revision = true, c.revision+1
}

func (c *Carousel) Has(id uint16) bool { return c.modules[id] != nil }

func (c *Carousel) Entries() []DirectoryEntry {
	out := make([]DirectoryEntry, 0, len(c.order))
	for _, id := range c.order {
		if id == ModuleIDBootstrap {
			continue
		}
		out = append(out, c.modules[id].entry)
	}
	return out
}

func (c *Carousel) cycleMicroseconds() uint32 {
	longest := int64(DIIInterval)
	for _, m := range c.modules {
		longest = max(longest, m.interval)
	}
	us := longest * 1_000_000 / 90000
	if us < 1 {
		return 1
	}
	if us > 0xffffffff {
		return 0xffffffff
	}
	return uint32(us)
}

func (c *Carousel) rebuild() error {
	entries := make([]ModuleEntry, 0, len(c.order))
	for _, id := range c.order {
		m := c.modules[id]
		entries = append(entries, ModuleEntry{ID: m.id, Size: uint32(len(m.stored)), Version: m.version})
	}
	c.transaction = (c.transaction + 1) & 0x3fffffff
	dii, err := BuildDII(c.DownloadID, TransactionID(c.transaction), c.cycleMicroseconds(), entries)
	if err != nil {
		return err
	}
	c.dii = dii
	c.dirty = false
	return nil
}

func (c *Carousel) blocks(m *module) ([][]byte, error) {
	if m.sections == nil {
		s, err := SplitModule(c.DownloadID, ModuleEntry{ID: m.id, Size: uint32(len(m.stored)), Version: m.version}, m.stored)
		if err != nil {
			return nil, err
		}
		m.sections = s
	}
	return m.sections, nil
}

func (c *Carousel) Emit(now int64, write func(pid uint16, section []byte) error) error {
	if c.dirty {
		if err := c.rebuild(); err != nil {
			return err
		}
		c.diiLast = now - DIIInterval
	}
	if len(c.modules) == 0 {
		return nil
	}
	if now-c.diiLast >= DIIInterval {
		c.diiLast = now
		if err := write(c.PID, c.dii); err != nil {
			return err
		}
		c.DIISections++
		c.Bytes += uint64(len(c.dii))
	}
	for _, id := range c.order {
		m := c.modules[id]
		if now < m.next {
			continue
		}
		sections, err := c.blocks(m)
		if err != nil {
			return err
		}
		for _, s := range sections {
			if err := write(c.PID, s); err != nil {
				return err
			}
			c.DDBSections++
			c.Bytes += uint64(len(s))
		}
		m.sent++
		switch {
		case m.once:
			m.next = neverAgain
		case m.sent <= uint64(m.retries):
			m.next = now + m.retryInterval
		case m.sent == uint64(m.retries)+1:
			m.next = m.initial + m.interval
			if m.next <= now {
				m.next = now + m.interval
			}
		default:
			m.next = now + m.interval
		}
	}
	return nil
}

func (c *Carousel) Revision() uint64 { return c.revision }

func (c *Carousel) ModuleCount() int { return len(c.modules) }
