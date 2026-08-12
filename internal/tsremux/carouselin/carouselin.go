// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package carouselin は復元用カルーセルを検証し、保存されたMMT情報を読み戻す。
package carouselin

import (
	"fmt"
	"sort"

	"mmt2ts/internal/preservation"
)

const (
	dsmccTableDII = 0x3b
	dsmccTableDDB = 0x3c

	dsmccProtocol  = 0x11
	dsmccTypeDown  = 0x03
	dsmccMsgDII    = 0x1002
	dsmccMsgDDB    = 0x1003
	dsmccHeaderLen = 12
	dsmccBlockSize = 4066
	dsmccMaxBlocks = 256
)

const (
	downloadRealtime = 0x4d52
	downloadObject   = 0x4d53
)

type diiModule struct {
	size    uint32
	version byte
}

type assembling struct {
	version byte
	blocks  map[uint16][]byte
	total   int
	bytes   int
}

type carousel struct {
	role       preservation.Role
	downloadID uint32
	haveDII    bool
	modules    map[uint16]diiModule
	pending    map[uint16]*assembling
	version    map[uint16]byte
	versioned  map[uint16]bool
}

func newCarousel() *carousel {
	return &carousel{
		modules:   make(map[uint16]diiModule),
		pending:   make(map[uint16]*assembling),
		version:   make(map[uint16]byte),
		versioned: make(map[uint16]bool),
	}
}

type State struct {
	Bootstrap    *preservation.Bootstrap
	Manifest     *preservation.Manifest
	CodecConfigs []preservation.CodecConfig
	AVMap        []preservation.AVMapEntry
	LossEntries  []preservation.LossEntry

	Segments map[uint64][]preservation.Record

	Objects        map[uint16][]byte
	ObjectVersions map[uint16]byte
	Snapshots      []ObjectSnapshot

	segmentParts     map[uint64]map[uint16][]byte
	segmentPartCount map[uint64]uint16
	lossSeen         map[uint64]bool
	avMapSeen        map[avMapKey]bool
	codecConfigSeen  map[uint64]bool
	snapshotSeen     map[uint64]bool
}

type ResolvedObject struct {
	Manifest preservation.ManifestObject
	Data     []byte
}

type ObjectSnapshot struct {
	Generation   uint32
	UpdateNumber uint32
	Objects      map[uint64]ResolvedObject
}

type avMapKey struct {
	startNTP    uint64
	outputPID   uint16
	mpuSequence uint32
}

func newState() State {
	return State{
		Segments:         make(map[uint64][]preservation.Record),
		Objects:          make(map[uint16][]byte),
		ObjectVersions:   make(map[uint16]byte),
		segmentParts:     make(map[uint64]map[uint16][]byte),
		segmentPartCount: make(map[uint64]uint16),
		lossSeen:         make(map[uint64]bool),
		avMapSeen:        make(map[avMapKey]bool),
		codecConfigSeen:  make(map[uint64]bool),
		snapshotSeen:     make(map[uint64]bool),
	}
}

type Reader struct {
	byPID map[uint16]*carousel

	Realtime State
	Object   State

	Problems []string
}

func New() *Reader {
	return &Reader{
		byPID:    make(map[uint16]*carousel),
		Realtime: newState(),
		Object:   newState(),
	}
}

func (r *Reader) problem(format string, args ...any) {
	if len(r.Problems) < 200 {
		r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
	}
}

func (r *Reader) carousel(pid uint16) *carousel {
	c := r.byPID[pid]
	if c == nil {
		c = newCarousel()
		r.byPID[pid] = c
	}
	return c
}

func (r *Reader) state(c *carousel) *State {
	switch c.role {
	case preservation.RoleRealtime:
		return &r.Realtime
	case preservation.RoleObject:
		return &r.Object
	}
	return nil
}

func (r *Reader) Push(pid uint16, section []byte) {
	if len(section) < 8+dsmccHeaderLen+4 {
		r.problem("PID %#04x: DSM-CC section of %d bytes is too short", pid, len(section))
		return
	}
	c := r.carousel(pid)
	msg := section[8 : len(section)-4]
	if msg[0] != dsmccProtocol || msg[1] != dsmccTypeDown {
		r.problem("PID %#04x: protocolDiscriminator %#02x dsmccType %#02x", pid, msg[0], msg[1])
		return
	}
	messageID := u16(msg[2:4])
	id := u32(msg[4:8])
	body := msg[dsmccHeaderLen:]

	switch section[0] {
	case dsmccTableDII:
		if messageID != dsmccMsgDII {
			return
		}
		r.dii(c, body)
	case dsmccTableDDB:
		if messageID != dsmccMsgDDB {
			return
		}
		r.ddb(c, pid, id, section, body)
	}
}

func (r *Reader) dii(c *carousel, body []byte) {
	if len(body) < 22 {
		r.problem("DII body of %d bytes", len(body))
		return
	}
	downloadID := u32(body[0:4])
	if !c.haveDII {
		switch downloadID >> 16 {
		case downloadRealtime:
			c.role = preservation.RoleRealtime
		case downloadObject:
			c.role = preservation.RoleObject
		default:
			r.problem("DII downloadId %#08x has an unrecognised prefix", downloadID)
			return
		}
	}
	c.downloadID = downloadID
	cdLen := int(u16(body[16:18]))
	p := 18 + cdLen
	if p+2 > len(body) {
		return
	}
	count := int(u16(body[p : p+2]))
	p += 2
	next := make(map[uint16]diiModule, count)
	for range count {
		if p+8 > len(body) {
			return
		}
		id := u16(body[p : p+2])
		size := u32(body[p+2 : p+6])
		version := body[p+6]
		infoLen := int(body[p+7])
		p += 8 + infoLen
		if size == 0 {
			continue
		}
		next[id] = diiModule{size: size, version: version}
	}
	for id, asm := range c.pending {
		if m, ok := next[id]; !ok || m.version != asm.version {
			delete(c.pending, id)
		}
	}
	c.modules = next
	c.haveDII = true
}

func (r *Reader) ddb(c *carousel, pid uint16, downloadID uint32, section, body []byte) {
	if len(body) < 6 || !c.haveDII || downloadID != c.downloadID {
		return
	}
	moduleID := u16(body[0:2])
	version := body[2]
	blockNumber := u16(body[4:6])
	block := body[6:]

	m, ok := c.modules[moduleID]
	if !ok || m.version != version {
		return
	}
	blocks := int(m.size+dsmccBlockSize-1) / dsmccBlockSize
	if blocks > dsmccMaxBlocks || int(blockNumber) >= blocks {
		return
	}
	want := dsmccBlockSize
	if int(blockNumber) == blocks-1 {
		want = int(m.size) - (blocks-1)*dsmccBlockSize
	}
	if len(block) != want {
		return
	}

	asm := c.pending[moduleID]
	if asm == nil || asm.version != version {
		asm = &assembling{version: version, blocks: make(map[uint16][]byte, blocks), total: blocks}
		c.pending[moduleID] = asm
	}
	if _, seen := asm.blocks[blockNumber]; seen {
		return
	}
	asm.blocks[blockNumber] = append([]byte(nil), block...)
	asm.bytes += len(block)
	if len(asm.blocks) != asm.total {
		return
	}

	stored := make([]byte, 0, asm.bytes)
	for i := range asm.total {
		stored = append(stored, asm.blocks[uint16(i)]...)
	}
	delete(c.pending, moduleID)
	if len(stored) != int(m.size) {
		r.problem("PID %#04x: module %#04x assembled to %d bytes, DII says %d", pid, moduleID, len(stored), m.size)
		return
	}
	r.moduleComplete(c, pid, moduleID, version, stored)
}

func (r *Reader) moduleComplete(c *carousel, pid uint16, moduleID uint16, version byte, stored []byte) {
	if c.versioned[moduleID] && c.version[moduleID] == version {
		return
	}
	header, payload, err := preservation.ParseModule(stored)
	if err != nil {
		r.problem("PID %#04x: module %#04x: %v", pid, moduleID, err)
		return
	}
	st := r.state(c)
	if st == nil {
		return
	}
	c.version[moduleID] = version
	c.versioned[moduleID] = true

	switch header.Kind {
	case preservation.KindBootstrapManifest:
		b, err := preservation.ParseBootstrap(payload)
		if err != nil {
			r.problem("PID %#04x: bootstrap: %v", pid, err)
			return
		}
		st.Bootstrap = b
	case preservation.KindTimedSegment:
		r.addSegmentPart(st, c.role, moduleID, header.LogicalID, payload)
	case preservation.KindStaticObject:
		st.Objects[moduleID] = payload
		st.ObjectVersions[moduleID] = version
		r.captureSnapshot(st)
	case preservation.KindObjectManifest:
		if header.Flags&preservation.FlagCommit == 0 {
			return
		}
		m, err := preservation.ParseManifest(payload)
		if err != nil {
			r.problem("PID %#04x: object manifest: %v", pid, err)
			return
		}
		st.Manifest = m
		r.captureSnapshot(st)
	case preservation.KindCodecConfig:
		cfgs, err := preservation.ParseCodecConfigs(payload)
		if err != nil {
			r.problem("PID %#04x: codec config: %v", pid, err)
			return
		}
		for _, c := range cfgs {
			if !st.codecConfigSeen[c.ConfigID] {
				st.codecConfigSeen[c.ConfigID] = true
				st.CodecConfigs = append(st.CodecConfigs, c)
			}
		}
	case preservation.KindAVMPUMap:
		av, err := preservation.ParseAVMap(payload)
		if err != nil {
			r.problem("PID %#04x: AV MPU map: %v", pid, err)
			return
		}
		// 同じAV情報は重複登録しない。
		for _, e := range av {
			key := avMapKey{startNTP: e.StartNTP, outputPID: e.OutputPID, mpuSequence: e.MPUSequence}
			if !st.avMapSeen[key] {
				st.avMapSeen[key] = true
				st.AVMap = append(st.AVMap, e)
			}
		}
	case preservation.KindLossReport:
		entries, err := preservation.ParseLossReport(payload)
		if err != nil {
			r.problem("PID %#04x: loss report: %v", pid, err)
			return
		}
		if !st.lossSeen[header.LogicalID] {
			st.lossSeen[header.LogicalID] = true
			st.LossEntries = append(st.LossEntries, entries...)
		}
	}
}

func (r *Reader) captureSnapshot(st *State) {
	if st.Manifest == nil {
		return
	}
	key := uint64(st.Manifest.Generation)<<32 | uint64(st.Manifest.UpdateNumber)
	if st.snapshotSeen[key] {
		return
	}
	snapshot := ObjectSnapshot{
		Generation: st.Manifest.Generation, UpdateNumber: st.Manifest.UpdateNumber,
		Objects: make(map[uint64]ResolvedObject, len(st.Manifest.Objects)),
	}
	for _, obj := range st.Manifest.Objects {
		data, err := ResolveObject(st, obj)
		if err != nil {
			return
		}
		snapshot.Objects[obj.ID] = ResolvedObject{Manifest: obj, Data: append([]byte(nil), data...)}
	}
	st.snapshotSeen[key] = true
	st.Snapshots = append(st.Snapshots, snapshot)
}

func (r *Reader) addSegmentPart(st *State, role preservation.Role, moduleID uint16, seq uint64, payload []byte) {
	partNumber, partCount := uint16(0), uint16(1)
	if st.Bootstrap != nil {
		for _, e := range st.Bootstrap.Entries {
			if e.Role == role && e.ModuleID == moduleID && e.Kind == preservation.KindTimedSegment && e.LogicalID == seq {
				partNumber, partCount = e.PartNumber, e.PartCount
				break
			}
		}
	}
	parts := st.segmentParts[seq]
	if parts == nil {
		parts = make(map[uint16][]byte, partCount)
		st.segmentParts[seq] = parts
	}
	parts[partNumber] = payload
	st.segmentPartCount[seq] = partCount
	if uint16(len(parts)) < partCount {
		return
	}
	joined := make([]byte, 0, len(payload)*int(partCount))
	for i := range partCount {
		p, ok := parts[i]
		if !ok {
			return
		}
		joined = append(joined, p...)
	}
	records, err := preservation.ParseSegment(joined)
	if err != nil {
		r.problem("segment %d: %v", seq, err)
		return
	}
	st.Segments[seq] = records
	delete(st.segmentParts, seq)
	delete(st.segmentPartCount, seq)
}

func (s State) SegmentSequences() []uint64 {
	out := make([]uint64, 0, len(s.Segments))
	for seq := range s.Segments {
		out = append(out, seq)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func u16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
func u32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
