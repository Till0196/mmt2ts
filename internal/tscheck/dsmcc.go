// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tscheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

const (
	dsmccTableDII = 0x3b
	dsmccTableDDB = 0x3c

	dsmccProtocol   = 0x11
	dsmccTypeDown   = 0x03
	dsmccMsgDII     = 0x1002
	dsmccMsgDDB     = 0x1003
	dsmccHeaderLen  = 12
	dsmccBlockSize  = 4066
	dsmccMaxBlocks  = 256
	dsmccMaxModules = 256
	dsmccMaxModule  = dsmccBlockSize * dsmccMaxBlocks

	mmtcHeaderLen = 48
	mmtcMajor     = 1

	kindBootstrap      = 0x01
	kindTimedSegment   = 0x02
	kindStaticObject   = 0x03
	kindObjectManifest = 0x04
	kindLossReport     = 0x07

	flagCommit     = 0x0004
	flagIncomplete = 0x0001

	roleRealtime = 1
	roleObject   = 2

	bootstrapFixed  = 46
	directoryEntry  = 78
	objectHeaderLen = 60
	partEntryLen    = 48
)

func isoHDLC(b []byte) uint32 {
	crc := ^uint32(0)
	for _, c := range b {
		crc ^= uint32(c)
		for range 8 {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xedb88320
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

type diiModule struct {
	size    uint32
	version byte
}

type assembling struct {
	version byte
	last    uint16
	blocks  map[uint16][]byte
	bytes   int
}

type storedModule struct {
	kind      byte
	version   byte
	flags     uint16
	logicalID uint64
	stored    int
	payload   []byte
	sha       [32]byte
}

type carousel struct {
	pid               uint16
	downloadID        uint32
	haveDII           bool
	modules           map[uint16]diiModule
	pending           map[uint16]*assembling
	complete          map[uint16]*storedModule
	verifiedBootstrap byte
	haveVerifiedBoot  bool
	verifiedManifest  byte
	haveVerifiedMan   bool
}

func newCarousel(pid uint16) *carousel {
	return &carousel{
		pid:      pid,
		modules:  make(map[uint16]diiModule),
		pending:  make(map[uint16]*assembling),
		complete: make(map[uint16]*storedModule),
	}
}

func (s *scanner) isDSMCC(st *pidState) bool { return st.stat.StreamType == 0x0b }

func (s *scanner) carousel(pid uint16) *carousel {
	if s.carousels == nil {
		s.carousels = make(map[uint16]*carousel)
	}
	c := s.carousels[pid]
	if c == nil {
		c = newCarousel(pid)
		s.carousels[pid] = c
	}
	return c
}

func (s *scanner) dsmccError(format string, args ...any) {
	s.report.DSMCCErrors++
	if len(s.report.DSMCCProblems) < 40 {
		s.report.DSMCCProblems = append(s.report.DSMCCProblems, fmt.Sprintf(format, args...))
	}
}

func (s *scanner) dsmcc(pid uint16, section []byte) {
	s.report.DSMCCSections++
	c := s.carousel(pid)
	if len(section) < 8+dsmccHeaderLen+4 {
		s.dsmccError("PID %#04x: DSM-CC section of %d bytes is too short for a message header", pid, len(section))
		return
	}
	if got := len(section) - 3; got > 4093 {
		s.dsmccError("PID %#04x: dsmcc_section_length %d exceeds 4093", pid, got)
	}
	if section[5]&0x01 == 0 {
		s.dsmccError("PID %#04x: current_next_indicator is 0", pid)
	}
	if section[1]&0x40 != 0 {
		s.dsmccError("PID %#04x: private_indicator is 1", pid)
	}

	msg := section[8 : len(section)-4]
	if msg[0] != dsmccProtocol || msg[1] != dsmccTypeDown {
		s.dsmccError("PID %#04x: protocolDiscriminator %#02x dsmccType %#02x", pid, msg[0], msg[1])
		return
	}
	messageID := binary.BigEndian.Uint16(msg[2:4])
	id := binary.BigEndian.Uint32(msg[4:8])
	if msg[9] != 0 {
		s.dsmccError("PID %#04x: adaptationLength %d is not 0", pid, msg[9])
		return
	}
	body := msg[dsmccHeaderLen:]
	if got := int(binary.BigEndian.Uint16(msg[10:12])); got != len(body) {
		s.dsmccError("PID %#04x: messageLength %d but %d body bytes", pid, got, len(body))
		return
	}

	switch section[0] {
	case dsmccTableDII:
		if messageID != dsmccMsgDII {
			s.dsmccError("PID %#04x: table_id 0x3b with messageId %#04x", pid, messageID)
			return
		}
		if got := binary.BigEndian.Uint16(section[3:5]); got != uint16(id&0xffff) {
			s.dsmccError("PID %#04x: DII table_id_extension %#04x does not match transaction_id %#08x", pid, got, id)
		}
		if id&0xc0000000 != 0x80000000 {
			s.dsmccError("PID %#04x: transaction_id %#08x does not start with the profile's '10' bits", pid, id)
		}
		s.report.DIISections++
		s.dii(c, body)
	case dsmccTableDDB:
		if messageID != dsmccMsgDDB {
			s.dsmccError("PID %#04x: table_id 0x3c with messageId %#04x", pid, messageID)
			return
		}
		s.report.DDBSections++
		s.ddb(c, section, id, body)
	default:
		s.dsmccError("PID %#04x: table_id %#02x on a DSM-CC stream", pid, section[0])
	}
}

func (s *scanner) dii(c *carousel, body []byte) {
	if len(body) < 22 {
		s.dsmccError("PID %#04x: DII body of %d bytes", c.pid, len(body))
		return
	}
	downloadID := binary.BigEndian.Uint32(body[0:4])
	if c.haveDII && downloadID != c.downloadID {
		s.dsmccError("PID %#04x: downloadId changed from %#08x to %#08x on one PID", c.pid, c.downloadID, downloadID)
	}
	c.downloadID = downloadID
	if got := binary.BigEndian.Uint16(body[4:6]); got != dsmccBlockSize {
		s.dsmccError("PID %#04x: blockSize %d, want %d", c.pid, got, dsmccBlockSize)
	}
	if body[6] != 0 || body[7] != 0 {
		s.dsmccError("PID %#04x: windowSize %d ackPeriod %d must be 0 on broadcast", c.pid, body[6], body[7])
	}
	if scenario := binary.BigEndian.Uint32(body[12:16]); scenario == 0 {
		s.dsmccError("PID %#04x: tCDownloadScenario is 0", c.pid)
	}
	cdLen := int(binary.BigEndian.Uint16(body[16:18]))
	p := 18 + cdLen
	if p+2 > len(body) {
		s.dsmccError("PID %#04x: compatibilityDescriptorLength %d runs past the DII", c.pid, cdLen)
		return
	}
	count := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	if count > dsmccMaxModules {
		s.dsmccError("PID %#04x: DII advertises %d modules, the profile allows %d", c.pid, count, dsmccMaxModules)
	}

	next := make(map[uint16]diiModule, count)
	for range count {
		if p+8 > len(body) {
			s.dsmccError("PID %#04x: DII module loop is truncated", c.pid)
			return
		}
		id := binary.BigEndian.Uint16(body[p : p+2])
		size := binary.BigEndian.Uint32(body[p+2 : p+6])
		version := body[p+6]
		infoLen := int(body[p+7])
		p += 8 + infoLen
		if size == 0 || size > dsmccMaxModule {
			s.dsmccError("PID %#04x: module %#04x has moduleSize %d", c.pid, id, size)
			continue
		}
		if _, dup := next[id]; dup {
			s.dsmccError("PID %#04x: module %#04x appears twice in one DII", c.pid, id)
		}
		next[id] = diiModule{size: size, version: version}
	}
	if p+2 > len(body) || p+2+int(binary.BigEndian.Uint16(body[p:p+2])) != len(body) {
		s.dsmccError("PID %#04x: DII privateDataLength does not close the message", c.pid)
	}

	for id, asm := range c.pending {
		if m, ok := next[id]; !ok || m.version != asm.version {
			delete(c.pending, id)
		}
	}
	for id, done := range c.complete {
		if m, ok := next[id]; !ok || m.version != done.version {
			delete(c.complete, id)
		}
	}
	c.modules = next
	c.haveDII = true
}

func (s *scanner) ddb(c *carousel, section []byte, downloadID uint32, body []byte) {
	if len(body) < 6 {
		s.dsmccError("PID %#04x: DDB body of %d bytes", c.pid, len(body))
		return
	}
	moduleID := binary.BigEndian.Uint16(body[0:2])
	version := body[2]
	blockNumber := binary.BigEndian.Uint16(body[4:6])
	block := body[6:]

	if !c.haveDII {
		s.report.DDBBeforeDII++
		return
	}
	if downloadID != c.downloadID {
		s.dsmccError("PID %#04x: DDB downloadId %#08x, the DII says %#08x", c.pid, downloadID, c.downloadID)
		return
	}
	if got := binary.BigEndian.Uint16(section[3:5]); got != moduleID {
		s.dsmccError("PID %#04x: DDB table_id_extension %#04x does not match moduleId %#04x", c.pid, got, moduleID)
	}
	if got := section[5] >> 1 & 0x1f; got != version&0x1f {
		s.dsmccError("PID %#04x: module %#04x section version %d, moduleVersion %d", c.pid, moduleID, got, version)
	}
	if int(section[6]) != int(blockNumber) {
		s.dsmccError("PID %#04x: module %#04x section_number %d, blockNumber %d", c.pid, moduleID, section[6], blockNumber)
	}

	m, ok := c.modules[moduleID]
	if !ok {
		s.report.DDBNotInDII++
		return
	}
	if m.version != version {
		s.report.DDBStaleVersion++
		return
	}
	blocks := int(m.size+dsmccBlockSize-1) / dsmccBlockSize
	if blocks > dsmccMaxBlocks {
		s.dsmccError("PID %#04x: module %#04x needs %d blocks", c.pid, moduleID, blocks)
		return
	}
	if int(section[7]) != blocks-1 {
		s.dsmccError("PID %#04x: module %#04x last_section_number %d, the DII implies %d", c.pid, moduleID, section[7], blocks-1)
	}
	if int(blockNumber) >= blocks {
		s.dsmccError("PID %#04x: module %#04x block %d of %d", c.pid, moduleID, blockNumber, blocks)
		return
	}
	want := dsmccBlockSize
	if int(blockNumber) == blocks-1 {
		want = int(m.size) - (blocks-1)*dsmccBlockSize
	}
	if len(block) != want {
		s.dsmccError("PID %#04x: module %#04x block %d is %d bytes, want %d", c.pid, moduleID, blockNumber, len(block), want)
		return
	}

	asm := c.pending[moduleID]
	if asm == nil || asm.version != version {
		asm = &assembling{version: version, last: uint16(blocks - 1), blocks: make(map[uint16][]byte, blocks)}
		c.pending[moduleID] = asm
	}
	if _, seen := asm.blocks[blockNumber]; seen {
		s.report.DDBRepeats++
		return
	}
	asm.blocks[blockNumber] = bytes.Clone(block)
	asm.bytes += len(block)
	if len(asm.blocks) != blocks {
		return
	}

	stored := make([]byte, 0, asm.bytes)
	for i := range blocks {
		stored = append(stored, asm.blocks[uint16(i)]...)
	}
	delete(c.pending, moduleID)
	if len(stored) != int(m.size) {
		s.dsmccError("PID %#04x: module %#04x assembled to %d bytes, the DII says %d", c.pid, moduleID, len(stored), m.size)
		return
	}
	s.report.ModulesComplete++
	s.module(c, moduleID, version, stored)
}

func (s *scanner) module(c *carousel, moduleID uint16, version byte, stored []byte) {
	if len(stored) < mmtcHeaderLen {
		s.dsmccError("PID %#04x: module %#04x is shorter than the common header", c.pid, moduleID)
		return
	}
	if string(stored[:4]) != "MMTC" {
		s.dsmccError("PID %#04x: module %#04x does not start with MMTC", c.pid, moduleID)
		return
	}
	if stored[4] != mmtcMajor {
		s.dsmccError("PID %#04x: module %#04x major version %d", c.pid, moduleID, stored[4])
		return
	}
	if got := binary.BigEndian.Uint16(stored[12:14]); got != mmtcHeaderLen {
		s.dsmccError("PID %#04x: module %#04x header_length %d", c.pid, moduleID, got)
		return
	}
	header := bytes.Clone(stored[:mmtcHeaderLen])
	binary.BigEndian.PutUint32(header[44:48], 0)
	if isoHDLC(header) != binary.BigEndian.Uint32(stored[44:48]) {
		s.dsmccError("PID %#04x: module %#04x header CRC mismatch", c.pid, moduleID)
		return
	}
	payload := stored[mmtcHeaderLen:]
	if got := binary.BigEndian.Uint32(stored[36:40]); int(got) != len(payload) {
		s.dsmccError("PID %#04x: module %#04x declares %d payload bytes and carries %d", c.pid, moduleID, got, len(payload))
		return
	}
	if isoHDLC(payload) != binary.BigEndian.Uint32(stored[40:44]) {
		s.dsmccError("PID %#04x: module %#04x payload CRC mismatch", c.pid, moduleID)
		return
	}

	kind := stored[5]
	flags := binary.BigEndian.Uint16(stored[6:8])
	if flags&flagCommit != 0 && kind != kindObjectManifest {
		s.dsmccError("PID %#04x: module %#04x sets the commit flag on kind %#02x", c.pid, moduleID, kind)
	}
	if flags&flagCommit != 0 && flags&flagIncomplete != 0 {
		s.dsmccError("PID %#04x: module %#04x is both committed and incomplete", c.pid, moduleID)
	}
	s.report.ModulesVerified++
	if s.report.ModuleKinds == nil {
		s.report.ModuleKinds = make(map[byte]uint64)
	}
	s.report.ModuleKinds[kind]++

	c.complete[moduleID] = &storedModule{
		kind: kind, version: version, flags: flags,
		logicalID: binary.BigEndian.Uint64(stored[16:24]),
		stored:    len(stored), payload: bytes.Clone(payload),
		sha: sha256.Sum256(payload),
	}
	switch kind {
	case kindBootstrap:
		s.bootstrap(c, moduleID, version)
	case kindObjectManifest:
		s.manifest(c, moduleID, version)
	}
	if kind == kindStaticObject {
		for id, m := range c.complete {
			if m.kind == kindObjectManifest {
				c.haveVerifiedMan = false
				s.manifest(c, id, m.version)
				break
			}
		}
	}
}

func (s *scanner) bootstrap(c *carousel, moduleID uint16, version byte) {
	if c.haveVerifiedBoot && c.verifiedBootstrap == version {
		return
	}
	c.verifiedBootstrap, c.haveVerifiedBoot = version, true
	b := c.complete[moduleID].payload
	if len(b) < bootstrapFixed {
		s.dsmccError("PID %#04x: bootstrap payload of %d bytes", c.pid, len(b))
		return
	}
	count := int(binary.BigEndian.Uint16(b[42:44]))
	if bootstrapFixed+count*directoryEntry != len(b) {
		s.dsmccError("PID %#04x: bootstrap declares %d entries but carries %d bytes", c.pid, count, len(b))
		return
	}
	s.report.BootstrapModules++

	prevRole, prevID := -1, -1
	for i := range count {
		e := b[bootstrapFixed+i*directoryEntry:][:directoryEntry]
		role := int(e[0])
		id := int(binary.BigEndian.Uint16(e[2:4]))
		entryVersion := e[4]
		kind := e[5]
		partNumber := binary.BigEndian.Uint16(e[6:8])
		partCount := binary.BigEndian.Uint16(e[8:10])
		storedSize := binary.BigEndian.Uint32(e[18:22])

		if role != roleRealtime && role != roleObject {
			s.dsmccError("PID %#04x: directory entry %d has carousel role %d", c.pid, i, role)
		}
		if role < prevRole || (role == prevRole && id <= prevID) {
			s.dsmccError("PID %#04x: bootstrap directory is not in role and module id order", c.pid)
		}
		prevRole, prevID = role, id
		if kind == kindBootstrap {
			s.dsmccError("PID %#04x: the bootstrap lists itself", c.pid)
		}
		if partCount == 0 || partNumber >= partCount {
			s.dsmccError("PID %#04x: module %#04x is part %d of %d", c.pid, id, partNumber, partCount)
		}
		m, ok := c.modules[uint16(id)]
		if !ok {
			s.report.DirectoryUnadvertised++
			continue
		}
		if m.version != entryVersion || m.size != storedSize {
			s.dsmccError("PID %#04x: directory entry for %#04x says version %d size %d, the DII says %d and %d",
				c.pid, id, entryVersion, storedSize, m.version, m.size)
			continue
		}
		done := c.complete[uint16(id)]
		if done == nil {
			continue
		}
		if done.kind != kind {
			s.dsmccError("PID %#04x: directory says module %#04x is kind %#02x, the module header says %#02x",
				c.pid, id, kind, done.kind)
		}
		if !bytes.Equal(e[46:78], done.sha[:]) {
			s.dsmccError("PID %#04x: directory SHA-256 for module %#04x does not match the received payload", c.pid, id)
			continue
		}
		s.report.DirectoryVerified++
	}
}

func (s *scanner) manifest(c *carousel, moduleID uint16, version byte) {
	if c.haveVerifiedMan && c.verifiedManifest == version {
		return
	}
	m := c.complete[moduleID]
	if m.flags&flagCommit == 0 {
		return
	}
	b := m.payload
	if len(b) < 12 {
		s.dsmccError("PID %#04x: object manifest of %d bytes", c.pid, len(b))
		return
	}
	count := int(binary.BigEndian.Uint32(b[8:12]))
	p := 12
	resolved, pending := 0, false
	prevID := int64(-1)
	for range count {
		if p+objectHeaderLen > len(b) {
			s.dsmccError("PID %#04x: object manifest is truncated", c.pid)
			return
		}
		objectID := binary.BigEndian.Uint64(b[p : p+8])
		compression := b[p+10]
		parts := int(binary.BigEndian.Uint16(b[p+12 : p+14]))
		pathLen := int(binary.BigEndian.Uint16(b[p+14 : p+16]))
		mediaLen := int(binary.BigEndian.Uint16(b[p+16 : p+18]))
		metaLen := int(binary.BigEndian.Uint16(b[p+18 : p+20]))
		originalSize := binary.BigEndian.Uint64(b[p+20 : p+28])
		originalSHA := bytes.Clone(b[p+28 : p+60])
		p += objectHeaderLen
		if p+pathLen+mediaLen+metaLen > len(b) {
			s.dsmccError("PID %#04x: object %d name and metadata run past the manifest", c.pid, objectID)
			return
		}
		p += pathLen + mediaLen + metaLen
		if int64(objectID) <= prevID {
			s.dsmccError("PID %#04x: object manifest is not in object id order", c.pid)
		}
		prevID = int64(objectID)

		var joined []byte
		for n := range parts {
			if p+partEntryLen > len(b) {
				s.dsmccError("PID %#04x: object %d part loop is truncated", c.pid, objectID)
				return
			}
			partModule := binary.BigEndian.Uint16(b[p : p+2])
			partVersion := b[p+2]
			partNumber := binary.BigEndian.Uint16(b[p+4 : p+6])
			offset := binary.BigEndian.Uint32(b[p+8 : p+12])
			length := binary.BigEndian.Uint32(b[p+12 : p+16])
			partSHA := b[p+16 : p+48]
			p += partEntryLen
			if int(partNumber) != n {
				s.dsmccError("PID %#04x: object %d part numbers are not consecutive", c.pid, objectID)
			}
			host := c.complete[partModule]
			if host == nil {
				pending = true
				joined = nil
				break
			}
			if host.version != partVersion {
				s.dsmccError("PID %#04x: object %d part %d wants module %#04x version %d, the carousel has %d",
					c.pid, objectID, partNumber, partModule, partVersion, host.version)
				joined = nil
				break
			}
			if uint64(offset)+uint64(length) > uint64(len(host.payload)) {
				s.dsmccError("PID %#04x: object %d part %d runs past module %#04x", c.pid, objectID, partNumber, partModule)
				joined = nil
				break
			}
			run := host.payload[offset : offset+length]
			if sum := sha256.Sum256(run); !bytes.Equal(sum[:], partSHA) {
				s.dsmccError("PID %#04x: object %d part %d hash mismatch", c.pid, objectID, partNumber)
				joined = nil
				break
			}
			joined = append(joined, run...)
		}
		if joined == nil {
			continue
		}
		if compression == 0 {
			if uint64(len(joined)) != originalSize {
				s.dsmccError("PID %#04x: object %d reassembles to %d bytes, the manifest says %d",
					c.pid, objectID, len(joined), originalSize)
				continue
			}
			if sum := sha256.Sum256(joined); !bytes.Equal(sum[:], originalSHA) {
				s.dsmccError("PID %#04x: object %d hash does not match the manifest", c.pid, objectID)
				continue
			}
		}
		resolved++
	}
	if p != len(b) {
		s.dsmccError("PID %#04x: object manifest has %d bytes after its object loop", c.pid, len(b)-p)
	}
	if !pending {
		c.verifiedManifest, c.haveVerifiedMan = version, true
		s.report.ManifestsCommitted++
		s.report.ObjectsResolved += uint64(resolved)
	}
}

func writeDSMCCReport(w io.Writer, r Report) {
	if r.DSMCCSections == 0 {
		return
	}
	fmt.Fprintf(w, "DSM-CC: %d sections (DII %d, DDB %d), modules complete %d, verified %d\n",
		r.DSMCCSections, r.DIISections, r.DDBSections, r.ModulesComplete, r.ModulesVerified)
	if len(r.ModuleKinds) > 0 {
		kinds := make([]int, 0, len(r.ModuleKinds))
		for k := range r.ModuleKinds {
			kinds = append(kinds, int(k))
		}
		sort.Ints(kinds)
		fmt.Fprint(w, "  module kinds:")
		for _, k := range kinds {
			fmt.Fprintf(w, " %s=%d", moduleKindName(byte(k)), r.ModuleKinds[byte(k)])
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  bootstraps %d, directory entries verified %d (not advertised %d), commits %d, objects resolved %d\n",
		r.BootstrapModules, r.DirectoryVerified, r.DirectoryUnadvertised, r.ManifestsCommitted, r.ObjectsResolved)
	fmt.Fprintf(w, "  blocks not placed: before a DII %d, not in the DII %d, stale version %d, repeats %d\n",
		r.DDBBeforeDII, r.DDBNotInDII, r.DDBStaleVersion, r.DDBRepeats)
	for _, p := range r.DSMCCProblems {
		fmt.Fprintf(w, "  problem: %s\n", p)
	}
}

func moduleKindName(k byte) string {
	switch k {
	case kindBootstrap:
		return "bootstrap"
	case kindTimedSegment:
		return "segment"
	case kindStaticObject:
		return "object"
	case kindObjectManifest:
		return "manifest"
	case 0x05:
		return "codec"
	case 0x06:
		return "avmap"
	case kindLossReport:
		return "loss"
	}
	return fmt.Sprintf("kind%#02x", k)
}
