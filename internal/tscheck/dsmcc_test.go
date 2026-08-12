// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tscheck

import (
	"bytes"
	"encoding/binary"
	"testing"
)

const testCarouselPID = 0x1d00

type packetizer struct {
	out bytes.Buffer
	cc  map[uint16]byte
}

func newPacketizer() *packetizer { return &packetizer{cc: make(map[uint16]byte)} }

func (p *packetizer) section(pid uint16, section []byte) {
	body := append([]byte{0x00}, section...)
	first := true
	for len(body) > 0 {
		n := min(184, len(body))
		pkt := make([]byte, 188)
		pkt[0] = 0x47
		pkt[1] = byte(pid >> 8)
		if first {
			pkt[1] |= 0x40
		}
		pkt[2] = byte(pid)
		pkt[3] = 0x10 | p.cc[pid]&0x0f
		p.cc[pid]++
		copy(pkt[4:], body[:n])
		for i := 4 + n; i < 188; i++ {
			pkt[i] = 0xff
		}
		p.out.Write(pkt)
		body = body[n:]
		first = false
	}
}

func longSection(tableID byte, extension uint16, version, number, last byte, body []byte) []byte {
	s := []byte{tableID, 0, 0}
	s = binary.BigEndian.AppendUint16(s, extension)
	s = append(s, 0xc1|version<<1&0x3e, number, last)
	s = append(s, body...)
	length := len(s) - 3 + 4
	binary.BigEndian.PutUint16(s[1:3], 0xb000|uint16(length&0x0fff))
	return binary.BigEndian.AppendUint32(s, crc32(s))
}

func testPAT() []byte {
	body := []byte{0x00, 0, 0}
	body = binary.BigEndian.AppendUint16(body, 0x4010)
	body = append(body, 0xc1, 0x00, 0x00)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = binary.BigEndian.AppendUint16(body, 0xe000|0x0100)
	length := len(body) - 3 + 4
	binary.BigEndian.PutUint16(body[1:3], 0xb000|uint16(length&0x0fff))
	return binary.BigEndian.AppendUint32(body, crc32(body))
}

func testPMT() []byte {
	body := []byte{0x02, 0, 0}
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, 0xc1, 0x00, 0x00)
	body = binary.BigEndian.AppendUint16(body, 0xe000|0x1011)
	body = binary.BigEndian.AppendUint16(body, 0xf000)
	body = append(body, 0x0b)
	body = binary.BigEndian.AppendUint16(body, 0xe000|testCarouselPID)
	body = binary.BigEndian.AppendUint16(body, 0xf000|3)
	body = append(body, 0x52, 0x01, 0xe0)
	length := len(body) - 3 + 4
	binary.BigEndian.PutUint16(body[1:3], 0xb000|uint16(length&0x0fff))
	return binary.BigEndian.AppendUint32(body, crc32(body))
}

func buildModule(kind byte, flags uint16, logicalID uint64, payload []byte) []byte {
	m := make([]byte, 48)
	copy(m, "MMTC")
	m[4] = 1
	m[5] = kind
	binary.BigEndian.PutUint16(m[6:8], flags)
	binary.BigEndian.PutUint16(m[12:14], 48)
	binary.BigEndian.PutUint64(m[16:24], logicalID)
	binary.BigEndian.PutUint32(m[36:40], uint32(len(payload)))
	binary.BigEndian.PutUint32(m[40:44], isoHDLC(payload))
	binary.BigEndian.PutUint32(m[44:48], isoHDLC(m))
	return append(m, payload...)
}

func buildDII(downloadID, transaction uint32, modules []diiModule, ids []uint16) []byte {
	body := binary.BigEndian.AppendUint32(nil, downloadID)
	body = binary.BigEndian.AppendUint16(body, dsmccBlockSize)
	body = append(body, 0x00, 0x00)
	body = binary.BigEndian.AppendUint32(body, 0)
	body = binary.BigEndian.AppendUint32(body, 500000)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(modules)))
	for i, m := range modules {
		body = binary.BigEndian.AppendUint16(body, ids[i])
		body = binary.BigEndian.AppendUint32(body, m.size)
		body = append(body, m.version, 0x00)
	}
	body = binary.BigEndian.AppendUint16(body, 0)

	msg := []byte{dsmccProtocol, dsmccTypeDown}
	msg = binary.BigEndian.AppendUint16(msg, dsmccMsgDII)
	msg = binary.BigEndian.AppendUint32(msg, transaction)
	msg = append(msg, 0xff, 0x00)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(body)))
	msg = append(msg, body...)
	return longSection(dsmccTableDII, uint16(transaction&0xffff), 0, 0, 0, msg)
}

func buildDDBs(downloadID uint32, moduleID uint16, version byte, module []byte) [][]byte {
	blocks := (len(module) + dsmccBlockSize - 1) / dsmccBlockSize
	out := make([][]byte, 0, blocks)
	for i := range blocks {
		end := min((i+1)*dsmccBlockSize, len(module))
		body := binary.BigEndian.AppendUint16(nil, moduleID)
		body = append(body, version, 0xff)
		body = binary.BigEndian.AppendUint16(body, uint16(i))
		body = append(body, module[i*dsmccBlockSize:end]...)

		msg := []byte{dsmccProtocol, dsmccTypeDown}
		msg = binary.BigEndian.AppendUint16(msg, dsmccMsgDDB)
		msg = binary.BigEndian.AppendUint32(msg, downloadID)
		msg = append(msg, 0xff, 0x00)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(body)))
		msg = append(msg, body...)
		out = append(out, longSection(dsmccTableDDB, moduleID, version&0x1f, byte(i), byte(blocks-1), msg))
	}
	return out
}

func scanCarousel(t *testing.T, dii []byte, ddbs [][]byte) Report {
	t.Helper()
	p := newPacketizer()
	p.section(0x0000, testPAT())
	p.section(0x0100, testPMT())
	p.section(testCarouselPID, dii)
	for _, s := range ddbs {
		p.section(testCarouselPID, s)
	}
	r, err := Scan(bytes.NewReader(p.out.Bytes()))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return r
}

func threeBlockModule() []byte {
	payload := make([]byte, dsmccBlockSize*2+500)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	return buildModule(kindTimedSegment, 0, 42, payload)
}

func TestTheReaderRebuildsAModuleWhateverOrderItsBlocksArriveIn(t *testing.T) {
	const downloadID = 0x4d520066
	module := threeBlockModule()
	dii := buildDII(downloadID, 0x80000000, []diiModule{{size: uint32(len(module)), version: 3}}, []uint16{0x0100})
	blocks := buildDDBs(downloadID, 0x0100, 3, module)
	if len(blocks) != 3 {
		t.Fatalf("the test module needs %d blocks, want 3", len(blocks))
	}

	for _, tc := range []struct {
		name  string
		order [][]byte
	}{
		{"in order", blocks},
		{"reversed", [][]byte{blocks[2], blocks[1], blocks[0]}},
		{"middle first", [][]byte{blocks[1], blocks[2], blocks[0]}},
		{"with duplicates", [][]byte{blocks[0], blocks[0], blocks[1], blocks[2], blocks[2]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := scanCarousel(t, dii, tc.order)
			if r.DSMCCErrors != 0 {
				t.Fatalf("%d DSM-CC errors: %v", r.DSMCCErrors, r.DSMCCProblems)
			}
			if r.ModulesComplete != 1 || r.ModulesVerified != 1 {
				t.Errorf("modules complete %d, verified %d, want 1 and 1", r.ModulesComplete, r.ModulesVerified)
			}
			if r.ModuleKinds[kindTimedSegment] != 1 {
				t.Errorf("module kinds = %v", r.ModuleKinds)
			}
		})
	}
}

func TestDuplicateBlocksAreCountedAndNotTreatedAsErrors(t *testing.T) {
	const downloadID = 0x4d520066
	module := threeBlockModule()
	dii := buildDII(downloadID, 0x80000000, []diiModule{{size: uint32(len(module)), version: 3}}, []uint16{0x0100})
	blocks := buildDDBs(downloadID, 0x0100, 3, module)
	r := scanCarousel(t, dii, [][]byte{blocks[0], blocks[0], blocks[1], blocks[2]})
	if r.DDBRepeats != 1 {
		t.Errorf("DDBRepeats = %d, want 1", r.DDBRepeats)
	}
	if r.DSMCCErrors != 0 {
		t.Errorf("a repeated block was reported as an error: %v", r.DSMCCProblems)
	}
}

func TestBlocksThatTheCurrentDIIDoesNotAdvertiseAreDiscarded(t *testing.T) {
	const downloadID = 0x4d520066
	module := threeBlockModule()
	dii := buildDII(downloadID, 0x80000000, []diiModule{{size: uint32(len(module)), version: 4}}, []uint16{0x0100})

	stale := buildDDBs(downloadID, 0x0100, 3, module)
	current := buildDDBs(downloadID, 0x0100, 4, module)
	r := scanCarousel(t, dii, append(append([][]byte{}, stale...), current...))
	if r.DDBStaleVersion != uint64(len(stale)) {
		t.Errorf("DDBStaleVersion = %d, want %d", r.DDBStaleVersion, len(stale))
	}
	if r.ModulesVerified != 1 {
		t.Errorf("modules verified = %d, want 1", r.ModulesVerified)
	}
	if r.DSMCCErrors != 0 {
		t.Errorf("stale blocks were reported as errors: %v", r.DSMCCProblems)
	}

	other := buildDDBs(downloadID, 0x0200, 4, module)
	r = scanCarousel(t, dii, other)
	if r.DDBNotInDII != uint64(len(other)) {
		t.Errorf("DDBNotInDII = %d, want %d", r.DDBNotInDII, len(other))
	}
}

func TestTheReaderRejectsACorruptedModule(t *testing.T) {
	const downloadID = 0x4d520066
	for _, tc := range []struct {
		name   string
		damage func(m []byte)
	}{
		{"payload byte", func(m []byte) { m[60] ^= 0xff }},
		{"magic", func(m []byte) { m[0] = 'X' }},
		{"major version", func(m []byte) { m[4] = 2 }},
		{"header length", func(m []byte) { binary.BigEndian.PutUint16(m[12:14], 40) }},
		{"declared payload length", func(m []byte) { binary.BigEndian.PutUint32(m[36:40], 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			module := threeBlockModule()
			tc.damage(module)
			dii := buildDII(downloadID, 0x80000000, []diiModule{{size: uint32(len(module)), version: 3}}, []uint16{0x0100})
			r := scanCarousel(t, dii, buildDDBs(downloadID, 0x0100, 3, module))
			if r.DSMCCErrors == 0 {
				t.Errorf("a module damaged in its %s was accepted", tc.name)
			}
			if r.ModulesVerified != 0 {
				t.Errorf("a damaged module was reported as verified")
			}
		})
	}
}

func TestTheReaderRejectsDIIValuesTheProfileFixes(t *testing.T) {
	const downloadID = 0x4d520066
	module := threeBlockModule()
	good := buildDII(downloadID, 0x80000000, []diiModule{{size: uint32(len(module)), version: 3}}, []uint16{0x0100})

	for _, tc := range []struct {
		name   string
		damage func(s []byte)
	}{
		{"blockSize", func(s []byte) { binary.BigEndian.PutUint16(s[24:26], 4000) }},
		{"windowSize", func(s []byte) { s[26] = 1 }},
		{"ackPeriod", func(s []byte) { s[27] = 1 }},
		{"tCDownloadScenario", func(s []byte) { binary.BigEndian.PutUint32(s[32:36], 0) }},
		{"transaction_id top bits", func(s []byte) { s[12] = 0x00 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dii := bytes.Clone(good)
			tc.damage(dii)
			binary.BigEndian.PutUint32(dii[len(dii)-4:], crc32(dii[:len(dii)-4]))
			r := scanCarousel(t, dii, nil)
			if r.DSMCCErrors == 0 {
				t.Errorf("a DII with a wrong %s was accepted", tc.name)
			}
		})
	}
}

func TestBlocksBeforeAnyDIIAreHeldRatherThanFaulted(t *testing.T) {
	const downloadID = 0x4d520066
	module := threeBlockModule()
	blocks := buildDDBs(downloadID, 0x0100, 3, module)

	p := newPacketizer()
	p.section(0x0000, testPAT())
	p.section(0x0100, testPMT())
	for _, s := range blocks {
		p.section(testCarouselPID, s)
	}
	r, err := Scan(bytes.NewReader(p.out.Bytes()))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.DDBBeforeDII != uint64(len(blocks)) {
		t.Errorf("DDBBeforeDII = %d, want %d", r.DDBBeforeDII, len(blocks))
	}
	if r.DSMCCErrors != 0 {
		t.Errorf("joining before a DII was reported as an error: %v", r.DSMCCProblems)
	}
}
