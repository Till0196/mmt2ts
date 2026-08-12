// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package appdata はデータ放送のアイテムとアプリ参照を収集する。
package appdata

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"mmt2ts/internal/si"
)

type Item struct {
	ID           uint32
	NodeTag      uint16
	Version      byte
	Size         uint32
	Checksum     uint32
	HasChecksum  bool
	Name         string
	Path         string
	Data         []byte
	MPUSequence  uint32
	Received     uint32
	mpu          uint32
	hasMPU       bool
	Repeats      uint64
	Compression  byte
	OriginalSize uint32
	Announced    bool
}

const (
	CompressionZlib = 0x00
	CompressionNone = 0xff
)

func (i *Item) Complete() bool { return i.Announced && i.Received == i.Size }

func (i *Item) ChecksumValid() (valid, ok bool) {
	if !i.HasChecksum || !i.Complete() {
		return false, false
	}
	return checksum32(i.Data) == i.Checksum, true
}

func checksum32(b []byte) uint32 {
	var sum uint32
	for len(b) >= 4 {
		sum += binary.BigEndian.Uint32(b[:4])
		b = b[4:]
	}
	if len(b) > 0 {
		var tail [4]byte
		copy(tail[:], b)
		sum += binary.BigEndian.Uint32(tail[:])
	}
	return sum
}

type Application struct {
	Type           uint16
	OrganizationID uint32
	ApplicationID  uint16
	ControlCode    byte
	Version        byte
	Location       string
	Protocol       uint16
	Descriptors    map[uint16]uint64
}

func (a *Application) Key() string {
	return fmt.Sprintf("%08x/%04x", a.OrganizationID, a.ApplicationID)
}

type Content struct {
	ID       uint16
	Version  byte
	Size     uint32
	NodeTags []uint16
}

type Stats struct {
	AITSections     uint64
	DAMTSections    uint64
	DDMTSections    uint64
	DCCTSections    uint64
	EMTSections     uint64
	UnknownTables   map[byte]uint64
	ParseErrors     map[byte]uint64
	ItemPayloads    uint64
	ItemBytes       uint64
	ItemsAnnounced  uint64
	ItemsComplete   uint64
	ItemsPartial    uint64
	ItemsUnknown    uint64
	ChecksumOK      uint64
	ChecksumBad     uint64
	ChecksumNone    uint64
	IndexItems      uint64
	IndexItemErrors uint64
	EventMessages   uint64
}

type Store struct {
	items        map[uint32]*Item
	byNode       map[uint16]*Item
	apps         map[string]*Application
	contents     map[uint16]*Content
	nodePaths    map[uint16]string
	pendingNames map[uint16]pending
	indexMPUs    map[uint32]bool
	indexDone    map[uint32]bool
	indexCand    map[indexKey][]byte
	indexCarrier map[uint32]bool
	stats        Stats
	maxItemBytes uint64
	heldBytes    uint64
}

// indexKey はindex item候補の再組立単位。index itemを載せるMPUは通常のitemも
// 一緒に運ぶため、MPUだけでなくitemごとに候補を貯める。
type indexKey struct{ mpu, item uint32 }

const DefaultMaxItemBytes = 64 << 20

// MaxIndexItemBytes はindex item候補として貯めるバイト数の上限。index itemは
// itemの一覧に過ぎず、コンテンツ本体のような大きさにはなりません。
const MaxIndexItemBytes = 1 << 20

func New() *Store {
	return &Store{
		items:        make(map[uint32]*Item),
		byNode:       make(map[uint16]*Item),
		apps:         make(map[string]*Application),
		contents:     make(map[uint16]*Content),
		nodePaths:    make(map[uint16]string),
		pendingNames: make(map[uint16]pending),
		indexMPUs:    make(map[uint32]bool),
		indexDone:    make(map[uint32]bool),
		indexCand:    make(map[indexKey][]byte),
		indexCarrier: make(map[uint32]bool),
		maxItemBytes: DefaultMaxItemBytes,
		stats: Stats{
			UnknownTables: make(map[byte]uint64),
			ParseErrors:   make(map[byte]uint64),
		},
	}
}

func (s *Store) Stats() Stats { return s.stats }

func (s *Store) Items() []*Item {
	out := make([]*Item, 0, len(s.items))
	for _, it := range s.items {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) Item(id uint32) *Item { return s.items[id] }

func (s *Store) Applications() []*Application {
	out := make([]*Application, 0, len(s.apps))
	for _, a := range s.apps {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

func (s *Store) PushItemData(mpuSequence, itemID uint32, data []byte) {
	s.stats.ItemPayloads++
	s.stats.ItemBytes += uint64(len(data))
	if s.indexCarrier[itemID] {
		// index itemはitemの一覧であってコンテンツではないので、通常のitemとしては保持しない。
		if !s.indexDone[mpuSequence] {
			s.pushIndexData(mpuSequence, itemID, data)
		}
		return
	}
	if s.indexMPUs[mpuSequence] && !s.indexDone[mpuSequence] {
		s.pushIndexData(mpuSequence, itemID, data)
		if s.indexCarrier[itemID] {
			return
		}
	}
	it := s.items[itemID]
	if it == nil {
		it = &Item{ID: itemID}
		s.items[itemID] = it
	}
	if (it.Announced && it.Received >= it.Size) || (it.hasMPU && it.mpu != mpuSequence && it.Received > 0 && !it.Announced) {
		it.Repeats++
		s.heldBytes -= uint64(len(it.Data))
		it.Data, it.Received = it.Data[:0], 0
	}
	it.mpu, it.hasMPU = mpuSequence, true
	it.MPUSequence = mpuSequence
	it.Received += uint32(len(data))
	if s.heldBytes+uint64(len(data)) <= s.maxItemBytes {
		if it.Data == nil && it.Announced && it.Size > 0 && uint64(it.Size) <= s.maxItemBytes {
			it.Data = make([]byte, 0, it.Size)
		}
		it.Data = append(it.Data, data...)
		s.heldBytes += uint64(len(data))
	}
}

func (s *Store) PushAIT(ait *si.AIT) {
	s.stats.AITSections++
	for _, app := range ait.Applications {
		a := &Application{
			Type:           ait.ApplicationType,
			OrganizationID: app.OrganizationID,
			ApplicationID:  app.ApplicationID,
			ControlCode:    app.ControlCode,
			Version:        ait.Version,
			Descriptors:    make(map[uint16]uint64),
		}
		for _, d := range app.Descriptors {
			a.Descriptors[d.Tag]++
			switch d.Tag {
			case tagSimpleApplicationLocation:
				a.Location = string(d.Data)
			case tagTransportProtocol:
				if len(d.Data) >= 2 {
					a.Protocol = binary.BigEndian.Uint16(d.Data[:2])
				}
			}
		}
		if old, ok := s.apps[a.Key()]; ok && old.Version == a.Version {
			continue
		}
		s.apps[a.Key()] = a
	}
}

const (
	tagApplication               = 0x8029
	tagTransportProtocol         = 0x802a
	tagSimpleApplicationLocation = 0x802b
)

func (s *Store) PushTable(sec si.Section) {
	switch sec.TableID {
	case si.TableIDDAMT:
		s.stats.DAMTSections++
		if !s.damt(sec) {
			s.stats.ParseErrors[sec.TableID]++
		}
	case si.TableIDDDMT:
		s.stats.DDMTSections++
		if !s.ddmt(sec) {
			s.stats.ParseErrors[sec.TableID]++
		}
	case si.TableIDDCCT:
		s.stats.DCCTSections++
		if !s.dcct(sec) {
			s.stats.ParseErrors[sec.TableID]++
		}
	case si.TableIDEMT:
		s.stats.EMTSections++
		s.stats.EventMessages++
	default:
		s.stats.UnknownTables[sec.TableID]++
	}
}

func (s *Store) damt(sec si.Section) bool {
	b := sec.Body
	if len(b) < 11 {
		return false
	}
	p := 10
	mpus := int(b[p])
	p++
	for range mpus {
		if len(b)-p < 9 {
			return false
		}
		sequence := binary.BigEndian.Uint32(b[p : p+4])
		p += 8
		flags := b[p]
		p++
		indexItem := flags&0x80 != 0
		if indexItem {
			s.indexMPUs[sequence] = true
		}
		if indexItem && flags&0x40 != 0 {
			if len(b)-p < 4 {
				return false
			}
			p += 4
		}
		if len(b)-p < 2 {
			return false
		}
		count := int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2
		for range count {
			n, ok := s.damtItem(b[p:], indexItem)
			if !ok {
				return false
			}
			p += n
		}
		if len(b)-p < 1 {
			return false
		}
		infoLen := int(b[p])
		p++
		if len(b)-p < infoLen {
			return false
		}
		p += infoLen
	}
	return true
}

func (s *Store) damtItem(b []byte, indexItem bool) (int, bool) {
	if len(b) < 2 {
		return 0, false
	}
	nodeTag := binary.BigEndian.Uint16(b[0:2])
	p := 2
	var id uint32
	if !indexItem {
		if len(b)-p < 4 {
			return 0, false
		}
		id = binary.BigEndian.Uint32(b[p : p+4])
		p += 4
	}
	if len(b)-p < 6 {
		return 0, false
	}
	size := binary.BigEndian.Uint32(b[p : p+4])
	version := b[p+4]
	flags := b[p+5]
	p += 6
	var sum uint32
	hasSum := flags&0x80 != 0
	if hasSum {
		if len(b)-p < 4 {
			return 0, false
		}
		sum = binary.BigEndian.Uint32(b[p : p+4])
		p += 4
	}
	if len(b)-p < 1 {
		return 0, false
	}
	infoLen := int(b[p])
	p++
	if len(b)-p < infoLen {
		return 0, false
	}
	p += infoLen

	it := s.items[id]
	if it == nil {
		it = &Item{ID: id}
		s.items[id] = it
	}
	if !it.Announced {
		s.stats.ItemsAnnounced++
	}
	it.NodeTag, it.Size, it.Version = nodeTag, size, version
	it.Checksum, it.HasChecksum, it.Announced = sum, hasSum, true
	it.Path = s.nodePaths[nodeTag]
	s.byNode[nodeTag] = it
	return p, true
}

func (s *Store) ddmt(sec si.Section) bool {
	b := sec.Body
	if len(b) < 2 {
		return false
	}
	baseLen := int(b[0])
	p := 1
	if len(b)-p < baseLen+1 {
		return false
	}
	base := string(b[p : p+baseLen])
	p += baseLen
	nodes := int(b[p])
	p++
	for range nodes {
		if len(b)-p < 4 {
			return false
		}
		nodeTag := binary.BigEndian.Uint16(b[p : p+2])
		pathLen := int(b[p+3])
		p += 4
		if len(b)-p < pathLen+2 {
			return false
		}
		path := base + string(b[p:p+pathLen])
		p += pathLen
		s.nodePaths[nodeTag] = path
		files := int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2
		for range files {
			if len(b)-p < 3 {
				return false
			}
			fileTag := binary.BigEndian.Uint16(b[p : p+2])
			nameLen := int(b[p+2])
			p += 3
			if len(b)-p < nameLen {
				return false
			}
			name := string(b[p : p+nameLen])
			p += nameLen
			s.nodePaths[fileTag] = path
			if it, ok := s.byNode[fileTag]; ok {
				it.Name, it.Path = name, path
			} else {
				s.pendingNames[fileTag] = pending{name: name, path: path}
			}
		}
	}
	return true
}

type pending struct{ name, path string }

// pushIndexData はindex itemを載せるMPUのpayloadを再組立し、index itemとして
// 読み切れたところで反映する。DAMTはindex itemのitem idを伝えず、当のMPUは
// コンテンツのitemも一緒に運ぶため、どのitemがindex itemかはpayloadを解析して
// 判別する。分割されて届く場合に備え、itemごとに継ぎ足しながら試す。
func (s *Store) pushIndexData(mpuSequence, itemID uint32, data []byte) {
	k := indexKey{mpu: mpuSequence, item: itemID}
	buf := append(s.indexCand[k], data...)
	if len(buf) > MaxIndexItemBytes {
		delete(s.indexCand, k)
		return
	}
	s.indexCand[k] = buf
	if !s.parseIndexItem(buf) {
		return
	}
	s.stats.IndexItems++
	s.indexDone[mpuSequence] = true
	s.indexCarrier[itemID] = true
	s.dropIndexCarrier(itemID)
	for key := range s.indexCand {
		if key.mpu == mpuSequence {
			delete(s.indexCand, key)
		}
	}
}

// dropIndexCarrier はindex itemを運んでいたitem idを、通常のitemの一覧から外す。
// index itemと分かる前に届いたpayloadがitemとして残るのを防ぐ。
func (s *Store) dropIndexCarrier(itemID uint32) {
	it := s.items[itemID]
	if it == nil || it.Announced {
		return
	}
	s.heldBytes -= uint64(len(it.Data))
	delete(s.items, itemID)
}

type indexEntry struct {
	id, size, originalSize uint32
	version, compression   byte
	sum                    uint32
	hasSum                 bool
	name                   string
}

// parseIndexItem はindex itemを解析する。呼び出し側はindex itemか分からないpayloadも
// 渡すため、末尾まで過不足なく読み切れた場合だけ成功とする。これがないとHTML等の
// コンテンツが偶然entryとして読めてしまい、その中身がitem名やサイズとして残る。
// 途中で失敗した断片を残さないよう、全entryを読み切ってからstoreへ反映する。
func (s *Store) parseIndexItem(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	count := int(binary.BigEndian.Uint16(b[0:2]))
	p := 2
	entries := make([]indexEntry, 0, count)
	for range count {
		if len(b)-p < 10 {
			return false
		}
		id := binary.BigEndian.Uint32(b[p : p+4])
		size := binary.BigEndian.Uint32(b[p+4 : p+8])
		version := b[p+8]
		nameLen := int(b[p+9])
		p += 10
		if len(b)-p < nameLen+1 {
			return false
		}
		name := string(b[p : p+nameLen])
		p += nameLen
		flags := b[p]
		p++
		var sum uint32
		hasSum := flags&0x80 != 0
		if hasSum {
			if len(b)-p < 4 {
				return false
			}
			sum = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}
		if len(b)-p < 1 {
			return false
		}
		typeLen := int(b[p])
		p++
		if len(b)-p < typeLen+1 {
			return false
		}
		p += typeLen
		compression := b[p]
		p++
		var originalSize uint32
		if compression != 0xff {
			if len(b)-p < 4 {
				return false
			}
			originalSize = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}
		entries = append(entries, indexEntry{
			id: id, size: size, originalSize: originalSize,
			version: version, compression: compression,
			sum: sum, hasSum: hasSum, name: name,
		})
	}
	if p != len(b) {
		return false
	}
	for _, e := range entries {
		it := s.items[e.id]
		if it == nil {
			it = &Item{ID: e.id}
			s.items[e.id] = it
		}
		if !it.Announced {
			s.stats.ItemsAnnounced++
		}
		it.Size, it.Version, it.Name = e.size, e.version, e.name
		it.Compression, it.OriginalSize = e.compression, e.originalSize
		it.Checksum, it.HasChecksum, it.Announced = e.sum, e.hasSum, true
	}
	return true
}

func (s *Store) dcct(sec si.Section) bool {
	b := sec.Body
	if len(b) < 8 {
		return false
	}
	c := &Content{
		ID:      binary.BigEndian.Uint16(b[0:2]),
		Version: b[2],
		Size:    binary.BigEndian.Uint32(b[3:7]),
	}
	flags := b[7]
	p := 8
	if flags&0x80 != 0 {
		if len(b)-p < 2 {
			return false
		}
		units := int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2
		for range units {
			if len(b)-p < 4 {
				return false
			}
			tags := int(b[p+3])
			p += 4
			for range tags {
				if len(b)-p < 2 {
					return false
				}
				c.NodeTags = append(c.NodeTags, binary.BigEndian.Uint16(b[p:p+2]))
				p += 2
			}
			if len(b)-p < 2 {
				return false
			}
			descLen := int(binary.BigEndian.Uint16(b[p : p+2]))
			p += 2
			if len(b)-p < descLen {
				return false
			}
			p += descLen
		}
	} else {
		if len(b)-p < 2 {
			return false
		}
		tags := int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2
		for range tags {
			if len(b)-p < 2 {
				return false
			}
			c.NodeTags = append(c.NodeTags, binary.BigEndian.Uint16(b[p:p+2]))
			p += 2
		}
	}
	s.contents[c.ID] = c
	return true
}

func (s *Store) Finish() {
	for tag, p := range s.pendingNames {
		if it, ok := s.byNode[tag]; ok {
			it.Name, it.Path = p.name, p.path
		}
	}
	clear(s.pendingNames)
	// DAMTがindex itemを載せると言ったMPUのうち、最後まで読み切れなかったものを数える。
	for mpu := range s.indexMPUs {
		if !s.indexDone[mpu] {
			s.stats.IndexItemErrors++
		}
	}
	clear(s.indexCand)
	for _, it := range s.items {
		switch {
		case !it.Announced:
			s.stats.ItemsUnknown++
		case it.Complete():
			s.stats.ItemsComplete++
		default:
			s.stats.ItemsPartial++
		}
		valid, ok := it.ChecksumValid()
		switch {
		case !ok:
			s.stats.ChecksumNone++
		case valid:
			s.stats.ChecksumOK++
		default:
			s.stats.ChecksumBad++
		}
	}
}

type Reference struct {
	Application string
	Target      string
	Resolved    bool
	Reason      string
}

func (s *Store) Graph() []Reference {
	var out []Reference
	for _, a := range s.Applications() {
		if a.Location == "" {
			out = append(out, Reference{
				Application: a.Key(),
				Target:      "entry point",
				Reason:      "no MH-simple application location descriptor",
			})
			continue
		}
		ref := Reference{Application: a.Key(), Target: a.Location}
		base := a.Location
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		for _, it := range s.items {
			if it.Name == "" {
				continue
			}
			full := it.Path+it.Name == a.Location
			if !full && it.Name != base {
				continue
			}
			switch {
			case !it.Complete():
				ref.Reason = "the item it names is incomplete"
			case full:
				ref.Resolved = true
			default:
				ref.Resolved = true
				ref.Reason = "matched by file name, not by full path"
			}
			break
		}
		if !ref.Resolved && ref.Reason == "" {
			ref.Reason = "no item with that name arrived"
		}
		out = append(out, ref)
	}
	return out
}
