// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package logocarousel はDSM-CCカルーセルから放送局ロゴを復元する。
package logocarousel

import "encoding/binary"

const (
	tableDII = 0x3b
	tableDDB = 0x3c
	msgDII   = 0x1002
	msgDDB   = 0x1003

	protocolDiscriminator = 0x11
	typeDownload          = 0x03

	headerLen   = 12
	maxLogoType = 0x05
	maxBlocks   = 4096
)

type Service struct {
	NetworkID         uint16
	TransportStreamID uint16
	ServiceID         uint16
}

type Logo struct {
	Type     byte
	ID       uint16
	Services []Service
	Data     []byte
}

type module struct {
	size    uint32
	version byte
	blocks  map[uint16][]byte
}

type carousel struct {
	haveDII    bool
	downloadID uint32
	blockSize  int
	modules    map[uint16]*module
}

type Reader struct {
	carousels map[uint16]*carousel
	logos     []Logo
	seen      map[logoKey]bool
	Modules   int
	Malformed int
}

type logoKey struct {
	logoType byte
	id       uint16
}

func New() *Reader {
	return &Reader{carousels: make(map[uint16]*carousel), seen: make(map[logoKey]bool)}
}

func (r *Reader) Logos() []Logo { return r.logos }

func (r *Reader) Push(pid uint16, section []byte) {
	if len(section) < 8+headerLen+4 {
		return
	}
	msg := section[8 : len(section)-4]
	if msg[0] != protocolDiscriminator || msg[1] != typeDownload {
		return
	}
	c := r.carousels[pid]
	if c == nil {
		c = &carousel{modules: make(map[uint16]*module)}
		r.carousels[pid] = c
	}
	id := binary.BigEndian.Uint32(msg[4:8])
	body := msg[headerLen:]
	switch {
	case section[0] == tableDII && binary.BigEndian.Uint16(msg[2:4]) == msgDII:
		r.dii(c, body)
	case section[0] == tableDDB && binary.BigEndian.Uint16(msg[2:4]) == msgDDB:
		r.ddb(c, id, body)
	}
}

func (r *Reader) dii(c *carousel, body []byte) {
	if len(body) < 20 {
		return
	}
	downloadID := binary.BigEndian.Uint32(body[0:4])
	blockSize := int(binary.BigEndian.Uint16(body[4:6]))
	compatibility := int(binary.BigEndian.Uint16(body[16:18]))
	p := 18 + compatibility
	if p+2 > len(body) || blockSize == 0 {
		return
	}
	count := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	next := make(map[uint16]*module, count)
	for range count {
		if p+8 > len(body) {
			return
		}
		id := binary.BigEndian.Uint16(body[p : p+2])
		size := binary.BigEndian.Uint32(body[p+2 : p+6])
		version := body[p+6]
		p += 8 + int(body[p+7])
		if size == 0 || int(size) > blockSize*maxBlocks {
			continue
		}
		if old := c.modules[id]; old != nil && old.version == version && old.size == size {
			next[id] = old
			continue
		}
		next[id] = &module{size: size, version: version, blocks: make(map[uint16][]byte)}
	}
	c.downloadID, c.blockSize, c.modules, c.haveDII = downloadID, blockSize, next, true
}

func (r *Reader) ddb(c *carousel, downloadID uint32, body []byte) {
	if !c.haveDII || downloadID != c.downloadID || len(body) < 6 {
		return
	}
	m := c.modules[binary.BigEndian.Uint16(body[0:2])]
	if m == nil || m.version != body[2] {
		return
	}
	blockNumber := binary.BigEndian.Uint16(body[4:6])
	total := (int(m.size) + c.blockSize - 1) / c.blockSize
	if int(blockNumber) >= total {
		return
	}
	want := c.blockSize
	if int(blockNumber) == total-1 {
		want = int(m.size) - c.blockSize*(total-1)
	}
	block := body[6:]
	if len(block) < want {
		return
	}
	if _, have := m.blocks[blockNumber]; have {
		return
	}
	m.blocks[blockNumber] = append([]byte(nil), block[:want]...)
	if len(m.blocks) != total {
		return
	}
	data := make([]byte, 0, m.size)
	for i := range total {
		data = append(data, m.blocks[uint16(i)]...)
	}
	m.blocks = make(map[uint16][]byte)
	r.moduleComplete(data)
}

func (r *Reader) moduleComplete(data []byte) {
	if len(data) < 3 || data[0] > maxLogoType {
		r.Malformed++
		return
	}
	r.Modules++
	logoType := data[0]
	count := int(binary.BigEndian.Uint16(data[1:3]))
	p := 3
	for range count {
		if p+3 > len(data) {
			r.Malformed++
			return
		}
		id := uint16(data[p]&0x01)<<8 | uint16(data[p+1])
		services := int(data[p+2])
		p += 3
		if p+6*services+2 > len(data) {
			r.Malformed++
			return
		}
		logo := Logo{Type: logoType, ID: id}
		for range services {
			logo.Services = append(logo.Services, Service{
				NetworkID:         binary.BigEndian.Uint16(data[p : p+2]),
				TransportStreamID: binary.BigEndian.Uint16(data[p+2 : p+4]),
				ServiceID:         binary.BigEndian.Uint16(data[p+4 : p+6]),
			})
			p += 6
		}
		size := int(binary.BigEndian.Uint16(data[p : p+2]))
		p += 2
		if p+size > len(data) {
			r.Malformed++
			return
		}
		logo.Data = append([]byte(nil), data[p:p+size]...)
		p += size
		if len(logo.Services) == 0 || size == 0 {
			continue
		}
		key := logoKey{logoType, id}
		if r.seen[key] {
			continue
		}
		r.seen[key] = true
		r.logos = append(r.logos, logo)
	}
}
