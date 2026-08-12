// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package tlv はTLVを同期し直し、圧縮IPを展開してUDPペイロードを渡す。
package tlv

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

const (
	SyncByte = 0x7f

	TypeIPv4         = 0x01
	TypeIPv6         = 0x02
	TypeCompressedIP = 0x03
	TypeControl      = 0xfe
	TypeNull         = 0xff

	cidIPv4Partial = 0x20
	cidIPv4None    = 0x21
	cidIPv6Partial = 0x60
	cidIPv6None    = 0x61

	protoUDP          = 17
	protoIPv6Fragment = 44

	ipv4MinHeader = 20
	ipv6Header    = 40
	udpHeader     = 8
)

const TableIDNITActual = 0x40

func NetworkID(payload []byte) (uint16, bool) {
	if len(payload) < 8 || payload[0] != TableIDNITActual {
		return 0, false
	}
	sectionLength := int(binary.BigEndian.Uint16(payload[1:3]) & 0x0fff)
	if sectionLength < 9 || 3+sectionLength > len(payload) {
		return 0, false
	}
	if payload[5]&1 == 0 {
		return 0, false
	}
	return binary.BigEndian.Uint16(payload[3:5]), true
}

type Stats struct {
	Bytes               uint64
	Packets             uint64
	NullPackets         uint64
	Resyncs             uint64
	TruncatedPackets    uint64
	IPv4Packets         uint64
	IPv6Packets         uint64
	CompressedIPv4      uint64
	CompressedIPv6      uint64
	ControlPackets      uint64
	UnknownType         map[byte]uint64
	UnknownCIDHeader    map[byte]uint64
	NonUDPPackets       uint64
	MalformedIP         uint64
	FragmentPackets     uint64
	ReassembledIP       uint64
	FragmentErrors      uint64
	CompressedNoContext uint64
}

func newStats() Stats {
	return Stats{UnknownType: make(map[byte]uint64), UnknownCIDHeader: make(map[byte]uint64)}
}

type Packet struct {
	Type    byte
	Payload []byte
	Offset  uint64
}

type ipContext struct {
	src, dst [16]byte
	addrLen  int
	srcPort  uint16
	dstPort  uint16
	hasPort  bool
}

type Reader struct {
	br        *bufio.Reader
	buf       []byte
	stats     Stats
	pos       uint64
	hdr       [4]byte
	contexts  map[uint16]*ipContext
	fragments map[ipFragmentKey]*ipFragmentSet
}

func NewReader(r io.Reader) *Reader {
	return &Reader{
		br:        bufio.NewReaderSize(r, 1<<20),
		buf:       make([]byte, 0, 65536),
		stats:     newStats(),
		contexts:  make(map[uint16]*ipContext),
		fragments: make(map[ipFragmentKey]*ipFragmentSet),
	}
}

func (r *Reader) Stats() Stats { return r.stats }

func (r *Reader) Next() (Packet, error) {
	for {
		if _, err := io.ReadFull(r.br, r.hdr[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				r.pos += 4
				return Packet{}, io.EOF
			}
			return Packet{}, err
		}
		r.pos += 4
		if r.hdr[0] != SyncByte {
			r.stats.Resyncs++
			skipped, err := r.resync()
			r.pos += skipped
			if err != nil {
				return Packet{}, err
			}
		}
		offset := r.pos - 4
		length := int(binary.BigEndian.Uint16(r.hdr[2:4]))
		if cap(r.buf) < length {
			r.buf = make([]byte, length)
		}
		payload := r.buf[:length]
		n, err := io.ReadFull(r.br, payload)
		r.pos += uint64(n)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				r.stats.TruncatedPackets++
				return Packet{}, io.EOF
			}
			return Packet{}, err
		}
		r.stats.Bytes += uint64(4 + length)
		r.stats.Packets++
		if r.hdr[1] == TypeNull {
			r.stats.NullPackets++
			continue
		}
		return Packet{Type: r.hdr[1], Payload: payload, Offset: offset}, nil
	}
}

func (r *Reader) resync() (uint64, error) {
	var skipped uint64
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			return skipped, err
		}
		skipped++
		copy(r.hdr[:], r.hdr[1:])
		r.hdr[3] = b
		if r.hdr[0] == SyncByte {
			return skipped, nil
		}
	}
}

type Datagram struct {
	Payload []byte
	SrcPort uint16
	DstPort uint16
	HasPort bool
	Src     []byte
	Dst     []byte
	CID     uint16
	HasCID  bool
}

func (d Datagram) IsNTP() bool { return d.HasPort && d.DstPort == NTPPort }

const NTPPort = 123

func (r *Reader) Datagram(p Packet) (Datagram, bool) {
	switch p.Type {
	case TypeIPv4:
		r.stats.IPv4Packets++
		return r.ipv4Datagram(p.Payload)
	case TypeIPv6:
		r.stats.IPv6Packets++
		return r.ipv6Datagram(p.Payload)
	case TypeCompressedIP:
		return r.compressedDatagram(p.Payload)
	case TypeControl:
		r.stats.ControlPackets++
		return Datagram{}, false
	default:
		r.stats.UnknownType[p.Type]++
		return Datagram{}, false
	}
}

func (r *Reader) ipv4Datagram(b []byte) (Datagram, bool) {
	if len(b) < ipv4MinHeader || b[0]>>4 != 4 {
		r.stats.MalformedIP++
		return Datagram{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < ipv4MinHeader || len(b) < ihl {
		r.stats.MalformedIP++
		return Datagram{}, false
	}
	if b[9] != protoUDP {
		r.stats.NonUDPPackets++
		return Datagram{}, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl || total > len(b) {
		r.stats.MalformedIP++
		return Datagram{}, false
	}
	ipPayload := b[ihl:total]
	frag := binary.BigEndian.Uint16(b[6:8])
	if frag&0x3fff != 0 {
		var complete bool
		ipPayload, complete = r.addIPFragment(ipFragmentKey{
			version: 4, id: uint32(binary.BigEndian.Uint16(b[4:6])), protocol: b[9],
			src: string(b[12:16]), dst: string(b[16:20]),
		}, int(frag&0x1fff)*8, frag&0x2000 != 0, ipPayload)
		if !complete {
			return Datagram{}, false
		}
	}
	d, ok := r.udpDatagram(ipPayload)
	if ok {
		d.Src, d.Dst = b[12:16], b[16:20]
	}
	return d, ok
}

func (r *Reader) ipv6Datagram(b []byte) (Datagram, bool) {
	if len(b) < ipv6Header || b[0]>>4 != 6 {
		r.stats.MalformedIP++
		return Datagram{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
	if ipv6Header+payloadLen > len(b) {
		r.stats.MalformedIP++
		return Datagram{}, false
	}
	next := b[6]
	payload := b[ipv6Header : ipv6Header+payloadLen]
	for isIPv6Extension(next) {
		if next == protoIPv6Fragment {
			if len(payload) < 8 {
				r.stats.MalformedIP++
				return Datagram{}, false
			}
			fragmentNext := payload[0]
			field := binary.BigEndian.Uint16(payload[2:4])
			var complete bool
			payload, complete = r.addIPFragment(ipFragmentKey{
				version: 6, id: binary.BigEndian.Uint32(payload[4:8]), protocol: fragmentNext,
				src: string(b[8:24]), dst: string(b[24:40]),
			}, int(field>>3)*8, field&1 != 0, payload[8:])
			if !complete {
				return Datagram{}, false
			}
			next = fragmentNext
			break
		}
		var ok bool
		next, payload, ok = skipIPv6Extension(next, payload)
		if !ok {
			r.stats.MalformedIP++
			return Datagram{}, false
		}
	}
	for isIPv6Extension(next) {
		var ok bool
		next, payload, ok = skipIPv6Extension(next, payload)
		if !ok || next == protoIPv6Fragment {
			r.stats.MalformedIP++
			return Datagram{}, false
		}
	}
	if next != protoUDP {
		r.stats.NonUDPPackets++
		return Datagram{}, false
	}
	d, ok := r.udpDatagram(payload)
	if ok {
		d.Src, d.Dst = b[8:24], b[24:40]
	}
	return d, ok
}

func isIPv6Extension(next byte) bool {
	switch next {
	case 0, 43, protoIPv6Fragment, 51, 60:
		return true
	default:
		return false
	}
}

func skipIPv6Extension(kind byte, b []byte) (byte, []byte, bool) {
	if len(b) < 2 || kind == protoIPv6Fragment {
		return 0, nil, false
	}
	length := (int(b[1]) + 1) * 8
	if kind == 51 {
		length = (int(b[1]) + 2) * 4
	}
	if length > len(b) {
		return 0, nil, false
	}
	return b[0], b[length:], true
}

func (r *Reader) udpDatagram(b []byte) (Datagram, bool) {
	if len(b) < udpHeader {
		r.stats.MalformedIP++
		return Datagram{}, false
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length < udpHeader || length > len(b) {
		r.stats.MalformedIP++
		return Datagram{}, false
	}
	return Datagram{
		Payload: b[udpHeader:length],
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		HasPort: true,
	}, true
}

func (r *Reader) compressedDatagram(b []byte) (Datagram, bool) {
	if len(b) < 3 {
		r.stats.MalformedIP++
		return Datagram{}, false
	}
	d := Datagram{CID: binary.BigEndian.Uint16(b[:2]) >> 4, HasCID: true}
	switch b[2] {
	case cidIPv4Partial:
		if len(b) < 23 {
			r.stats.MalformedIP++
			return Datagram{}, false
		}
		r.stats.CompressedIPv4++
		if b[3]>>4 != 4 || b[3]&0x0f < 5 || b[10] != protoUDP {
			r.stats.MalformedIP++
			return Datagram{}, false
		}
		if binary.BigEndian.Uint16(b[7:9])&0x3fff != 0 {
			r.stats.MalformedIP++
			return Datagram{}, false
		}
		d.SrcPort = binary.BigEndian.Uint16(b[19:21])
		d.DstPort, d.HasPort = binary.BigEndian.Uint16(b[21:23]), true
		d.Payload = b[23:]
		d.Src, d.Dst = r.remember(d.CID, b[11:15], b[15:19], d.SrcPort, d.DstPort)
		return d, true
	case cidIPv6Partial:
		if len(b) < 45 {
			r.stats.MalformedIP++
			return Datagram{}, false
		}
		r.stats.CompressedIPv6++
		d.SrcPort = binary.BigEndian.Uint16(b[41:43])
		d.DstPort, d.HasPort = binary.BigEndian.Uint16(b[43:45]), true
		d.Payload = b[45:]
		d.Src, d.Dst = r.remember(d.CID, b[9:25], b[25:41], d.SrcPort, d.DstPort)
		return d, true
	case cidIPv6None:
		r.stats.CompressedIPv6++
		d.Payload = b[3:]
		r.recall(&d)
		return d, true
	case cidIPv4None:
		r.stats.CompressedIPv4++
		d.Payload = b[3:]
		r.recall(&d)
		return d, true
	default:
		r.stats.UnknownCIDHeader[b[2]]++
		return Datagram{}, false
	}
}

func (r *Reader) remember(cid uint16, src, dst []byte, srcPort, dstPort uint16) ([]byte, []byte) {
	c := r.contexts[cid]
	if c == nil {
		c = &ipContext{}
		r.contexts[cid] = c
	}
	c.addrLen = copy(c.src[:], src)
	copy(c.dst[:], dst)
	c.srcPort, c.dstPort, c.hasPort = srcPort, dstPort, true
	return c.src[:c.addrLen], c.dst[:c.addrLen]
}

func (r *Reader) recall(d *Datagram) {
	c := r.contexts[d.CID]
	if c == nil {
		r.stats.CompressedNoContext++
		return
	}
	d.Src, d.Dst = c.src[:c.addrLen], c.dst[:c.addrLen]
	if c.hasPort {
		d.SrcPort, d.DstPort, d.HasPort = c.srcPort, c.dstPort, true
	}
}
