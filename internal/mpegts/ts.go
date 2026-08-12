// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package mpegts はTSパケットとPSI/SIセクションを組み立てる。
package mpegts

import (
	"errors"
	"io"

	"mmt2ts/internal/iox"
)

const (
	PacketSize    = 188
	payloadSize   = 184
	SyncByte      = 0x47
	PIDPAT        = 0x0000
	PIDNull       = 0x1fff
	maxPID        = 0x1fff
	afcPayload    = 0x01
	afcAdaptation = 0x02
	afcBoth       = 0x03
)

var ErrInvalidPID = errors.New("mpegts: PID out of range")

type Adaptation struct {
	PCR           int64
	HasPCR        bool
	Discontinuity bool
	RandomAccess  bool
	Priority      bool
}

func (a Adaptation) empty() bool {
	return !a.HasPCR && !a.Discontinuity && !a.RandomAccess && !a.Priority
}

const outBufferPackets = 1024

type BlockWriter interface {
	io.Writer
	NextBlock() []byte
	WriteBlock(b []byte) error
}

func (w *Writer) SkipContinuity(pid uint16, n uint32) {
	if pid > maxPID || n == 0 {
		return
	}
	w.cc[pid] = (w.cc[pid] + byte(n&0x0f)) & 0x0f
}

type Writer struct {
	w       io.Writer
	blocks  BlockWriter
	cc      [maxPID + 1]byte
	out     []byte
	sec     []byte
	Packets uint64
	Bytes   uint64
}

func NewWriter(w io.Writer) *Writer {
	tw := &Writer{w: w}
	if b, ok := w.(BlockWriter); ok {
		tw.blocks = b
		tw.out = b.NextBlock()
	} else {
		tw.out = make([]byte, 0, outBufferPackets*PacketSize)
	}
	return tw
}

func (w *Writer) Flush() error {
	if len(w.out) == 0 {
		return nil
	}
	if w.blocks != nil {
		if err := w.blocks.WriteBlock(w.out); err != nil {
			return err
		}
		w.out = w.blocks.NextBlock()
		return nil
	}
	if err := iox.WriteFull(w.w, w.out); err != nil {
		return err
	}
	w.out = w.out[:0]
	return nil
}

func (w *Writer) packet() ([]byte, error) {
	if len(w.out)+PacketSize > cap(w.out) {
		if err := w.Flush(); err != nil {
			return nil, err
		}
	}
	n := len(w.out)
	w.out = w.out[:n+PacketSize]
	w.Packets++
	w.Bytes += PacketSize
	return w.out[n : n+PacketSize], nil
}

func (w *Writer) WriteUnit(pid uint16, payload []byte, first Adaptation) error {
	return w.WriteUnitParts(pid, payload, nil, first)
}

func (w *Writer) WriteUnitParts(pid uint16, head, tail []byte, first Adaptation) error {
	if pid > maxPID {
		return ErrInvalidPID
	}
	start := true
	af := first
	for {
		n, err := w.writePacketParts(pid, start, af, head, tail)
		if err != nil {
			return err
		}
		if n <= len(head) {
			head = head[n:]
		} else {
			tail = tail[n-len(head):]
			head = nil
		}
		start = false
		af = Adaptation{}
		if len(head)+len(tail) == 0 {
			return nil
		}
	}
}

func (w *Writer) WriteAdaptationOnly(pid uint16, af Adaptation) error {
	if pid > maxPID {
		return ErrInvalidPID
	}
	_, err := w.writePacket(pid, false, af, nil)
	return err
}

func (w *Writer) WriteNull() error {
	p, err := w.packet()
	if err != nil {
		return err
	}
	p[0] = SyncByte
	p[1] = byte(PIDNull >> 8)
	p[2] = byte(PIDNull & 0xff)
	p[3] = afcPayload << 4
	for i := 4; i < PacketSize; i++ {
		p[i] = 0xff
	}
	return nil
}

func (w *Writer) writePacket(pid uint16, start bool, af Adaptation, payload []byte) (int, error) {
	return w.writePacketParts(pid, start, af, payload, nil)
}

func (w *Writer) writePacketParts(pid uint16, start bool, af Adaptation, head, tail []byte) (int, error) {
	total := len(head) + len(tail)
	afLen := 0
	if !af.empty() {
		afLen = 2
		if af.HasPCR {
			afLen += 6
		}
	}
	space := payloadSize - afLen
	if space < 0 {
		return 0, errors.New("mpegts: adaptation field larger than packet")
	}
	take := min(total, space)
	stuffing := space - take
	if stuffing > 0 {
		if afLen == 0 {
			afLen = 1
			stuffing--
			if stuffing > 0 {
				afLen++
				stuffing--
			}
		}
		afLen += stuffing
	}

	p, err := w.packet()
	if err != nil {
		return 0, err
	}
	p[0] = SyncByte
	p[1] = byte(pid >> 8)
	if start {
		p[1] |= 0x40
	}
	p[2] = byte(pid)

	hasPayload := take > 0
	switch {
	case afLen > 0 && hasPayload:
		p[3] = afcBoth << 4
	case afLen > 0:
		p[3] = afcAdaptation << 4
	default:
		p[3] = afcPayload << 4
	}
	cc := w.cc[pid]
	if hasPayload {
		p[3] |= cc & 0x0f
		w.cc[pid] = (cc + 1) & 0x0f
	} else {
		p[3] |= (cc - 1) & 0x0f
	}

	o := 4
	if afLen > 0 {
		p[o] = byte(afLen - 1)
		o++
		if afLen >= 2 {
			flags := byte(0)
			if af.Discontinuity {
				flags |= 0x80
			}
			if af.RandomAccess {
				flags |= 0x40
			}
			if af.Priority {
				flags |= 0x20
			}
			if af.HasPCR {
				flags |= 0x10
			}
			p[o] = flags
			o++
			if af.HasPCR {
				writePCR(p[o:o+6], af.PCR)
				o += 6
			}
			for o < 4+afLen {
				p[o] = 0xff
				o++
			}
		}
	}
	n := copy(p[o:o+take], head)
	copy(p[o+n:o+take], tail)
	return take, nil
}

func writePCR(dst []byte, pcr27 int64) {
	base := (pcr27 / 300) & 0x1ffffffff
	ext := pcr27 % 300
	dst[0] = byte(base >> 25)
	dst[1] = byte(base >> 17)
	dst[2] = byte(base >> 9)
	dst[3] = byte(base >> 1)
	dst[4] = byte(base<<7) | 0x7e | byte(ext>>8)
	dst[5] = byte(ext)
}

func (w *Writer) WriteSection(pid uint16, section []byte) error {
	if pid > maxPID {
		return ErrInvalidPID
	}
	w.sec = append(w.sec[:0], 0x00)
	w.sec = append(w.sec, section...)
	for len(w.sec)%payloadSize != 0 {
		w.sec = append(w.sec, 0xff)
	}
	start := true
	for unit := w.sec; len(unit) > 0; unit = unit[payloadSize:] {
		if _, err := w.writePacketParts(pid, start, Adaptation{}, unit[:payloadSize], nil); err != nil {
			return err
		}
		start = false
	}
	return nil
}
