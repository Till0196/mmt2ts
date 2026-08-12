// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"encoding/binary"

	"mmt2ts/internal/codec"
	"mmt2ts/internal/mpu"
)

type accessUnit struct {
	MPUSequence uint32
	Index       uint32
	Data        []byte
	RAP         bool
}

type auBuilder struct {
	kind Kind

	mpuSeq  uint32
	haveMPU bool
	trusted bool
	index   uint32

	data    []byte
	open    bool
	rap     bool
	pending accessUnit

	mpuEnd func(seq uint32, count uint32, trusted bool)

	unitsBeforeStart uint64
	unitsUntrusted   uint64
	lostAUs          uint64
	droppedAtEnd     uint64
	auPerMPU         uint32
}

func newAUBuilder(kind Kind) *auBuilder { return &auBuilder{kind: kind} }

func (b *auBuilder) push(u mpu.Unit, emit func(accessUnit) error) error {
	if u.Loss {
		if b.open {
			b.lostAUs++
		}
		b.open = false
		b.trusted = false
		return nil
	}
	if !b.haveMPU || u.MPUSequence != b.mpuSeq {
		if err := b.flush(emit); err != nil {
			return err
		}
		if b.haveMPU && b.mpuEnd != nil {
			b.mpuEnd(b.mpuSeq, b.auPerMPU, b.trusted)
		}
		b.trusted = b.haveMPU
		b.mpuSeq, b.haveMPU = u.MPUSequence, true
		b.index = 0
		b.auPerMPU = 0
	}
	if !b.trusted {
		b.unitsUntrusted++
		return nil
	}
	switch b.kind {
	case KindVideo:
		if isAccessUnitDelimiter(u.Data) {
			if err := b.flush(emit); err != nil {
				return err
			}
			b.start(u.RAP)
		}
		if !b.open {
			b.unitsBeforeStart++
			return nil
		}
		b.data = append(b.data, u.Data...)
		b.rap = b.rap || u.RAP
	case KindAudio:
		if err := b.flush(emit); err != nil {
			return err
		}
		b.start(u.RAP)
		b.data = append(b.data, u.Data...)
	}
	return nil
}

func (b *auBuilder) start(rap bool) {
	b.index++
	b.auPerMPU++
	b.open = true
	b.rap = rap
	b.data = b.data[:0]
}

func (b *auBuilder) finish() {
	if b.open {
		b.droppedAtEnd++
		b.open = false
	}
	if b.haveMPU && b.mpuEnd != nil {
		b.mpuEnd(b.mpuSeq, b.auPerMPU, b.trusted)
		b.haveMPU = false
	}
}

func (b *auBuilder) flush(emit func(accessUnit) error) error {
	if !b.open || len(b.data) == 0 {
		b.open = false
		return nil
	}
	b.open = false
	return emit(accessUnit{
		MPUSequence: b.mpuSeq,
		Index:       b.index,
		Data:        b.data,
		RAP:         b.rap,
	})
}

func isAccessUnitDelimiter(unit []byte) bool {
	if len(unit) < 6 {
		return false
	}
	if int(binary.BigEndian.Uint32(unit[:4])) < 2 {
		return false
	}
	return (unit[4]>>1)&0x3f == codec.NALAUD
}
