// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package codec

import (
	"encoding/binary"
	"errors"
)

const (
	NALBLAWithLP = 16
	NALIRAPLast  = 23
	NALVPS       = 32
	NALSPS       = 33
	NALPPS       = 34
	NALAUD       = 35
)

var (
	ErrNALLength   = errors.New("codec: NAL length prefix does not match payload")
	ErrEmptySample = errors.New("codec: empty sample")
)

type HEVCSample struct {
	NALCount        int
	HasAUD          bool
	HasIRAP         bool
	HasParameterSet bool
}

func HEVCAnnexB(dst, sample []byte) ([]byte, HEVCSample, error) {
	var info HEVCSample
	if len(sample) == 0 {
		return dst, info, ErrEmptySample
	}
	for p := 0; p < len(sample); {
		if len(sample)-p < 4 {
			return dst, info, ErrNALLength
		}
		length := int(binary.BigEndian.Uint32(sample[p : p+4]))
		p += 4
		if length < 2 || length > len(sample)-p {
			return dst, info, ErrNALLength
		}
		nal := sample[p : p+length]
		p += length
		switch t := (nal[0] >> 1) & 0x3f; {
		case t == NALAUD:
			info.HasAUD = true
		case t >= NALBLAWithLP && t <= NALIRAPLast:
			info.HasIRAP = true
		case t == NALVPS || t == NALSPS || t == NALPPS:
			info.HasParameterSet = true
		}
		dst = append(dst, 0x00, 0x00, 0x00, 0x01)
		dst = append(dst, nal...)
		info.NALCount++
	}
	return dst, info, nil
}
