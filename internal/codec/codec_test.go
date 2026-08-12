// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package codec

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func lengthPrefixed(nals ...[]byte) []byte {
	var out []byte
	for _, n := range nals {
		out = binary.BigEndian.AppendUint32(out, uint32(len(n)))
		out = append(out, n...)
	}
	return out
}

func TestHEVCAnnexB(t *testing.T) {
	aud := []byte{35 << 1, 0x01, 0x50}
	vps := []byte{32 << 1, 0x01, 0xaa, 0xbb}
	idr := []byte{19 << 1, 0x01, 0x11, 0x22, 0x33}
	got, info, err := HEVCAnnexB(nil, lengthPrefixed(aud, vps, idr))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 1}
	want = append(want, aud...)
	want = append(want, 0, 0, 0, 1)
	want = append(want, vps...)
	want = append(want, 0, 0, 0, 1)
	want = append(want, idr...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Annex B conversion:\n got % x\nwant % x", got, want)
	}
	if info.NALCount != 3 || !info.HasAUD || !info.HasIRAP || !info.HasParameterSet {
		t.Fatalf("sample info = %+v", info)
	}
}

func TestHEVCAnnexBRejectsBadLength(t *testing.T) {
	sample := binary.BigEndian.AppendUint32(nil, 99)
	sample = append(sample, 0x40, 0x01)
	if _, _, err := HEVCAnnexB(nil, sample); err != ErrNALLength {
		t.Fatalf("err = %v, want %v", err, ErrNALLength)
	}
	if _, _, err := HEVCAnnexB(nil, []byte{0, 0}); err != ErrNALLength {
		t.Fatalf("truncated prefix err = %v", err)
	}
	if _, _, err := HEVCAnnexB(nil, nil); err != ErrEmptySample {
		t.Fatalf("empty sample err = %v", err)
	}
}
