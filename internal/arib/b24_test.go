// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package arib

import (
	"encoding/binary"
	"testing"
)

func TestDataGroupCRCAndSize(t *testing.T) {
	body := Statement(0, nil, DataUnit(UnitStatementBody, []byte{0x0c}))
	group, ok := DataGroup(GroupStatementA, 0, 0, 0, body)
	if !ok {
		t.Fatal("data group was refused")
	}
	if size := binary.BigEndian.Uint16(group[3:5]); int(size) != len(body) {
		t.Fatalf("size field %d, body %d", size, len(body))
	}
	if CRC16(group) != 0 {
		t.Fatalf("CRC does not verify: %#04x", CRC16(group))
	}
	group[5] ^= 0xff
	if CRC16(group) == 0 {
		t.Fatal("a corrupted data group still verified")
	}
}
func TestPESPayloadRefusesOversizedHeader(t *testing.T) {
	if _, ok := PESPayload(DataIdentifierSynchronised, make([]byte, 16), nil); ok {
		t.Fatal("a 16-byte header fits a four-bit length field")
	}
	p, ok := PESPayload(DataIdentifierSynchronised, nil, []byte{1, 2})
	if !ok || p[0] != DataIdentifierSynchronised || p[1] != privateStreamID || p[2] != 0xf0 {
		t.Fatalf("payload = % x, ok = %v", p, ok)
	}
}
func TestManagementLanguageReservedBitIsOne(t *testing.T) {
	body := Management(0, nil, []LanguageEntry{{
		Tag: 0, DMF: 3, Language: "jpn", Format: 8,
	}}, nil)
	if body[2]&0x10 == 0 {
		t.Fatalf("language control byte = %#02x", body[2])
	}
}

func TestControlLengths(t *testing.T) {
	for _, c := range []struct {
		code byte
		in   []byte
		want int
	}{
		{CodeCS, []byte{CodeCS}, 1},
		{CodeAPS, []byte{CodeAPS, 0x40, 0x41}, 3},
		{CodePAPF, []byte{CodePAPF, 0x40}, 2},
		{CodeSZX, []byte{CodeSZX, 0x60}, 2},
		{CodeCOL, []byte{CodeCOL, 0x41}, 2},
		{CodeCOL, []byte{CodeCOL, 0x20, 0x41}, 3},
		{CodeCDC, []byte{CodeCDC, 0x20, 0x41}, 3},
		{CodeMSZ, []byte{CodeMSZ}, 1},
		{CodeCSI, []byte{CodeCSI, '3', '0', ';', '3', '0', CSISWF}, 7},
		{CodeCSI, []byte{CodeCSI, '1', CSIORN}, 3},
		{CodeTIME, []byte{CodeTIME, 0x20, 0x40}, 3},
		{CodeMACRO, []byte{CodeMACRO, 0x40, CodeMACRO, 0x4f}, 4},
	} {
		if got := controlLength(c.in, 0); got != c.want {
			t.Errorf("%#02x: length = %d, want %d", c.code, got, c.want)
		}
		got := DecodeString(append(append([]byte(nil), c.in...), 0x46, 0x7c))
		if got.Text != "日" {
			t.Errorf("%#02x: text after the control = %q", c.code, got.Text)
		}
	}
}
