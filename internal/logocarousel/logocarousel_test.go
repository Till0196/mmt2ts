// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package logocarousel

import (
	"encoding/binary"
	"testing"
)

func dsmccSection(tableID byte, messageID uint16, id uint32, payload []byte) []byte {
	s := []byte{tableID, 0, 0, 0, 0, 0xc1, 0, 0}
	s = append(s, protocolDiscriminator, typeDownload)
	s = binary.BigEndian.AppendUint16(s, messageID)
	s = binary.BigEndian.AppendUint32(s, id)
	s = append(s, 0xff, 0x00)
	s = binary.BigEndian.AppendUint16(s, uint16(len(payload)))
	s = append(s, payload...)
	return append(s, 0, 0, 0, 0)
}

func logoModule(logoType byte, logos []Logo) []byte {
	out := []byte{logoType}
	out = binary.BigEndian.AppendUint16(out, uint16(len(logos)))
	for _, l := range logos {
		out = binary.BigEndian.AppendUint16(out, 0xfe00|l.ID&0x01ff)
		out = append(out, byte(len(l.Services)))
		for _, s := range l.Services {
			out = binary.BigEndian.AppendUint16(out, s.NetworkID)
			out = binary.BigEndian.AppendUint16(out, s.TransportStreamID)
			out = binary.BigEndian.AppendUint16(out, s.ServiceID)
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(l.Data)))
		out = append(out, l.Data...)
	}
	return out
}

func TestCarouselYieldsLogos(t *testing.T) {
	want := []Logo{
		{ID: 0x0c8, Services: []Service{{0xfff7, 0x0210, 0x0191}}, Data: make([]byte, 300)},
		{ID: 0x1e7, Services: []Service{{0xfff7, 0x0209, 0x0212}, {0xfff7, 0x0211, 0x01b1}}, Data: make([]byte, 200)},
	}
	for i := range want {
		for j := range want[i].Data {
			want[i].Data[j] = byte(i*31 + j)
		}
	}
	module := logoModule(3, want)

	const blockSize = 256
	dii := binary.BigEndian.AppendUint32(nil, 0x00000000)
	dii = binary.BigEndian.AppendUint16(dii, blockSize)
	dii = append(dii, 0, 0)
	dii = append(dii, make([]byte, 8)...)
	dii = binary.BigEndian.AppendUint16(dii, 0)
	dii = binary.BigEndian.AppendUint16(dii, 1)
	dii = binary.BigEndian.AppendUint16(dii, 0x0003)
	dii = binary.BigEndian.AppendUint32(dii, uint32(len(module)))
	dii = append(dii, 0x05, 0)

	r := New()
	r.Push(0x150c, dsmccSection(tableDII, msgDII, 0x80000000, dii))
	for block := 0; block*blockSize < len(module); block++ {
		lo := block * blockSize
		hi := min(lo+blockSize, len(module))
		body := binary.BigEndian.AppendUint16(nil, 0x0003)
		body = append(body, 0x05, 0xff)
		body = binary.BigEndian.AppendUint16(body, uint16(block))
		body = append(body, module[lo:hi]...)
		r.Push(0x150c, dsmccSection(tableDDB, msgDDB, 0x00000000, body))
	}

	got := r.Logos()
	if r.Modules != 1 || r.Malformed != 0 {
		t.Fatalf("modules=%d malformed=%d", r.Modules, r.Malformed)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d logos, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Type != 3 || got[i].ID != want[i].ID {
			t.Errorf("logo %d = type %d id %#05x, want type 3 id %#05x", i, got[i].Type, got[i].ID, want[i].ID)
		}
		if len(got[i].Services) != len(want[i].Services) {
			t.Fatalf("logo %d services = %+v, want %+v", i, got[i].Services, want[i].Services)
		}
		for j := range want[i].Services {
			if got[i].Services[j] != want[i].Services[j] {
				t.Errorf("logo %d service %d = %+v, want %+v", i, j, got[i].Services[j], want[i].Services[j])
			}
		}
		if string(got[i].Data) != string(want[i].Data) {
			t.Errorf("logo %d image is %d bytes, want the %d it was given", i, len(got[i].Data), len(want[i].Data))
		}
	}

	r.Push(0x150c, dsmccSection(tableDII, msgDII, 0x80000000, dii))
	if len(r.Logos()) != len(want) {
		t.Errorf("a repeat of the carousel added logos: %d", len(r.Logos()))
	}
}
