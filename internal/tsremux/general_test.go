// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"mmt2ts/internal/arib"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/si"
	"mmt2ts/internal/tsdemux"
	"mmt2ts/internal/tsremux/siup"
)

func TestBuildGeneralAMTMatchesBroadcast(t *testing.T) {
	const recorded = "fef0310000cf0000007f00ddfc22" +
		"2401dbc010090000000000000000000180" +
		"ff3e00000000000000000000a000100080" +
		"6fb35562"
	want, err := hex.DecodeString(recorded)
	if err != nil {
		t.Fatal(err)
	}
	got := buildGeneralAMT(0x000b, []*generalService{{number: 0x00dd, flow: generalFlowFor(0)}})
	if len(got) != len(want) {
		t.Fatalf("length %d, broadcast section is %d", len(got), len(want))
	}
	if got[5] != 0xc1 {
		t.Errorf("version byte %#02x, want %#02x", got[5], 0xc1)
	}
	want[5] = got[5]
	body := want[:len(want)-4]
	binary.BigEndian.PutUint32(want[len(want)-4:], mpegts.CRC32(body))
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("AMT\n got %s\nwant %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func eitPFSection(service uint16, sectionNumber byte, eventID uint16, start [5]byte, duration [3]byte) tsdemux.Section {
	data := []byte{mpegts.TableIDEITPFActual, 0, 0}
	data = binary.BigEndian.AppendUint16(data, service)
	data = append(data, 0xc1, sectionNumber, 1)
	data = binary.BigEndian.AppendUint16(data, service)
	data = binary.BigEndian.AppendUint16(data, service)
	data = append(data, 1, mpegts.TableIDEITPFActual)
	data = binary.BigEndian.AppendUint16(data, eventID)
	data = append(data, start[:]...)
	data = append(data, duration[:]...)
	data = binary.BigEndian.AppendUint16(data, 0x8000)
	data = append(data, 0, 0, 0, 0)
	return tsdemux.Section{PID: mpegts.PIDEIT, TableID: mpegts.TableIDEITPFActual, Data: data}
}

func TestBuildGeneralMHEITSendsPresentAndFollowing(t *testing.T) {
	const service = 0x0191
	following := eitPFSection(service, 1, 0x6ba8, [5]byte{0xef, 0x4e, 0x17, 0x00, 0x00}, [3]byte{0x01, 0x00, 0x00})

	for _, tc := range []struct {
		name     string
		sections []tsdemux.Section
	}{
		{"following only", []tsdemux.Section{following}},
		{"no EIT at all", nil},
		{"both halves", []tsdemux.Section{
			eitPFSection(service, 0, 0x6ba7, [5]byte{0xef, 0x4e, 0x16, 0x00, 0x00}, [3]byte{0x01, 0x00, 0x00}),
			following,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := buildGeneralMHEIT(service, tc.sections, generalNTPBase, siup.New())
			if len(out) != 2 {
				t.Fatalf("got %d sections, want present and following", len(out))
			}
			var ids [2]uint16
			var starts [2]int
			for i, s := range out {
				if s[0] != si.TableIDMHEITPF {
					t.Errorf("section %d table_id %#02x", i, s[0])
				}
				if s[6] != byte(i) || s[7] != 1 {
					t.Errorf("section %d numbering section_number=%d last_section_number=%d", i, s[6], s[7])
				}
				ids[i] = binary.BigEndian.Uint16(s[14:16])
				starts[i] = int(s[18])>>4*10 + int(s[18]&0x0f)
			}
			if ids[0] == ids[1] {
				t.Errorf("both sections carry event_id %#04x; the second slot stays empty", ids[0])
			}
			if starts[1] <= starts[0] {
				t.Errorf("following starts at hour %d, present at %d", starts[1], starts[0])
			}
		})
	}
}

func eitSectionWithName(tableID byte, service uint16, sectionNumber byte, eventID uint16,
	start [5]byte, duration [3]byte, name string) tsdemux.Section {
	short := append([]byte("jpn"), byte(len(name)))
	short = append(short, name...)
	short = append(short, 0)
	desc := append([]byte{0x4d, byte(len(short))}, short...)

	data := []byte{tableID, 0, 0}
	data = binary.BigEndian.AppendUint16(data, service)
	data = append(data, 0xc1, sectionNumber, 1)
	data = binary.BigEndian.AppendUint16(data, service)
	data = binary.BigEndian.AppendUint16(data, service)
	data = append(data, 1, tableID)
	data = binary.BigEndian.AppendUint16(data, eventID)
	data = append(data, start[:]...)
	data = append(data, duration[:]...)
	data = binary.BigEndian.AppendUint16(data, 0x8000|uint16(len(desc)))
	data = append(data, desc...)
	data = append(data, 0, 0, 0, 0)
	return tsdemux.Section{PID: mpegts.PIDEIT, TableID: tableID, Data: data}
}

func sdtSection(service uint16, name string) tsdemux.Section {
	svc := append([]byte{0x48, 0, 0xa5, 0}, byte(len(name)))
	svc = append(svc, name...)
	svc[1] = byte(len(svc) - 2)

	data := []byte{mpegts.TableIDSDTActual, 0, 0}
	data = binary.BigEndian.AppendUint16(data, service)
	data = append(data, 0xc1, 0, 0)
	data = binary.BigEndian.AppendUint16(data, service)
	data = append(data, 0xff)
	data = binary.BigEndian.AppendUint16(data, service)
	data = append(data, 0)
	data = binary.BigEndian.AppendUint16(data, 0x8000|uint16(len(svc)))
	data = append(data, svc...)
	data = append(data, 0, 0, 0, 0)
	return tsdemux.Section{PID: mpegts.PIDSDT, TableID: mpegts.TableIDSDTActual, Data: data}
}

func TestGeneralEITEventsNameFallback(t *testing.T) {
	const service = 0x0191
	var now [5]byte
	copy(now[:], buildGeneralMHTOT(generalNTPBase)[3:8])
	hour := now
	hour[3], hour[4] = 0, 0

	scheduled := eitSectionWithName(mpegts.TableIDEITScheduleFirst, service, 40, 0x1234,
		hour, [3]byte{0x02, 0x00, 0x00}, "SCHEDULED")
	sdt := sdtSection(service, "SERVICE")

	wantScheduled := arib.DecodeString([]byte("SCHEDULED")).Text
	wantService := arib.DecodeString([]byte("SERVICE")).Text

	t.Run("EIT schedule supplies the present event", func(t *testing.T) {
		present, _ := generalEITEvents(service, []tsdemux.Section{scheduled, sdt}, generalNTPBase, siup.New())
		if present.name != wantScheduled || present.eventID != 0x1234 {
			t.Errorf("present = %q/%#04x, want %q/0x1234 from EIT schedule", present.name, present.eventID, wantScheduled)
		}
	})

	t.Run("SDT service name when no EIT describes it", func(t *testing.T) {
		present, following := generalEITEvents(service, []tsdemux.Section{sdt}, generalNTPBase, siup.New())
		if present.name != wantService || following.name != wantService {
			t.Errorf("names %q/%q, want the SDT service name %q", present.name, following.name, wantService)
		}
	})

	t.Run("placeholder only with no SI at all", func(t *testing.T) {
		present, _ := generalEITEvents(service, nil, generalNTPBase, siup.New())
		if present.name != "番組" {
			t.Errorf("present name %q, want the placeholder", present.name)
		}
	})
}
