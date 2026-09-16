// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/timeline"
	"mmt2ts/internal/tlv"
)

// asset は1つのアセットの、時刻を出すのに要る素性。
type asset struct {
	packetID   uint16
	kind       string
	timescale  uint32
	offsetKind byte
	defaultPTS uint16
	times      map[uint32]uint64
	extended   map[uint32]signaling.ExtendedEntry
	video      bool

	// MPU の境界ごとに数え直す。放送は sample_number を 0 のままにしてくる。
	current uint32
	haveMPU bool
	// 最初の MPU は途中から拾った可能性があるので、番号を信じない。
	trusted bool
	index   uint32

	// 断片化したデータユニットの、ここまでの中身。
	fragment []byte

	// 組み立て中のアクセスユニット。
	open bool
	size int
	rap  bool
}

// unit はデータユニットを1つ食わせる。映像はアクセスユニット区切りで切り、
// 音声は1データユニットが1アクセスユニット。
func (a *asset) unit(data []byte, rap bool, emit func(index uint32, size int, rap bool)) {
	if !a.trusted {
		return
	}
	if a.video {
		if isAUD(data) {
			a.flush(emit)
			a.start(rap)
		}
		if !a.open {
			return
		}
		a.size += len(data)
		a.rap = a.rap || rap
		return
	}
	a.flush(emit)
	a.start(rap)
	a.size += len(data)
}

func (a *asset) start(rap bool) {
	a.index++
	a.open, a.size, a.rap = true, 0, rap
}

func (a *asset) flush(emit func(index uint32, size int, rap bool)) {
	if !a.open || a.size == 0 {
		a.open = false
		return
	}
	emit(a.index, a.size, a.rap)
	a.open = false
}

// isAUD は HEVC のアクセスユニット区切りかどうか。データユニットは
// 4バイトの長さが前に付く。
func isAUD(unit []byte) bool {
	if len(unit) < 6 || binary.BigEndian.Uint32(unit[:4]) < 2 {
		return false
	}
	return (unit[4]>>1)&0x3f == 35
}

func traceTLV(out *bufio.Writer, file io.Reader) {
	fmt.Fprintln(out, "# tlv")

	reader := tlv.NewReader(file)
	assembler := signaling.NewReassembler()
	assets := map[uint16]*asset{}
	units := make([]mmtp.DataUnit, 0, 64)
	var base timeline.Base
	var ntpCount, tlvCount, mmtpCount, nullCount, mpuCount, auCount uint64
	emitter := func(holder *asset, sequence uint32) func(index uint32, size int, rap bool) {
		return func(index uint32, size int, rap bool) {
			dts, pts, ok := holder.times90k(&base, sequence, index)
			if !ok {
				return
			}
			auCount++
			flag := 0
			if rap {
				flag = 1
			}
			fmt.Fprintf(out, "au pid=0x%04x mpu=%d idx=%d dts=%d pts=%d size=%d rap=%d\n",
				holder.packetID, sequence, index, dts, pts, size, flag)
		}
	}
	lastMPT := ""

	for {
		packet, err := reader.Next()
		if err != nil {
			break
		}
		tlvCount++
		datagram, ok := reader.Datagram(packet)
		if !ok {
			continue
		}
		if datagram.IsNTP() && len(datagram.Payload) >= 48 {
			ntpCount++
			value := binary.BigEndian.Uint64(datagram.Payload[40:48])
			base.Set(value)
			fmt.Fprintf(out, "ntp n=%d value=0x%016x\n", ntpCount, value)
			continue
		}
		message, err := mmtp.Parse(datagram.Payload)
		if err != nil {
			continue
		}
		mmtpCount++

		switch message.PayloadType {
		case mmtp.PayloadTypeSignaling:
			for _, entry := range assembler.Push(message.PacketID, message.Payload) {
				for _, table := range entry.Tables {
					if table.MPT == nil {
						continue
					}
					line := describeMPT(table.MPT, assets)
					if line != lastMPT {
						fmt.Fprintln(out, line)
						lastMPT = line
					}
				}
			}
		case mmtp.PayloadTypeMPU:
			mpuCount++
			holder := assets[message.PacketID]
			if holder == nil {
				continue
			}
			payload, err := mmtp.ParseMPU(message.Payload, units)
			if err != nil || !payload.Timed || payload.FragmentType != 2 {
				continue
			}
			if !holder.haveMPU || holder.current != payload.MPUSequence {
				// 前の MPU の最後の AU は、次の MPU が始まって初めて閉じる。
				holder.flush(emitter(holder, holder.current))
				// 2つめ以降の MPU なら、先頭から見えている。
				holder.trusted = holder.haveMPU
				holder.current, holder.haveMPU = payload.MPUSequence, true
				holder.index, holder.fragment = 0, nil
			}
			emit := emitter(holder, payload.MPUSequence)
			for _, unit := range payload.Units {
				data := unit.Data
				if !payload.Aggregation {
					switch payload.Fragmentation {
					case 1:
						holder.fragment = append(holder.fragment[:0], data...)
						continue
					case 2:
						holder.fragment = append(holder.fragment, data...)
						continue
					case 3:
						holder.fragment = append(holder.fragment, data...)
						data = holder.fragment
					}
				}
				holder.unit(data, message.RAP, emit)
			}
		}
	}
	for _, holder := range assets {
		holder.flush(emitter(holder, holder.current))
	}
	nullCount = reader.Stats().NullPackets
	fmt.Fprintf(out, "end tlv=%d mmtp=%d null=%d mpu=%d au=%d\n",
		tlvCount, mmtpCount, nullCount, mpuCount, auCount)
}

func describeMPT(mpt *signaling.MPT, assets map[uint16]*asset) string {
	type row struct {
		packetID uint16
		kind     string
	}
	var rows []row
	for i := range mpt.Assets {
		entry := &mpt.Assets[i]
		packetID, ok := entry.LocalPacketID()
		if !ok {
			continue
		}
		holder := assets[packetID]
		if holder == nil {
			holder = &asset{
				packetID: packetID,
				times:    map[uint32]uint64{},
				extended: map[uint32]signaling.ExtendedEntry{},
			}
			assets[packetID] = holder
		}
		holder.kind = entry.Type
		holder.video = entry.Type == "hev1" || entry.Type == "hvc1"
		for _, stamp := range entry.MPUTimestamps {
			holder.times[stamp.Sequence] = stamp.NTP
		}
		if e := entry.Extended; e != nil && !e.Invalid {
			if e.HasTimescale {
				holder.timescale = e.Timescale
			}
			holder.offsetKind = e.PTSOffsetType
			holder.defaultPTS = e.DefaultPTSOffset
			for _, item := range e.Entries {
				holder.extended[item.Sequence] = item
			}
		}
		rows = append(rows, row{packetID, entry.Type})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].packetID < rows[j].packetID })
	line := fmt.Sprintf("mpt service=%d", mpt.ServiceID())
	for _, r := range rows {
		line += fmt.Sprintf(" asset=%s/0x%04x", r.kind, r.packetID)
	}
	return line
}

// times90k は remux/stream.go の auTimes と同じ式。
func (a *asset) times90k(base *timeline.Base, sequence, sample uint32) (int64, int64, bool) {
	ntp, haveNTP := a.times[sequence]
	entry, haveExtended := a.extended[sequence]
	if !haveNTP || !haveExtended || a.timescale == 0 {
		return 0, 0, false
	}
	if sample == 0 || int(sample) > len(entry.AUs) {
		return 0, 0, false
	}
	index := int(sample) - 1
	offset := -int64(entry.DecodingTimeOffset)
	if a.offsetKind == 2 {
		for _, au := range entry.AUs[:index] {
			offset += int64(au.PTSOffset)
		}
	} else {
		offset += int64(index) * int64(a.defaultPTS)
	}
	base.Set(ntp)
	origin := base.To90k(ntp)
	dts := origin + timeline.TicksTo90k(offset, a.timescale)
	pts := origin + timeline.TicksTo90k(offset+int64(entry.AUs[index].DTSPTSOffset), a.timescale)
	return dts, pts, true
}
