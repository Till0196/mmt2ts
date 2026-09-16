// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// trace は分離器のトレースを吐く。形式は parity/TRACE.md にある。
//
// 出すのは実装を照合するための行であって、人が読むための要約ではない。
// 浮動小数も壁時計も出さず、並べるものは必ず整列してから出す。
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/tsdemux"
)

func main() {
	kind := flag.String("kind", "ts", "ts か tlv")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: trace -kind ts|tlv <file>")
		os.Exit(2)
	}
	file, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer file.Close()

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	switch *kind {
	case "ts":
		traceTS(out, file)
	case "tlv":
		traceTLV(out, file)
	default:
		fmt.Fprintf(os.Stderr, "知らない種別 %q\n", *kind)
		os.Exit(2)
	}
}

type counters struct {
	packets   uint64
	cc        uint64
	scrambled uint64
	pes       uint64
	sections  uint64
}

func traceTS(out *bufio.Writer, file io.Reader) {
	fmt.Fprintln(out, "# ts")

	var count counters
	perPID := map[uint16]uint64{}
	lastPAT := ""
	lastPMT := map[uint16]string{}
	// PMT が申告した PID だけを出す。どのPIDが何かを知らないまま
	// 組み立てたものまで並べると、実装ごとに違いが出やすい。
	declared := map[uint16]bool{}

	d := tsdemux.New()
	d.Handlers.OnPAT = func(p tsdemux.PAT) {
		programs := append([]tsdemux.Program(nil), p.Programs...)
		sort.Slice(programs, func(i, j int) bool { return programs[i].Number < programs[j].Number })
		line := fmt.Sprintf("pat network=0x%04x", p.NetworkPID)
		for _, program := range programs {
			line += fmt.Sprintf(" program=%d/0x%04x", program.Number, program.PID)
		}
		if line != lastPAT {
			fmt.Fprintln(out, line)
			lastPAT = line
		}
	}
	d.Handlers.OnPMT = func(m tsdemux.PMT) {
		streams := append([]tsdemux.StreamInfo(nil), m.Streams...)
		sort.Slice(streams, func(i, j int) bool { return streams[i].PID < streams[j].PID })
		line := fmt.Sprintf("pmt program=%d pcr=0x%04x", m.ProgramNumber, m.PCRPID)
		for _, stream := range streams {
			line += fmt.Sprintf(" es=0x%04x/0x%02x", stream.PID, stream.StreamType)
			declared[stream.PID] = true
		}
		if lastPMT[m.ProgramNumber] != line {
			fmt.Fprintln(out, line)
			lastPMT[m.ProgramNumber] = line
		}
	}
	d.Handlers.OnSection = func(tsdemux.Section) { count.sections++ }
	d.Handlers.OnPES = func(p tsdemux.PES) {
		if !declared[p.PID] {
			return
		}
		count.pes++
		perPID[p.PID]++
		rap := 0
		if p.RandomAccess {
			rap = 1
		}
		fmt.Fprintf(out, "pes pid=0x%04x n=%d pts=%s dts=%s size=%d rap=%d\n",
			p.PID, perPID[p.PID], stamp(p.HasPTS, p.PTS), stamp(p.HasDTS, p.DTS),
			len(p.Payload), rap)
	}

	packet := make([]byte, mpegts.PacketSize)
	reader := bufio.NewReaderSize(file, 1<<20)
	for {
		if _, err := io.ReadFull(reader, packet); err != nil {
			break
		}
		if packet[0] != 0x47 {
			// 同期を取り直す。読んだ分の中に同期バイトがあればそこから、
			// なければ1バイトずつ進める。
			if i := bytes.IndexByte(packet[1:], 0x47); i >= 0 {
				n := copy(packet, packet[1+i:])
				if _, err := io.ReadFull(reader, packet[n:]); err != nil {
					goto done
				}
			} else {
				for {
					b, err := reader.ReadByte()
					if err != nil {
						goto done
					}
					if b == 0x47 {
						packet[0] = b
						if _, err := io.ReadFull(reader, packet[1:]); err != nil {
							goto done
						}
						break
					}
				}
			}
		}
		count.packets++
		if packet[3]&0xc0 != 0 {
			count.scrambled++
		}
		d.Push(packet)
	}
done:
	d.Flush()
	for _, lost := range d.Lost {
		count.cc += lost
	}
	fmt.Fprintf(out, "end packets=%d cc=%d scrambled=%d pes=%d sections=%d\n",
		count.packets, count.cc, count.scrambled, count.pes, count.sections)
}

func stamp(present bool, value int64) string {
	if !present {
		return "-"
	}
	return fmt.Sprintf("%d", value)
}

var _ = binary.BigEndian
