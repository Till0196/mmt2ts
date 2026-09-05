// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"sort"

	"mmt2ts/internal/escan"
	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/tsdemux"
)

// esOut は種別 es の行を書く。
//
// format は内容が変わったときだけ出す決まりなので、ストリームごとに直前の行を覚えておく。
type esOut struct {
	out      *bufio.Writer
	streams  map[uint16]*esStream
	pictures uint64
	frames   uint64
	fields   uint64
	formats  uint64
}

type esStream struct {
	scanner *escan.Scanner
	count   uint64
	last    string
}

func newESOut(out *bufio.Writer) *esOut {
	fmt.Fprintln(out, "# es")
	return &esOut{out: out, streams: map[uint16]*esStream{}}
}

// stream は追う対象を1つ登録する。既にあるものはそのままにして、走査の状態を捨てない。
func (e *esOut) stream(pid uint16, codec escan.Codec) *esStream {
	if s := e.streams[pid]; s != nil {
		return s
	}
	s := &esStream{scanner: escan.New(codec)}
	e.streams[pid] = s
	return s
}

func (e *esOut) picture(pid uint16, s *esStream, p escan.Picture, dts, pts string) {
	f := p.Format
	line := fmt.Sprintf("format pid=0x%04x codec=%s width=%d height=%d depth=%d chroma=%d rate=%d/%d progressive=%d aspect=%d/%d",
		pid, s.scanner.Codec(), f.Width, f.Height, f.Depth, f.Chroma,
		f.RateNum, f.RateDen, f.Progressive, f.AspectNum, f.AspectDen)
	if line != s.last {
		fmt.Fprintln(e.out, line)
		s.last = line
		e.formats++
	}

	coding := byte('-')
	if p.Coding != 0 {
		coding = p.Coding
	}
	rap := 0
	if p.RAP {
		rap = 1
	}
	s.count++
	e.pictures++
	if p.Structure == escan.Frame {
		e.frames++
	} else {
		e.fields++
	}
	fmt.Fprintf(e.out, "pic pid=0x%04x n=%d dts=%s pts=%s coding=%c structure=%s tff=%d rff=%d prog=%d rap=%d size=%d\n",
		pid, s.count, dts, pts, coding, p.Structure, p.TFF, p.RFF, p.Prog, rap, p.Size)
}

func (e *esOut) end() {
	fmt.Fprintf(e.out, "end pictures=%d frames=%d fields=%d formats=%d\n",
		e.pictures, e.frames, e.fields, e.formats)
}

// traceESTS は TS から映像を全部取り出す。
//
// どの PID を追うかは PMT の stream_type だけで決める。
// 「最初の1本」のような選び方をすると、トランスポンダ丸ごとの入力で実装ごとに違う答えが出る。
func traceESTS(out *bufio.Writer, file io.Reader) {
	e := newESOut(out)

	d := tsdemux.New()
	d.Handlers.OnPMT = func(m tsdemux.PMT) {
		streams := append([]tsdemux.StreamInfo(nil), m.Streams...)
		sort.Slice(streams, func(i, j int) bool { return streams[i].PID < streams[j].PID })
		for _, stream := range streams {
			if codec, ok := escan.CodecOfStreamType(stream.StreamType); ok {
				e.stream(stream.PID, codec)
			}
		}
	}
	d.Handlers.OnPES = func(p tsdemux.PES) {
		s := e.streams[p.PID]
		if s == nil {
			return
		}
		dts, pts := stamp(p.HasDTS, p.DTS), stamp(p.HasPTS, p.PTS)
		// PES のペイロードにピクチャがちょうど1枚とは限らない。
		// 1つの PES から出た分は、どれも同じ時刻を持つものとして出す。
		for _, picture := range s.scanner.Push(p.Payload) {
			e.picture(p.PID, s, picture, dts, pts)
		}
	}

	packet := make([]byte, mpegts.PacketSize)
	reader := bufio.NewReaderSize(file, 1<<20)
	for {
		if _, err := io.ReadFull(reader, packet); err != nil {
			break
		}
		if packet[0] != 0x47 {
			// 同期を取り直す。1バイトずつ進める。
			resynced := false
			for {
				b, err := reader.ReadByte()
				if err != nil {
					break
				}
				if b == 0x47 {
					packet[0] = b
					if _, err := io.ReadFull(reader, packet[1:]); err != nil {
						break
					}
					resynced = true
					break
				}
			}
			if !resynced {
				break
			}
		}
		d.Push(packet)
	}
	// 最後まで届かなかった PES は捨てる。長さの分からないものを1枚のピクチャとして数えると、
	// 切り出した位置しだいで数が変わる。
	e.end()
}

// traceESTLV は MMT/TLV から映像を全部取り出す。
// アクセスユニットの組み立ては種別 tlv と同じものを使う。
func traceESTLV(out *bufio.Writer, file io.Reader) {
	e := newESOut(out)
	walkTLV(file, tlvHooks{
		collect: true,
		onAU: func(a *asset, _, _ uint32, dts, pts int64, size int, _ bool, nalus [][]byte) {
			codec, ok := escan.CodecOfAssetType(a.kind)
			if !ok {
				return
			}
			s := e.stream(a.packetID, codec)
			picture, ok := s.scanner.PushUnits(nalus, size)
			if !ok {
				return
			}
			e.picture(a.packetID, s, picture, fmt.Sprintf("%d", dts), fmt.Sprintf("%d", pts))
		},
	})
	e.end()
}
