// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sort"
	"time"

	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/timeline"
	"mmt2ts/internal/tlv"
)

// mmtStream は 1 アセットぶんの時刻計算。remux/stream.go の auTimes と同じ式。
type mmtStream struct {
	packetID  uint16
	assetType string
	video     bool
	audio     bool

	timescale        uint32
	ptsOffsetType    byte
	defaultPTSOffset uint16
	times            map[uint32]uint64
	extended         map[uint32]signaling.ExtendedEntry

	curSeq   uint32
	haveSeq  bool
	auIndex  uint32
	firstAU  []byte
	fragment []byte
	auSize   series
	pending  int
	lastPTS  int64
	havePTS  bool
	count    int
	ptsDelta series
}

func newMMTStream(pid uint16) *mmtStream {
	return &mmtStream{
		packetID: pid,
		times:    map[uint32]uint64{},
		extended: map[uint32]signaling.ExtendedEntry{},
	}
}

func (s *mmtStream) apply(a *signaling.Asset) {
	s.assetType = a.Type
	switch a.Type {
	case "hev1", "hvc1":
		s.video = true
	case "mp4a":
		s.audio = true
	}
	for _, t := range a.MPUTimestamps {
		s.times[t.Sequence] = t.NTP
	}
	if e := a.Extended; e != nil && !e.Invalid {
		if e.HasTimescale {
			s.timescale = e.Timescale
		}
		s.ptsOffsetType = e.PTSOffsetType
		s.defaultPTSOffset = e.DefaultPTSOffset
		for _, entry := range e.Entries {
			s.extended[entry.Sequence] = entry
		}
	}
}

func (s *mmtStream) auTimes(base *timeline.Base, mpuSeq, sample uint32) (int64, bool) {
	ntp, ok1 := s.times[mpuSeq]
	entry, ok2 := s.extended[mpuSeq]
	if !ok1 || !ok2 || s.timescale == 0 {
		return 0, false
	}
	if sample == 0 || int(sample) > len(entry.AUs) {
		return 0, false
	}
	index := int(sample) - 1
	offset := -int64(entry.DecodingTimeOffset)
	if s.ptsOffsetType == 2 {
		for _, au := range entry.AUs[:index] {
			offset += int64(au.PTSOffset)
		}
	} else {
		offset += int64(index) * int64(s.defaultPTSOffset)
	}
	base.Set(ntp)
	origin := base.To90k(ntp)
	return origin + timeline.TicksTo90k(offset+int64(entry.AUs[index].DTSPTSOffset), s.timescale), true
}

type mmtFlow struct {
	streams map[uint16]*mmtStream
	base    timeline.Base
	skew    series
	video   *mmtStream
	audio   *mmtStream
}

func probeMMT(r io.Reader, src string) {
	reader := tlv.NewReader(r)
	sig := signaling.NewReassembler()
	flow := &mmtFlow{streams: map[uint16]*mmtStream{}}
	units := make([]mmtp.DataUnit, 0, 64)
	total := 0

	var nPkt, nDat, nMMTP, nSig, nMPU, nMPT, nAU int
	var nNTP int
	var ntpGap, ntpVsLocal series
	var lastNTP uint64
	var lastNTPLocal time.Time
	var firstNTP uint64
	var firstNTPLocal time.Time
	var lead series
	var nScram, nNoStream, nMedia, nParseErr, nUntimed, nNoTime int
	var fragTypes [16]int
	for {
		pkt, err := reader.Next()
		if err != nil {
			break
		}
		nPkt++
		total += len(pkt.Payload)
		datagram, ok := reader.Datagram(pkt)
		if !ok {
			continue
		}
		nDat++
		if datagram.IsNTP() && len(datagram.Payload) >= 48 {
			now := time.Now()
			ntp := binary.BigEndian.Uint64(datagram.Payload[40:48])
			nNTP++
			if lastNTP != 0 {
				ntpGap.add(timeline.NTPDeltaSeconds(ntp, lastNTP) * 1000)
			} else {
				firstNTP, firstNTPLocal = ntp, now
			}
			lastNTP, lastNTPLocal = ntp, now
			flow.base.Set(ntp)
			continue
		}
		m, err := mmtp.Parse(datagram.Payload)
		if err != nil {
			continue
		}
		nMMTP++
		switch m.PayloadType {
		case mmtp.PayloadTypeSignaling:
			nSig++
			for _, msg := range sig.Push(m.PacketID, m.Payload) {
				for _, t := range msg.Tables {
					mpt := t.MPT
					if mpt == nil {
						continue
					}
					nMPT++
					for i := range mpt.Assets {
						a := &mpt.Assets[i]
						pid, ok := a.LocalPacketID()
						if !ok {
							continue
						}
						s := flow.streams[pid]
						if s == nil {
							s = newMMTStream(pid)
							flow.streams[pid] = s
						}
						s.apply(a)
						if s.video && flow.video == nil {
							flow.video = s
						}
						if s.audio && flow.audio == nil {
							flow.audio = s
						}
					}
				}
			}
		case mmtp.PayloadTypeMPU:
			nMPU++
			if m.Scrambled {
				nScram++
			}
			s := flow.streams[m.PacketID]
			if s == nil || (!s.video && !s.audio) {
				nNoStream++
				continue
			}
			nMedia++
			mpu, err := mmtp.ParseMPU(m.Payload, units)
			if err != nil {
				nParseErr++
				continue
			}
			if !mpu.Timed {
				nUntimed++
				continue
			}
			fragTypes[mpu.FragmentType]++
			// 完結した AU の先頭断片だけを数える (FragmentType 0 = 完全, 1 = 先頭)
			if mpu.FragmentType != 2 {
				continue
			}
			if !s.haveSeq || s.curSeq != mpu.MPUSequence {
				s.curSeq, s.haveSeq, s.auIndex = mpu.MPUSequence, true, 0
			}
			for _, u := range mpu.Units {
				// 完結した AU だけ数える。集約は 1 ユニット 1 AU、
				// 断片化は最後の断片で 1 AU。
				if mpu.Aggregation {
					// 集約された各ユニットが 1 AU
				} else if mpu.Fragmentation != 0 && mpu.Fragmentation != 3 {
					if s.audio {
						if mpu.Fragmentation == 1 {
							s.pending = len(u.Data)
							s.fragment = append(s.fragment[:0], u.Data...)
						} else {
							s.pending += len(u.Data)
							s.fragment = append(s.fragment, u.Data...)
						}
					}
					continue
				}
				if s.audio && s.firstAU == nil && len(u.Data) > 0 {
					// 断片化していたら、先頭からの断片をつないだものが AU。
					if mpu.Fragmentation == 3 {
						s.firstAU = append(append([]byte(nil), s.fragment...), u.Data...)
					} else {
						s.firstAU = append([]byte(nil), u.Data...)
					}
				}
				if s.audio {
					switch mpu.Fragmentation {
					case 0:
						s.auSize.add(float64(len(u.Data)))
					case 1:
						s.pending = len(u.Data)
					case 2:
						s.pending += len(u.Data)
					case 3:
						s.auSize.add(float64(s.pending + len(u.Data)))
						s.pending = 0
					}
				}
				s.auIndex++
				pts, ok := s.auTimes(&flow.base, mpu.MPUSequence, s.auIndex)
				if !ok {
					nNoTime++
					continue
				}
				nAU++
				s.count++
				if lastNTP != 0 {
					lead.add(float64(wrapDiff(pts, flow.base.To90k(lastNTP))) / hz * 1000)
				}
				if s.havePTS {
					d := float64(wrapDiff(pts, s.lastPTS)) / hz * 1000
					if math.Abs(d) < 5000 {
						s.ptsDelta.add(d)
					}
				}
				s.lastPTS, s.havePTS = pts, true
				if flow.video != nil && flow.audio != nil && flow.video.havePTS && flow.audio.havePTS {
					ms := float64(wrapDiff(flow.video.lastPTS, flow.audio.lastPTS)) / hz * 1000
					if math.Abs(ms) < 10000 {
						flow.skew.add(ms)
					}
				}
			}
		}
	}

	fmt.Printf("%s  %.1f MiB  TLV=%d MMTP=%d MPT=%d AU=%d (時刻不明 %d)\n",
		src, float64(total)/(1<<20), nPkt, nMMTP, nMPT, nAU, nNoTime)
	_ = nDat
	_ = nSig
	_ = nMPU
	_ = nScram
	_ = nNoStream
	_ = nMedia
	_ = nParseErr
	_ = nUntimed
	_ = fragTypes
	pids := make([]int, 0, len(flow.streams))
	for p := range flow.streams {
		pids = append(pids, int(p))
	}
	sort.Ints(pids)
	for _, p := range pids {
		s := flow.streams[uint16(p)]
		if s.count == 0 {
			continue
		}
		kind := s.assetType
		fmt.Printf("  asset packet_id=0x%04x type=%-5s AU=%-5d timescale=%-6d ptsOffsetType=%d  PTSdelta ms p1=%s p50=%s p99=%s\n",
			p, kind, s.count, s.timescale, s.ptsOffsetType,
			f(s.ptsDelta.pct(1)), f(s.ptsDelta.med()), f(s.ptsDelta.pct(99)))
		if s.firstAU != nil {
			fmt.Printf("      %s\n", audioConfig(s.firstAU))
			fmt.Printf("      AUサイズ p50=%.0f B  最大=%.0f B  概算ビットレート=%.0f kbps\n",
				s.auSize.med(), s.auSize.max(), s.auSize.med()*8/0.021333/1000)
		}
	}
	if nNTP > 1 {
		streamSec := timeline.NTPDeltaSeconds(lastNTP, firstNTP)
		localSec := lastNTPLocal.Sub(firstNTPLocal).Seconds()
		ppm := math.NaN()
		if localSec > 1 {
			ppm = (streamSec/localSec - 1) * 1e6
		}
		fmt.Printf("  NTP  packets=%d  間隔 ms p50=%s min=%s max=%s  観測長=%.1fs  局所時計との差=%.0f ppm\n",
			nNTP, f(ntpGap.med()), f(ntpGap.min()), f(ntpGap.max()), streamSec, ppm)
		fmt.Printf("  提示時刻 - 直近NTP ms  p1=%s p50=%s p99=%s\n",
			f(lead.pct(1)), f(lead.med()), f(lead.pct(99)))
		_ = ntpVsLocal
	}
	fmt.Printf("  skew (videoPTS - audioPTS, 伝送順) ms  min=%s p1=%s p50=%s p99=%s max=%s   n=%d\n",
		f(flow.skew.min()), f(flow.skew.pct(1)), f(flow.skew.med()),
		f(flow.skew.pct(99)), f(flow.skew.max()), flow.skew.n())
}
