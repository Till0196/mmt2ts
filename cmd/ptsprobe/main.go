// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// ptsprobe は TS の PES タイムスタンプを測る。映像と音声の PTS が伝送順で
// どれだけずれているか、音声 PTS がフレーム長からどれだけ揺れるか、
// PCR から PTS までどれだけあるか。A/V 同期の設計に必要な数値だけを出す。
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"

	"mmt2ts/internal/tsdemux"
)

const hz = 90000.0

type series struct {
	v []float64
}

func (s *series) add(x float64) { s.v = append(s.v, x) }
func (s *series) n() int        { return len(s.v) }
func (s *series) pct(p float64) float64 {
	if len(s.v) == 0 {
		return math.NaN()
	}
	c := append([]float64(nil), s.v...)
	sort.Float64s(c)
	i := int(p / 100 * float64(len(c)-1))
	return c[i]
}
func (s *series) min() float64 { return s.pct(0) }
func (s *series) max() float64 { return s.pct(100) }
func (s *series) med() float64 { return s.pct(50) }

type stream struct {
	pid        uint16
	streamType byte
	lastPTS    int64
	lastDTS    int64
	havePTS    bool
	count      int
	noPTS      int
	ptsDelta   series
	dtsDelta   series
	reorder    series // PTS - DTS
	jumps      int
}

func (s *stream) feed(p tsdemux.PES) {
	s.count++
	if !p.HasPTS {
		s.noPTS++
		return
	}
	if s.havePTS {
		d := wrapDiff(p.PTS, s.lastPTS)
		if math.Abs(float64(d)) > 5*hz {
			s.jumps++
		} else {
			s.ptsDelta.add(float64(d) / hz * 1000)
		}
	}
	if p.HasDTS {
		if s.havePTS && s.lastDTS >= 0 {
			d := wrapDiff(p.DTS, s.lastDTS)
			if math.Abs(float64(d)) <= 5*hz {
				s.dtsDelta.add(float64(d) / hz * 1000)
			}
		}
		s.reorder.add(float64(wrapDiff(p.PTS, p.DTS)) / hz * 1000)
		s.lastDTS = p.DTS
	} else {
		s.lastDTS = -1
	}
	s.lastPTS, s.havePTS = p.PTS, true
}

func wrapDiff33(a, b int64) int64 { return wrapDiff(a, b) }

func wrapDiff(a, b int64) int64 {
	d := a - b
	const mod = int64(1) << 33
	if d > mod/2 {
		d -= mod
	} else if d < -mod/2 {
		d += mod
	}
	return d
}

type program struct {
	number uint16
	pcrPID uint16
	video  *stream
	audio  *stream
	// 伝送順のずれ: PES が届くたびに、その時点で見えている
	// 直近の映像 PTS と音声 PTS の差 (video - audio) を記録する。
	skew series
	// PCR から PTS まで
	videoAhead series
	audioAhead series
	lastPCR    int64
	havePCR    bool
	pcrCount   int
	pcrGap     series
	firstPCR   int64
	firstLocal time.Time
	lastLocal  time.Time
	oneSeg     bool
}

func isVideo(t byte) bool { return t == 0x01 || t == 0x02 || t == 0x1b || t == 0x24 }
func isAudio(t byte) bool { return t == 0x03 || t == 0x04 || t == 0x0f || t == 0x11 }

func main() {
	seconds := flag.Int("t", 20, "取得する秒数")
	limit := flag.Int("bytes", 0, "取得する最大バイト数 (0 で無制限)")
	asJSON := flag.Bool("json", false, "JSON で出す")
	isMMT := flag.Bool("mmt", false, "入力を MMT/TLV として読む")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: ptsprobe [flags] <url|file>")
		os.Exit(2)
	}
	src := flag.Arg(0)

	r, err := open(src, *seconds)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer r.Close()

	if *isMMT {
		probeMMT(r, src)
		return
	}

	programs := map[uint16]*program{}
	byPID := map[uint16]*program{}
	pcrOf := map[uint16][]*program{}
	pmtSeen := map[uint16]bool{}

	d := tsdemux.New()
	d.Handlers.OnPMT = func(m tsdemux.PMT) {
		if pmtSeen[m.ProgramNumber] {
			return
		}
		pmtSeen[m.ProgramNumber] = true
		p := &program{number: m.ProgramNumber, pcrPID: m.PCRPID}
		for _, s := range m.Streams {
			switch {
			case isVideo(s.StreamType) && p.video == nil && byPID[s.PID] == nil:
				p.video = &stream{pid: s.PID, streamType: s.StreamType, lastDTS: -1}
				byPID[s.PID] = p
			case isAudio(s.StreamType) && p.audio == nil && byPID[s.PID] == nil:
				p.audio = &stream{pid: s.PID, streamType: s.StreamType, lastDTS: -1}
				byPID[s.PID] = p
			}
		}
		programs[m.ProgramNumber] = p
		pcrOf[m.PCRPID] = append(pcrOf[m.PCRPID], p)
	}
	d.Handlers.OnPES = func(p tsdemux.PES) {
		prog := byPID[p.PID]
		if prog == nil {
			return
		}
		switch {
		case prog.video != nil && prog.video.pid == p.PID:
			prog.video.feed(p)
		case prog.audio != nil && prog.audio.pid == p.PID:
			prog.audio.feed(p)
		default:
			return
		}
		if p.HasPTS && prog.havePCR {
			ms := float64(wrapDiff(p.PTS, prog.lastPCR)) / hz * 1000
			if math.Abs(ms) < 5000 {
				if prog.video != nil && prog.video.pid == p.PID {
					prog.videoAhead.add(ms)
				} else {
					prog.audioAhead.add(ms)
				}
			}
		}
		if prog.video != nil && prog.audio != nil && prog.video.havePTS && prog.audio.havePTS {
			ms := float64(wrapDiff(prog.video.lastPTS, prog.audio.lastPTS)) / hz * 1000
			if math.Abs(ms) < 10000 {
				prog.skew.add(ms)
			}
		}
	}

	buf := make([]byte, 188*1024)
	total := 0
	pkt := make([]byte, 0, 188)
	for {
		n, err := r.Read(buf)
		for i := 0; i < n; i++ {
			pkt = append(pkt, buf[i])
			if len(pkt) == 1 && pkt[0] != 0x47 {
				pkt = pkt[:0]
				continue
			}
			if len(pkt) == 188 {
				feedPCR(pkt, pcrOf)
				d.Push(pkt)
				pkt = pkt[:0]
			}
		}
		total += n
		if err != nil || (*limit > 0 && total >= *limit) {
			break
		}
	}

	report(src, total, programs, *asJSON)
}

func feedPCR(b []byte, pcrOf map[uint16][]*program) {
	pid := binary.BigEndian.Uint16(b[1:3]) & 0x1fff
	ps := pcrOf[pid]
	if len(ps) == 0 || b[3]&0x20 == 0 || b[4] == 0 || b[5]&0x10 == 0 {
		return
	}
	base := int64(b[6])<<25 | int64(b[7])<<17 | int64(b[8])<<9 | int64(b[9])<<1 | int64(b[10])>>7
	now := time.Now()
	for _, p := range ps {
		if p.havePCR {
			d := float64(wrapDiff33(base, p.lastPCR)) / 90000 * 1000
			if d > 0 && d < 1000 {
				p.pcrGap.add(d)
			}
		} else {
			p.firstPCR, p.firstLocal = base, now
		}
		p.lastPCR, p.havePCR = base, true
		p.pcrCount++
		p.lastLocal = now
	}
}

func open(src string, seconds int) (io.ReadCloser, error) {
	if u, err := url.Parse(src); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		tr := &http.Transport{}
		c := &http.Client{Transport: tr, Timeout: time.Duration(seconds+25) * time.Second}
		resp, err := c.Get(src)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %s", resp.Status)
		}
		return &timedReader{rc: resp.Body, deadline: time.Now().Add(time.Duration(seconds) * time.Second)}, nil
	}
	return os.Open(src)
}

type timedReader struct {
	rc       io.ReadCloser
	deadline time.Time
}

func (t *timedReader) Read(p []byte) (int, error) {
	if time.Now().After(t.deadline) {
		return 0, io.EOF
	}
	return t.rc.Read(p)
}
func (t *timedReader) Close() error { return t.rc.Close() }

func f(x float64) string {
	if math.IsNaN(x) {
		return "   -   "
	}
	return fmt.Sprintf("%7.1f", x)
}

func report(src string, total int, programs map[uint16]*program, asJSON bool) {
	nums := make([]int, 0, len(programs))
	for n := range programs {
		nums = append(nums, int(n))
	}
	sort.Ints(nums)
	for _, n := range nums {
		if _, ok := programs[uint16(n-0x180)]; ok {
			programs[uint16(n)].oneSeg = true
		}
	}

	if asJSON {
		out := map[string]any{"source": src, "bytes": total, "programs": []any{}}
		for _, n := range nums {
			p := programs[uint16(n)]
			e := map[string]any{"program": n, "oneSeg": p.oneSeg}
			if p.video != nil {
				e["videoPID"] = p.video.pid
				e["videoType"] = p.video.streamType
				e["videoPTSDeltaMed"] = p.video.ptsDelta.med()
				e["videoReorderMax"] = p.video.reorder.max()
			}
			if p.audio != nil {
				e["audioPID"] = p.audio.pid
				e["audioPTSDeltaMed"] = p.audio.ptsDelta.med()
			}
			e["skewP1"], e["skewMed"], e["skewP99"] = p.skew.pct(1), p.skew.med(), p.skew.pct(99)
			out["programs"] = append(out["programs"].([]any), e)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
		return
	}

	fmt.Printf("%s  %.1f MiB\n", src, float64(total)/(1<<20))
	for _, n := range nums {
		p := programs[uint16(n)]
		if p.video == nil || p.audio == nil {
			continue
		}
		kind := "fullseg"
		if p.oneSeg {
			kind = "1seg"
		}
		fmt.Printf("\nprogram %d (%s)  PCR=0x%04x  video=0x%04x/st=0x%02x  audio=0x%04x/st=0x%02x\n",
			n, kind, p.pcrPID, p.video.pid, p.video.streamType, p.audio.pid, p.audio.streamType)
		fmt.Printf("  video  PES=%-5d noPTS=%-4d PTSdelta ms p1=%s p50=%s p99=%s  PTS-DTS ms p50=%s max=%s  jumps=%d\n",
			p.video.count, p.video.noPTS,
			f(p.video.ptsDelta.pct(1)), f(p.video.ptsDelta.med()), f(p.video.ptsDelta.pct(99)),
			f(p.video.reorder.med()), f(p.video.reorder.max()), p.video.jumps)
		fmt.Printf("  audio  PES=%-5d noPTS=%-4d PTSdelta ms p1=%s p50=%s p99=%s  jitter(|d-p50|) p95=%s max=%s  jumps=%d\n",
			p.audio.count, p.audio.noPTS,
			f(p.audio.ptsDelta.pct(1)), f(p.audio.ptsDelta.med()), f(p.audio.ptsDelta.pct(99)),
			f(jitter(&p.audio.ptsDelta, 95)), f(jitter(&p.audio.ptsDelta, 100)), p.audio.jumps)
		fmt.Printf("  skew (videoPTS - audioPTS, 伝送順) ms  min=%s p1=%s p50=%s p99=%s max=%s   n=%d\n",
			f(p.skew.min()), f(p.skew.pct(1)), f(p.skew.med()), f(p.skew.pct(99)), f(p.skew.max()), p.skew.n())
		fmt.Printf("  PTS-PCR ms  video p50=%s max=%s   audio p50=%s max=%s\n",
			f(p.videoAhead.med()), f(p.videoAhead.max()), f(p.audioAhead.med()), f(p.audioAhead.max()))
		if p.pcrCount > 1 {
			streamSec := float64(wrapDiff(p.lastPCR, p.firstPCR)) / 90000
			localSec := p.lastLocal.Sub(p.firstLocal).Seconds()
			ppm := math.NaN()
			if localSec > 1 {
				ppm = (streamSec/localSec - 1) * 1e6
			}
			fmt.Printf("  PCR  packets=%-6d 間隔 ms p50=%s p99=%s max=%s  観測長=%.1fs  局所時計との差=%.0f ppm\n",
				p.pcrCount, f(p.pcrGap.med()), f(p.pcrGap.pct(99)), f(p.pcrGap.max()), streamSec, ppm)
		}
	}
}

func jitter(s *series, p float64) float64 {
	if s.n() == 0 {
		return math.NaN()
	}
	m := s.med()
	var j series
	for _, x := range s.v {
		j.add(math.Abs(x - m))
	}
	return j.pct(p)
}
