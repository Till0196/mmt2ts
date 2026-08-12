// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"mmt2ts/internal/filecheck"
	"mmt2ts/internal/timeline"
	"mmt2ts/internal/tlv"
)

const searchWindow = 8 << 20

const probeLimit = 16 << 20

var (
	version = "devel"
	commit  = "unknown"
	date    = "unknown"
)

const (
	syncWindow = 1 << 20
	syncChain  = 8
)

var errNoSync = errors.New("no TLV packet boundary found")

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mmtcut:", err)
		os.Exit(1)
	}
}

func run() error {
	input := flag.String("i", "", "input .mmts/.mmtp file (a real file: cutting needs to seek)")
	output := flag.String("o", "", "output file")
	fromStr := flag.String("from", "0", "start time, HH:MM:SS[.mmm], MM:SS or seconds; relative to the stream's first NTP sample")
	toStr := flag.String("to", "", "end time, same format; empty means end of file")
	margin := flag.Float64("margin", 0, "seconds to add before -from and after -to, so periodic signalling and caption management data are included")
	quiet := flag.Bool("quiet", false, "suppress the summary printed to stderr")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("%s commit=%s date=%s\n", version, commit, date)
		return nil
	}

	if *input == "" || *output == "" {
		return errors.New("-i and -o are required")
	}
	if err := filecheck.Distinct(*input, *output); err != nil {
		return fmt.Errorf("%w; cutting a file onto itself would destroy it", err)
	}
	from, err := parseTime(*fromStr)
	if err != nil {
		return fmt.Errorf("-from: %w", err)
	}
	from -= *margin
	if from < 0 {
		from = 0
	}
	haveTo := *toStr != ""
	var to float64
	if haveTo {
		to, err = parseTime(*toStr)
		if err != nil {
			return fmt.Errorf("-to: %w", err)
		}
		to += *margin
		if to <= from {
			return fmt.Errorf("-to (%s) is not after -from (%s) once -margin is applied", *toStr, *fromStr)
		}
	}

	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := uint64(info.Size())

	base, ok, err := firstNTP(f, size)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("no NTP packet in the input: the sender clock is what times the cut")
	}

	startOffset, ok, err := seekTo(f, size, base, from)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the stream ends before -from (%.3fs)", from)
	}
	endOffset := size
	toAtEOF := true
	if haveTo {
		off, found, err := seekTo(f, size, base, to)
		if err != nil {
			return err
		}
		if found {
			endOffset, toAtEOF = off, false
		}
	}
	if endOffset <= startOffset {
		return fmt.Errorf("empty range: start offset %d, end offset %d", startOffset, endOffset)
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "mmtcut: byte range [%d, %d) = %.1f MiB",
			startOffset, endOffset, float64(endOffset-startOffset)/(1<<20))
		if toAtEOF {
			fmt.Fprint(os.Stderr, " (to end of file)")
		}
		fmt.Fprintln(os.Stderr)
	}

	if _, err := f.Seek(int64(startOffset), io.SeekStart); err != nil {
		return err
	}
	out, err := os.Create(*output)
	if err != nil {
		return err
	}
	defer out.Close()
	w := bufio.NewWriterSize(out, 1<<20)
	if _, err := io.CopyN(w, f, int64(endOffset-startOffset)); err != nil {
		return err
	}
	return w.Flush()
}

func seekTo(f *os.File, size, base uint64, target float64) (uint64, bool, error) {
	if target <= 0 {
		off, err := syncAt(f, 0, size)
		if errors.Is(err, errNoSync) {
			return 0, false, nil
		}
		return off, err == nil, err
	}
	lo, hi := uint64(0), size
	for hi-lo > searchWindow {
		mid := lo + (hi-lo)/2
		ntp, _, found, err := probeNTP(f, mid, size)
		if err != nil {
			return 0, false, err
		}
		if !found || timeline.NTPDeltaSeconds(ntp, base) >= target {
			hi = mid
			continue
		}
		lo = mid
	}
	return scanTo(f, lo, size, base, target)
}

func scanTo(f *os.File, off, size, base uint64, target float64) (uint64, bool, error) {
	sync, err := syncAt(f, off, size)
	if errors.Is(err, errNoSync) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	tr := tlv.NewReader(bufio.NewReaderSize(io.NewSectionReader(f, int64(sync), int64(size-sync)), 1<<20))
	for {
		p, err := tr.Next()
		if err != nil {
			return 0, false, nil
		}
		d, ok := tr.Datagram(p)
		if !ok || !d.IsNTP() || len(d.Payload) < 48 {
			continue
		}
		if timeline.NTPDeltaSeconds(binary.BigEndian.Uint64(d.Payload[40:48]), base) >= target {
			return sync + p.Offset, true, nil
		}
	}
}

func probeNTP(f *os.File, off, size uint64) (ntp uint64, packetOffset uint64, found bool, err error) {
	sync, err := syncAt(f, off, size)
	if errors.Is(err, errNoSync) {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	limit := size - sync
	if limit > probeLimit {
		limit = probeLimit
	}
	tr := tlv.NewReader(bufio.NewReaderSize(io.NewSectionReader(f, int64(sync), int64(limit)), 1<<20))
	for {
		p, err := tr.Next()
		if err != nil {
			return 0, 0, false, nil
		}
		d, ok := tr.Datagram(p)
		if !ok || !d.IsNTP() || len(d.Payload) < 48 {
			continue
		}
		return binary.BigEndian.Uint64(d.Payload[40:48]), sync + p.Offset, true, nil
	}
}

func firstNTP(f *os.File, size uint64) (uint64, bool, error) {
	ntp, _, found, err := probeNTP(f, 0, size)
	return ntp, found, err
}

func syncAt(f *os.File, off, size uint64) (uint64, error) {
	if off >= size {
		return 0, errNoSync
	}
	n := size - off
	if n > syncWindow {
		n = syncWindow
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, int64(off)); err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	for i := range buf {
		if buf[i] == tlv.SyncByte && chains(buf[i:], syncChain) {
			return off + uint64(i), nil
		}
	}
	return 0, errNoSync
}

func chains(b []byte, want int) bool {
	p := 0
	for n := range want {
		if p+4 > len(b) {
			return n >= 2
		}
		if b[p] != tlv.SyncByte || !knownType(b[p+1]) {
			return false
		}
		p += 4 + int(binary.BigEndian.Uint16(b[p+2:p+4]))
	}
	return true
}

func knownType(t byte) bool {
	switch t {
	case tlv.TypeIPv4, tlv.TypeIPv6, tlv.TypeCompressedIP, tlv.TypeControl, tlv.TypeNull:
		return true
	}
	return false
}

func parseTime(s string) (float64, error) {
	parts := strings.Split(s, ":")
	if len(parts) > 3 {
		return 0, fmt.Errorf("too many ':'-separated fields in %q", s)
	}
	var total float64
	for _, p := range parts {
		v, err := strconv.ParseFloat(p, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a number", p)
		}
		total = total*60 + v
	}
	return total, nil
}
