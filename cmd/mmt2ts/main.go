// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"mmt2ts/internal/filecheck"
	"mmt2ts/internal/inspect"
	"mmt2ts/internal/iopipe"
	"mmt2ts/internal/remux"
	"mmt2ts/internal/siconv"
	"mmt2ts/internal/timeline"
	"mmt2ts/internal/tscheck"
)

var (
	version = "devel"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "inspect":
			run("inspect", runInspect(os.Args[2:]))
		case "verify":
			run("verify", runVerify(os.Args[2:]))
		}
	}
	if err := runConvert(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mmt2ts:", err)
		os.Exit(1)
	}
}

func run(name string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "mmt2ts %s: %v\n", name, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func runConvert(args []string) error {
	fs := flag.NewFlagSet("mmt2ts", flag.ContinueOnError)
	input := fs.String("i", "-", "input TLV file ('-' for stdin)")
	output := fs.String("o", "-", "output MPEG-2 TS file ('-' for stdout)")
	service := fs.Uint("service", 0, "output program_number / service_id (0: the service the input names)")
	tsid := fs.Uint("tsid", 0, "output transport_stream_id (0: the TLV stream the service arrived on)")
	pmtPID := fs.Uint("pmt-pid", 0x0100, "PMT PID")
	reorder := fs.Float64("reorder", 3, "reorder window in seconds")
	preroll := fs.Float64("preroll", 1, "PCR to PTS distance in seconds")
	siText := fs.String("si-text", "arib", "SI string encoding (only arib is supported by full TS output)")
	resumeNoIRAP := fs.Bool("resume-without-irap", false, "after a loss, write video before the next random access point")
	noCarousel := fs.Bool("no-carousel", false, "omit the MMT restoration DSM-CC carousels")
	segmentMS := fs.Uint("segment-ms", 0, "preservation time window in ms, 250-1000 (0: chosen from the input)")
	quiet := fs.Bool("quiet", false, "suppress the conversion report")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("%s commit=%s date=%s\n", version, commit, date)
		return nil
	}

	opts := remux.DefaultOptions()
	var err error
	if opts.ServiceID, err = uint16Flag("-service", *service); err != nil {
		return err
	}
	if opts.TSID, err = uint16Flag("-tsid", *tsid); err != nil {
		return err
	}
	if opts.PMTPID, err = pmtPIDValue(*pmtPID); err != nil {
		return err
	}
	opts.ReorderWindow = int64(*reorder * timeline.Hz)
	opts.Preroll = int64(*preroll * timeline.Hz)
	if opts.TextMode, err = textMode(*siText); err != nil {
		return err
	}
	opts.ResumeWithoutIRAP = *resumeNoIRAP
	opts.Carousel = !*noCarousel
	if *segmentMS > 1000 {
		return fmt.Errorf("-segment-ms %d is outside 250-1000", *segmentMS)
	}
	opts.SegmentDurationMS = uint32(*segmentMS)
	if err := opts.Validate(); err != nil {
		return err
	}
	if err := checkDistinct(*input, *output); err != nil {
		return err
	}

	in, closeIn, err := openInput(*input)
	if err != nil {
		return err
	}
	defer closeIn()
	out, closeOut, err := openOutput(*output)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			closeOut()
		}
	}()

	report, err := remux.Run(in, out, opts)
	if err != nil {
		return err
	}
	closed = true
	if err := closeOut(); err != nil {
		return err
	}
	if !*quiet {
		remux.WriteReport(os.Stderr, report)
	}
	return nil
}

func uint16Flag(name string, v uint) (uint16, error) {
	if v > 0xffff {
		return 0, fmt.Errorf("%s %d is out of range 0-65535", name, v)
	}
	return uint16(v), nil
}

func pmtPIDValue(v uint) (uint16, error) {
	pid, err := uint16Flag("-pmt-pid", v)
	if err != nil {
		return 0, err
	}
	if pid < remux.MinPMTPID || pid > remux.MaxPMTPID {
		return 0, fmt.Errorf("-pmt-pid %#x is outside the usable range %#04x-%#04x",
			v, remux.MinPMTPID, remux.MaxPMTPID)
	}
	if err := remux.ValidatePMTPID(pid); err != nil {
		return 0, fmt.Errorf("-pmt-pid: %w", err)
	}
	return pid, nil
}

func textMode(name string) (siconv.TextMode, error) {
	switch name {
	case "arib":
		return siconv.TextARIB, nil
	default:
		return 0, fmt.Errorf("unknown -si-text %q: full TS output requires arib", name)
	}
}

func checkDistinct(input, output string) error {
	if err := filecheck.Distinct(input, output); err != nil {
		return fmt.Errorf("%w; converting a file onto itself would destroy it", err)
	}
	return nil
}

const (
	ioBlock     = 1 << 20
	readAhead   = 4
	readWorkers = 4
	writeBehind = 4
)

func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		r := iopipe.NewReadAhead(os.Stdin, ioBlock, readAhead)
		return r, func() { r.Close() }, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if info, err := f.Stat(); err == nil && info.Mode().IsRegular() {
		r := iopipe.NewParallelReader(f, info.Size(), ioBlock, readWorkers, readAhead)
		return r, func() { r.Close(); f.Close() }, nil
	}
	r := iopipe.NewReadAhead(f, ioBlock, readAhead)
	return r, func() { r.Close(); f.Close() }, nil
}

func openOutput(path string) (io.Writer, func() error, error) {
	if path == "-" {
		w := iopipe.NewAsyncWriter(os.Stdout, ioBlock, writeBehind)
		return w, w.Close, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	w := iopipe.NewAsyncWriter(f, ioBlock, writeBehind)
	return w, func() error {
		werr := w.Close()
		cerr := f.Close()
		if werr != nil {
			return werr
		}
		return cerr
	}, nil
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	inputPath := fs.String("i", "-", "input TLV file ('-' for stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	in, closeIn, err := openInput(*inputPath)
	if err != nil {
		return err
	}
	defer closeIn()
	report, err := inspect.Scan(in)
	if err != nil {
		return err
	}
	inspect.WriteReport(os.Stdout, report)
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	inputPath := fs.String("i", "-", "MPEG-2 TS file to check ('-' for stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	in, closeIn, err := openInput(*inputPath)
	if err != nil {
		return err
	}
	defer closeIn()
	report, err := tscheck.Scan(in)
	if err != nil {
		return err
	}
	tscheck.WriteReport(os.Stdout, report)
	if report.Errors() > 0 {
		return fmt.Errorf("%d problems found", report.Errors())
	}
	return nil
}
