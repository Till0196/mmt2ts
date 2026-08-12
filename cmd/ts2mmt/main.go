// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"mmt2ts/internal/filecheck"
	"mmt2ts/internal/iopipe"
	"mmt2ts/internal/tsremux"
)

var (
	version = "devel"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ts2mmt:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("ts2mmt", flag.ContinueOnError)
	input := fs.String("i", "-", "input MPEG-2 TS file ('-' for stdin)")
	output := fs.String("o", "-", "output MMT/TLV file ('-' for stdout)")
	quiet := fs.Bool("quiet", false, "suppress the conversion report")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("%s commit=%s date=%s\n", version, commit, date)
		return nil
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

	report, err := tsremux.Run(in, out)
	if err != nil {
		return err
	}
	closed = true
	if err := closeOut(); err != nil {
		return err
	}
	if !*quiet {
		tsremux.WriteReport(os.Stderr, report)
	}
	return nil
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
