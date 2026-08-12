// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"bytes"
	"testing"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/tscheck"
)

type countingReader struct {
	b     *bytes.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.b.Read(p)
}

type countingWriter struct{ writes, bytes int }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	c.bytes += len(p)
	return len(p), nil
}

func TestRunRejectsUnusableOptionsBeforeTouchingTheStreams(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"zero PCR interval", func(o *Options) { o.PCRInterval = 0 }},
		{"negative PCR interval", func(o *Options) { o.PCRInterval = -1 }},
		{"zero PSI interval", func(o *Options) { o.PSIInterval = 0 }},
		{"negative PSI interval", func(o *Options) { o.PSIInterval = -1 }},
		{"negative reorder window", func(o *Options) { o.ReorderWindow = -1 }},
		{"PMT PID below the usable range", func(o *Options) { o.PMTPID = 0x001f }},
		{"PMT PID zero", func(o *Options) { o.PMTPID = 0 }},
		{"PMT PID at the null packet", func(o *Options) { o.PMTPID = 0x1fff }},
		{"PMT PID at BIT", func(o *Options) { o.PMTPID = mpegts.PIDBIT }},
		{"PMT PID at CDT", func(o *Options) { o.PMTPID = mpegts.PIDCDT }},
	}
	input := buildStream(2, 3, 5, -1)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := DefaultOptions()
			opts.ServiceID = 1
			tc.mutate(&opts)
			if err := opts.Validate(); err == nil {
				t.Fatal("Validate accepted the options")
			}
			r := &countingReader{b: bytes.NewReader(input)}
			w := &countingWriter{}
			if _, err := Run(r, w, opts); err == nil {
				t.Fatal("Run accepted the options")
			}
			if r.reads != 0 {
				t.Fatalf("input was read %d times before the options were rejected", r.reads)
			}
			if w.writes != 0 {
				t.Fatalf("output was written %d times before the options were rejected", w.writes)
			}
		})
	}
}

func TestRunAcceptsANegativePreroll(t *testing.T) {
	opts := DefaultOptions()
	opts.Preroll = -1
	if err := opts.Validate(); err != nil {
		t.Fatalf("a negative preroll was rejected: %v", err)
	}
}

func TestRunAcceptsTheEdgesOfThePMTPIDRange(t *testing.T) {
	for _, pid := range []uint16{MinPMTPID, MaxPMTPID} {
		opts := DefaultOptions()
		opts.PMTPID = pid
		if err := opts.Validate(); err != nil {
			t.Fatalf("PMT PID %#04x was rejected: %v", pid, err)
		}
	}
}

func TestCustomPMTPIDDoesNotCollideWithAnElementaryStream(t *testing.T) {
	var out bytes.Buffer
	opts := DefaultOptions()
	opts.ServiceID = 1
	opts.PMTPID = videoPIDBase
	if _, err := Run(bytes.NewReader(buildStream(4, 3, 5, -1)), &out, opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	check, err := tscheck.Scan(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("tscheck: %v", err)
	}
	if check.Errors() != 0 {
		tscheck.WriteReport(testWriter{t}, check)
		t.Fatalf("independent check found %d problems", check.Errors())
	}
	if got := check.Programs[1]; got != videoPIDBase {
		t.Fatalf("PMT PID = %#04x, want %#04x", got, videoPIDBase)
	}
	if pmt := check.PIDs[videoPIDBase]; pmt == nil || pmt.PESUnits != 0 || pmt.StreamType != 0 {
		t.Fatalf("an elementary stream was placed on the PMT PID %#04x: %+v", videoPIDBase, pmt)
	}
	video := check.PIDs[videoPIDBase+1]
	if video == nil {
		t.Fatalf("video did not move to the next free PID: %v", check.PIDs)
	}
	if check.PCRPID != videoPIDBase+1 {
		t.Fatalf("PCR PID = %#04x, want the video PID", check.PCRPID)
	}
}
