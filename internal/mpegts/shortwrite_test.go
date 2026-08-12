// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package mpegts

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type chunkWriter struct {
	buf   bytes.Buffer
	chunk int
	calls int
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	c.calls++
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	return c.buf.Write(p)
}

type stalledWriter struct{ calls int }

func (s *stalledWriter) Write(p []byte) (int, error) {
	s.calls++
	return 0, nil
}

func TestFlushCompletesAShortWrite(t *testing.T) {
	w := &chunkWriter{chunk: 100}
	tw := NewWriter(w)
	const units = 40
	payload := bytes.Repeat([]byte{0xa5}, 400)
	for range units {
		if err := tw.WriteUnit(0x0100, payload, Adaptation{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := uint64(w.buf.Len()); got != tw.Bytes {
		t.Fatalf("writer received %d bytes, the muxer produced %d", got, tw.Bytes)
	}
	if w.calls < 2 {
		t.Fatalf("the short write was never retried: %d calls", w.calls)
	}
	out := w.buf.Bytes()
	for i := 0; i < len(out); i += PacketSize {
		if out[i] != SyncByte {
			t.Fatalf("packet at %d does not start with the sync byte", i/PacketSize)
		}
	}
}

func TestFlushFailsOnAWriterThatTakesNothing(t *testing.T) {
	w := &stalledWriter{}
	tw := NewWriter(w)
	if err := tw.WriteUnit(0x0100, []byte{1, 2, 3}, Adaptation{}); err != nil {
		t.Fatal(err)
	}
	err := tw.Flush()
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Flush error = %v, want io.ErrShortWrite", err)
	}
	if w.calls != 1 {
		t.Fatalf("writer calls = %d, want the loop to stop at once", w.calls)
	}
}
