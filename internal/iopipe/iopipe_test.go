// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package iopipe

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
)

type chunkWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	chunk int
	calls int
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	return c.buf.Write(p)
}

func (c *chunkWriter) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

type stalledWriter struct{}

func (stalledWriter) Write(p []byte) (int, error) { return 0, nil }

func TestAsyncWriterCompletesShortWrites(t *testing.T) {
	w := &chunkWriter{chunk: 7}
	a := NewAsyncWriter(w, 64, 2)
	want := bytes.Repeat([]byte("mmt2ts--"), 40)
	if n, err := a.Write(want); n != len(want) || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if got := w.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("wrote %d bytes, want %d", len(got), len(want))
	}
	if w.calls < 2 {
		t.Fatalf("the short write was never retried: %d calls", w.calls)
	}
}

func TestAsyncWriterBlockPathCompletesShortWrites(t *testing.T) {
	w := &chunkWriter{chunk: 5}
	a := NewAsyncWriter(w, 64, 2)
	want := bytes.Repeat([]byte{0x47}, 64)
	b := append(a.NextBlock(), want...)
	if err := a.WriteBlock(b); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if got := w.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("wrote %d bytes, want %d", len(got), len(want))
	}
}

func TestAsyncWriterFailsOnAWriterThatTakesNothing(t *testing.T) {
	a := NewAsyncWriter(stalledWriter{}, 8, 2)
	if _, err := a.Write(bytes.Repeat([]byte{1}, 32)); err != nil {
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("Write error = %v, want io.ErrShortWrite", err)
		}
	}
	if err := a.Close(); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Close error = %v, want io.ErrShortWrite", err)
	}
}
