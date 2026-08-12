// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package iox

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type chunkWriter struct {
	bytes.Buffer
	chunk int
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	if len(p) > w.chunk {
		p = p[:w.chunk]
	}
	return w.Buffer.Write(p)
}

func TestWriteFull(t *testing.T) {
	w := &chunkWriter{chunk: 3}
	if err := WriteFull(w, []byte("abcdefgh")); err != nil {
		t.Fatal(err)
	}
	if got := w.String(); got != "abcdefgh" {
		t.Fatalf("wrote %q", got)
	}
}

func TestWriteFullRejectsNoProgress(t *testing.T) {
	err := WriteFull(writerFunc(func([]byte) (int, error) { return 0, nil }), []byte{1})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error = %v", err)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
