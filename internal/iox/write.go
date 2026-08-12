// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package iox は短い書き込みを検出する共通処理を提供する。
package iox

import (
	"io"
)

func WriteFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
