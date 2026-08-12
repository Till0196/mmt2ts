// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

var errTruncated = errors.New("preservation: truncated structure")

type reader struct {
	b   []byte
	err error
}

func (r *reader) fail() {
	if r.err == nil {
		r.err = errTruncated
	}
	r.b = nil
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return make([]byte, n)
	}
	if n < 0 || len(r.b) < n {
		r.fail()
		return make([]byte, n)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() byte    { return r.take(1)[0] }
func (r *reader) u16() uint16 { return binary.BigEndian.Uint16(r.take(2)) }
func (r *reader) u32() uint32 { return binary.BigEndian.Uint32(r.take(4)) }
func (r *reader) u64() uint64 { return binary.BigEndian.Uint64(r.take(8)) }
func (r *reader) skip(n int)  { r.take(n) }
func (r *reader) bytes(n int) []byte {
	return append([]byte(nil), r.take(n)...)
}

func (r *reader) sha256() [32]byte {
	var out [32]byte
	copy(out[:], r.take(32))
	return out
}

func (r *reader) text(n int) string {
	b := r.take(n)
	if r.err != nil {
		return ""
	}
	if !utf8.Valid(b) {
		r.err = errors.New("preservation: string is not valid UTF-8")
		return ""
	}
	return string(b)
}

func (r *reader) done() error {
	if r.err != nil {
		return r.err
	}
	if len(r.b) != 0 {
		return errors.New("preservation: trailing bytes after the declared structure")
	}
	return nil
}
