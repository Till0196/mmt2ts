// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package siconv

import (
	"unicode/utf8"

	"mmt2ts/internal/arib"
)

type TextMode int

const (
	TextARIB TextMode = iota
)

type TextStats struct {
	Strings       uint64
	Scalars       uint64
	Standard      uint64
	Normalized    uint64
	Substituted   uint64
	DRCS          uint64
	Unconvertible uint64
	Truncated     uint64
	Dropped       uint64
	Samples       []rune
}

const maxSamples = 16

type Text struct {
	Mode  TextMode
	enc   *arib.Encoder
	stats TextStats
	cache map[textKey]*textEntry
}

type textKey struct {
	s     string
	limit int
}

type textEntry struct {
	out       []byte
	truncated bool
	dropped   int
	scalars   uint64
	counts    [5]uint64
	samples   []rune
}

const maxTextCache = 8192

func NewText(mode TextMode) *Text {
	return &Text{Mode: mode, enc: arib.NewEncoder(), cache: make(map[textKey]*textEntry)}
}

func (t *Text) Stats() TextStats { return t.stats }

func (t *Text) Encode(s string) []byte {
	b, _, _ := t.EncodeLimit(s, -1)
	return b
}

func (t *Text) EncodeLimit(s string, limit int) (out []byte, truncated bool, dropped int) {
	key := textKey{s: s, limit: limit}
	e, ok := t.cache[key]
	if !ok {
		e = t.build(s, limit)
		if len(t.cache) >= maxTextCache {
			clear(t.cache)
		}
		t.cache[key] = e
	}
	t.account(e)
	return e.out, e.truncated, e.dropped
}

func (t *Text) build(s string, limit int) *textEntry {
	res := t.enc.Encode(s)
	e := &textEntry{
		out:     res.Bytes,
		scalars: uint64(utf8.RuneCountInString(s)),
		counts:  res.Counts,
	}
	for _, rec := range res.Records {
		if rec.Class == arib.ClassUnconvertible {
			e.samples = append(e.samples, rec.Rune)
		}
	}
	if limit < 0 || len(res.Bytes) <= limit {
		return e
	}
	keep := len(res.Offsets)
	for i, off := range res.Offsets {
		if int(off) > limit {
			keep = i
			break
		}
	}
	e.out = res.Bytes[:0]
	if keep > 0 {
		e.out = res.Bytes[:res.Offsets[keep-1]]
	}
	e.truncated = true
	e.dropped = len(res.Offsets) - keep
	return e
}

func (t *Text) account(e *textEntry) {
	t.stats.Strings++
	t.stats.Scalars += e.scalars
	t.stats.Standard += e.counts[arib.ClassStandard]
	t.stats.Normalized += e.counts[arib.ClassNormalized]
	t.stats.Substituted += e.counts[arib.ClassSubstituted]
	t.stats.DRCS += e.counts[arib.ClassDRCS]
	t.stats.Unconvertible += e.counts[arib.ClassUnconvertible]
	for _, r := range e.samples {
		if len(t.stats.Samples) < maxSamples {
			t.stats.Samples = append(t.stats.Samples, r)
		}
	}
	if e.truncated {
		t.stats.Truncated++
		t.stats.Dropped += uint64(e.dropped)
	}
}

func (s TextStats) Lossless() bool {
	return s.Substituted == 0 && s.DRCS == 0 && s.Unconvertible == 0 && s.Dropped == 0
}
