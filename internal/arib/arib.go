// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package arib はARIB文字コードと字幕データの読み書きを扱う。
package arib

import "strings"

type Class uint8

const (
	ClassStandard Class = iota
	ClassNormalized
	ClassSubstituted
	ClassDRCS
	ClassUnconvertible
)

func (c Class) String() string {
	switch c {
	case ClassStandard:
		return "standard"
	case ClassNormalized:
		return "normalized"
	case ClassSubstituted:
		return "substituted"
	case ClassDRCS:
		return "drcs"
	default:
		return "unconvertible"
	}
}

type Record struct {
	Rune       rune
	Class      Class
	Via        rune
	Substitute string
	Cell       uint16
}

type Result struct {
	Bytes   []byte
	Records []Record
	Counts  [5]uint64
	Offsets []int32
}

func (r Result) Count(c Class) uint64 { return r.Counts[c] }

func (r Result) Lossless() bool {
	return r.Counts[ClassSubstituted] == 0 && r.Counts[ClassDRCS] == 0 && r.Counts[ClassUnconvertible] == 0
}

func (r Result) Unconvertible() []rune {
	var out []rune
	for _, rec := range r.Records {
		if rec.Class == ClassUnconvertible {
			out = append(out, rec.Rune)
		}
	}
	return out
}

func (r Result) Describe() string {
	if r.Lossless() {
		return ""
	}
	var b strings.Builder
	for _, rec := range r.Records {
		switch rec.Class {
		case ClassSubstituted:
			b.WriteString(string(rec.Rune) + "->" + rec.Substitute + " ")
		case ClassDRCS:
			b.WriteString(string(rec.Rune) + "->DRCS ")
		case ClassUnconvertible:
			b.WriteString(string(rec.Rune) + "->? ")
		}
	}
	return strings.TrimSpace(b.String())
}
