// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"mmt2ts/internal/remux"
	"mmt2ts/internal/siconv"
)

func TestUint16FlagRejectsValuesThatWouldWrap(t *testing.T) {
	for _, v := range []uint{0x10000, 0x1ffff, 1 << 20} {
		if _, err := uint16Flag("-service", v); err == nil {
			t.Fatalf("%d was accepted", v)
		}
	}
	for _, v := range []uint{0, 1, 0xffff} {
		got, err := uint16Flag("-service", v)
		if err != nil || uint(got) != v {
			t.Fatalf("uint16Flag(%d) = %d, %v", v, got, err)
		}
	}
}

func TestPMTPIDValueChecksTheUsableRange(t *testing.T) {
	for _, v := range []uint{0, 1, 0x1f, 0x24, 0x29, 0x1fff, 0x2000, 0x10000} {
		if _, err := pmtPIDValue(v); err == nil {
			t.Fatalf("-pmt-pid %#x was accepted", v)
		}
	}
	for _, v := range []uint{remux.MinPMTPID, 0x0100, remux.MaxPMTPID} {
		got, err := pmtPIDValue(uint(v))
		if err != nil || uint(got) != uint(v) {
			t.Fatalf("pmtPIDValue(%#x) = %#x, %v", v, got, err)
		}
	}
}

func TestTextModeOnlyAcceptsARIB(t *testing.T) {
	got, err := textMode("arib")
	if err != nil || got != siconv.TextARIB {
		t.Fatalf("textMode(arib) = %v, %v", got, err)
	}
	if _, err := textMode("utf8"); err == nil {
		t.Fatal("an unsupported encoding was accepted")
	}
}

func TestCheckDistinctRefusesToOverwriteTheInput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.tlv")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("same path", func(t *testing.T) {
		if err := checkDistinct(input, input); err == nil {
			t.Fatal("converting a file onto itself was allowed")
		}
	})

	t.Run("different spelling of the same path", func(t *testing.T) {
		indirect := filepath.Join(dir, "sub", "..", "in.tlv")
		if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := checkDistinct(input, indirect); err == nil {
			t.Fatal("a different spelling of the input path was allowed")
		}
	})

	t.Run("hard link", func(t *testing.T) {
		link := filepath.Join(dir, "hard.tlv")
		if err := os.Link(input, link); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		if err := checkDistinct(input, link); err == nil {
			t.Fatal("a hard link to the input was allowed")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(dir, "soft.tlv")
		if err := os.Symlink(input, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := checkDistinct(input, link); err == nil {
			t.Fatal("a symlink to the input was allowed")
		}
	})

	t.Run("a different file", func(t *testing.T) {
		other := filepath.Join(dir, "out.ts")
		if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := checkDistinct(input, other); err != nil {
			t.Fatalf("a distinct output was refused: %v", err)
		}
	})

	t.Run("output that does not exist yet", func(t *testing.T) {
		if err := checkDistinct(input, filepath.Join(dir, "new.ts")); err != nil {
			t.Fatalf("a new output was refused: %v", err)
		}
	})

	t.Run("standard streams", func(t *testing.T) {
		if err := checkDistinct("-", "-"); err != nil {
			t.Fatalf("stdin to stdout was refused: %v", err)
		}
	})
}

func TestBadFlagsDoNotTruncateTheOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.tlv")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "out.ts")
	existing := []byte("do not truncate me")
	if err := os.WriteFile(output, existing, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{"-pmt-pid", "0x1fff"},
		{"-pmt-pid", "0"},
		{"-service", "70000"},
		{"-tsid", "70000"},
		{"-si-text", "utf8"},
		{"-reorder", "-1"},
	}
	for _, extra := range cases {
		args := append([]string{"-i", input, "-o", output}, extra...)
		if err := runConvert(args); err == nil {
			t.Fatalf("%v was accepted", extra)
		}
		got, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(existing) {
			t.Fatalf("%v truncated the output file to %q", extra, got)
		}
	}
}

func TestConvertingAFileOntoItselfLeavesItIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stream.tlv")
	content := []byte("payload that must survive")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runConvert([]string{"-i", path, "-o", path}); err == nil {
		t.Fatal("converting a file onto itself was allowed")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("the input was modified: %q", got)
	}
}
