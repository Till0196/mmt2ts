// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package filecheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDistinctRecognisesLinks(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	if err := os.WriteFile(in, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, makeLink := range map[string]func(string) error{
		"hard": func(path string) error { return os.Link(in, path) },
		"soft": func(path string) error { return os.Symlink(in, path) },
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := makeLink(path); err != nil {
				t.Skip(err)
			}
			if err := Distinct(in, path); err == nil {
				t.Fatal("same file was accepted")
			}
		})
	}
}
