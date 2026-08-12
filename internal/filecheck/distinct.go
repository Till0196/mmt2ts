// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package filecheck は入力と出力が同じファイルを指していないか確認する。
package filecheck

import (
	"fmt"
	"os"
)

func Distinct(input, output string) error {
	if input == "-" || output == "-" {
		return nil
	}
	in, err := os.Stat(input)
	if err != nil {
		return nil
	}
	out, err := os.Stat(output)
	if err != nil {
		return nil
	}
	if os.SameFile(in, out) {
		return fmt.Errorf("output %q is the input file %q", output, input)
	}
	return nil
}
