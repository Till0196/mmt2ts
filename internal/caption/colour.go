// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package caption

import (
	"strconv"
	"strings"
)

type RGBA struct{ R, G, B, A uint8 }

var defaultColours = [8]struct {
	name    string
	r, g, b uint8
}{
	{"black", 0x00, 0x00, 0x00},
	{"red", 0xff, 0x00, 0x00},
	{"green", 0x00, 0xff, 0x00},
	{"yellow", 0xff, 0xff, 0x00},
	{"blue", 0x00, 0x00, 0xff},
	{"magenta", 0xff, 0x00, 0xff},
	{"cyan", 0x00, 0xff, 0xff},
	{"white", 0xff, 0xff, 0xff},
}

const clutPaletteSize = 16

const transparentIndex = 8

var defaultCLUT = buildDefaultCLUT()

func halfIntensity(v uint8) uint8 {
	if v == 0xff {
		return 0xaa
	}
	return v
}

func buildDefaultCLUT() []RGBA {
	clut := make([]RGBA, 0, 128)
	for _, c := range defaultColours {
		clut = append(clut, RGBA{c.r, c.g, c.b, 0xff})
	}
	clut = append(clut, RGBA{0, 0, 0, 0})
	for _, c := range defaultColours[1:] {
		clut = append(clut, RGBA{halfIntensity(c.r), halfIntensity(c.g), halfIntensity(c.b), 0xff})
	}
	seen := make(map[RGBA]bool, len(clut))
	for _, c := range clut {
		seen[RGBA{c.R, c.G, c.B, 0xff}] = true
	}
	levels := [4]uint8{0x00, 0x55, 0xaa, 0xff}
	for _, r := range levels {
		for _, g := range levels {
			for _, b := range levels {
				if c := (RGBA{r, g, b, 0xff}); !seen[c] {
					clut = append(clut, c)
				}
			}
		}
	}
	for i := 0; len(clut) < 128; i++ {
		if clut[i].A == 0 {
			continue
		}
		c := clut[i]
		c.A = 0x80
		clut = append(clut, c)
	}
	return clut
}

func nearestColour(css string) (palette, index byte, exact bool) {
	want, ok := parseColour(css)
	if !ok {
		return 0, 7, false
	}
	if want.A == 0 {
		return 0, transparentIndex, true
	}
	best, bestDist := 0, 1<<30
	for i, c := range defaultCLUT {
		dr, dg, db := int(want.R)-int(c.R), int(want.G)-int(c.G), int(want.B)-int(c.B)
		da := int(want.A) - int(c.A)
		if d := dr*dr + dg*dg + db*db + da*da; d < bestDist {
			best, bestDist = i, d
		}
	}
	return byte(best / clutPaletteSize), byte(best % clutPaletteSize), bestDist == 0
}

func parseColour(css string) (RGBA, bool) {
	css = strings.TrimSpace(strings.ToLower(css))
	for _, c := range defaultColours {
		if css == c.name {
			return RGBA{c.r, c.g, c.b, 0xff}, true
		}
	}
	if css == "transparent" {
		return RGBA{}, true
	}
	if !strings.HasPrefix(css, "#") {
		return RGBA{}, false
	}
	hex := css[1:]
	c := RGBA{A: 0xff}
	out := [4]*uint8{&c.R, &c.G, &c.B, &c.A}
	switch len(hex) {
	case 3, 4:
		for i := range hex {
			v, err := strconv.ParseUint(hex[i:i+1], 16, 8)
			if err != nil {
				return RGBA{}, false
			}
			*out[i] = uint8(v) * 0x11
		}
		return c, true
	case 6, 8:
		for i := 0; i*2 < len(hex); i++ {
			v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
			if err != nil {
				return RGBA{}, false
			}
			*out[i] = uint8(v)
		}
		return c, true
	default:
		return RGBA{}, false
	}
}
