// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package siup

import (
	"encoding/binary"
	"sort"

	"mmt2ts/internal/logocarousel"
	"mmt2ts/internal/si"
)

const dataTypeLogo = 0x01

type LogoSet struct {
	LogoID         uint16
	DownloadDataID uint16
	Sections       [][]byte
	Services       []logocarousel.Service
	descriptor     []byte
}

func (l LogoSet) Descriptor() []byte { return l.descriptor }

func (c *Converter) Logos(logos []logocarousel.Logo, networkID uint16) []LogoSet {
	byID := map[uint16][]logocarousel.Logo{}
	var order []uint16
	for _, l := range logos {
		if _, seen := byID[l.ID]; !seen {
			order = append(order, l.ID)
		}
		byID[l.ID] = append(byID[l.ID], l)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })

	out := make([]LogoSet, 0, len(order))
	for _, id := range order {
		group := byID[id]
		sort.SliceStable(group, func(i, j int) bool { return group[i].Type < group[j].Type })
		set := LogoSet{LogoID: id, DownloadDataID: id, Services: group[0].Services}
		entries := make([]byte, 0, 3*len(group))
		for i, l := range group {
			section, ok := c.logoSection(set.DownloadDataID, networkID, byte(i), byte(len(group)-1), l)
			if !ok {
				c.dropped[dataTypeLogo]++
				continue
			}
			set.Sections = append(set.Sections, section)
			entries = append(entries, l.Type, byte(i), 1)
		}
		if len(set.Sections) == 0 {
			continue
		}
		set.descriptor = c.logoTransmission(set.DownloadDataID, id, entries)
		out = append(out, set)
	}
	return out
}

func (c *Converter) logoSection(downloadDataID, networkID uint16, number, last byte,
	logo logocarousel.Logo) ([]byte, bool) {
	if len(logo.Data) > 0xffff {
		return nil, false
	}
	module := []byte{logo.Type}
	module = binary.BigEndian.AppendUint16(module, 0xfe00|logo.ID&0x01ff)
	module = binary.BigEndian.AppendUint16(module, 0xf000)
	module = binary.BigEndian.AppendUint16(module, uint16(len(logo.Data)))
	module = append(module, logo.Data...)

	body := binary.BigEndian.AppendUint16(nil, networkID)
	body = append(body, dataTypeLogo)
	body = binary.BigEndian.AppendUint16(body, 0xf000)
	body = append(body, module...)
	if len(body) > maxSectionBody {
		return nil, false
	}
	section, ok := longSection(si.TableIDMHCDT, downloadDataID, 0, number, last, body)
	if !ok {
		return nil, false
	}
	c.converted[dataTypeLogo]++
	c.outTag[dataTypeLogo] = si.TableIDMHCDT
	return section, true
}

func (c *Converter) logoTransmission(downloadDataID, logoID uint16, entries []byte) []byte {
	body := []byte{0x01}
	body = binary.BigEndian.AppendUint16(body, 0xfe00|logoID&0x01ff)
	body = binary.BigEndian.AppendUint16(body, 0xf000)
	body = binary.BigEndian.AppendUint16(body, downloadDataID)
	body = append(body, entries...)
	out, ok := appendMH(nil, si.TagMHLogoTransmission, body)
	if !ok {
		return nil
	}
	return out
}
