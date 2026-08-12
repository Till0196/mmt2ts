// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"mmt2ts/internal/si"
	"mmt2ts/internal/signaling"
)

type Disposition int

const (
	DispositionConverted Disposition = iota
	DispositionUsed
	DispositionPreserved
	DispositionMissing
)

func (d Disposition) String() string {
	switch d {
	case DispositionConverted:
		return "converted"
	case DispositionUsed:
		return "used"
	case DispositionPreserved:
		return "preserved"
	default:
		return "missing"
	}
}

type DescriptorStat struct {
	Tag         uint16
	Count       uint64
	Disposition Disposition
	Note        string
}

func assetDescriptorDisposition(tag uint16) (Disposition, string) {
	switch tag {
	case signaling.TagMPUTimestamp, signaling.TagMPUExtendedTimestamp:
		return DispositionUsed, "presentation and decoding times of the output"
	case signaling.TagStreamIdentifier:
		return DispositionConverted, "PMT stream identifier descriptor"
	case si.TagMHAudioComponent:
		return DispositionConverted, "PMT audio component descriptor"
	case si.TagMHDataComponent:
		return DispositionConverted, "PMT data component descriptor of the caption stream"
	case si.TagVideoComponent:
		return DispositionConverted, "PMT and SI component descriptor"
	case si.TagContentCopyControl:
		return DispositionConverted, "digital copy control descriptor, with the same values"
	case si.TagContentUsageControl:
		return DispositionPreserved, "no transport stream descriptor carries remote viewing or retention control"
	case si.TagMHEmergencyInformation:
		return DispositionPreserved, "emergency signalling is reported with its raw values, never re-derived"
	case si.TagEmergencyNews:
		return DispositionPreserved, "emergency news has no transport stream equivalent"
	case signaling.TagAssetGroup:
		return DispositionPreserved, "hierarchical transmission grouping has no PMT equivalent"
	case signaling.TagMHHierarchy:
		return DispositionPreserved, "layer dependencies cannot be expressed by a PMT alone"
	case signaling.TagDependency:
		return DispositionPreserved, "asset dependency graph has no PMT equivalent"
	case si.TagMHHEVCVideo:
		return DispositionPreserved, "the HEVC descriptor is not copied without checking it against the bitstream"
	case si.TagMHMPEG4Audio, si.TagMHMPEG4AudioExtension:
		return DispositionPreserved, "the audio configuration is taken from the LATM stream itself"
	case si.TagApplicationService:
		return DispositionPreserved, "application services are carried by the restoration carousel, not as a broadcast data service"
	case accessControlTag:
		return DispositionPreserved, "CA signalling is never synthesised for an output that carries no ECM"
	default:
		return DispositionPreserved, "no converter for this tag"
	}
}

const accessControlTag = 0x8004

func (c *converter) noteDescriptors(list []signaling.Descriptor) {
	if c.descriptors == nil {
		c.descriptors = make(map[uint16]*DescriptorStat)
	}
	for _, d := range list {
		st := c.descriptors[d.Tag]
		if st == nil {
			disposition, note := assetDescriptorDisposition(d.Tag)
			st = &DescriptorStat{Tag: d.Tag, Disposition: disposition, Note: note}
			c.descriptors[d.Tag] = st
		}
		st.Count++
	}
}
