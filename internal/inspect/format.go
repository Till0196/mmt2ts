// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"encoding/hex"
	"fmt"
	"io"
	"sort"
)

func WriteReport(w io.Writer, report Report) {
	fmt.Fprintf(w, "bytes: %d\nTLV packets: %d (null: %d, invalid: %d)\nMMTP packets: %d\n",
		report.Bytes, report.TLVPackets, report.NullPackets, report.InvalidPackets, report.MMTPPackets)
	fmt.Fprintf(w, "MMTP headers: versions=%v FEC-types=%v packet-counter=%d\n",
		report.MMTPVersions, report.MMTPFECTypes, report.MMTPCounters)
	type flowCount struct {
		name  string
		count uint64
	}
	flows := make([]flowCount, 0, len(report.Flows))
	for name, count := range report.Flows {
		flows = append(flows, flowCount{name, count})
	}
	sort.Slice(flows, func(i, j int) bool { return flows[i].count > flows[j].count })
	fmt.Fprintln(w, "MMTP flows:")
	for i, flow := range flows {
		if i == 8 {
			break
		}
		fmt.Fprintf(w, "  %s  %d\n", flow.name, flow.count)
	}

	type pidCount struct {
		pid   AssetKey
		count uint64
	}
	counts := make([]pidCount, 0, len(report.PacketIDs))
	for pid, count := range report.PacketIDs {
		counts = append(counts, pidCount{pid, count})
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].count != counts[j].count {
			return counts[i].count > counts[j].count
		}
		return less(counts[i].pid, counts[j].pid)
	})
	fmt.Fprintln(w, "\nMMTP packet IDs:")
	for _, entry := range counts {
		fmt.Fprintf(w, "  %s  %d (RAP %d)\n", name(report, entry.pid), entry.count, report.RAPPackets[entry.pid])
	}
	fmt.Fprintln(w, "\nSignaling packet IDs (first payload bytes):")
	for _, pid := range sortedAssets(report.SignalingIDs) {
		first := report.FirstSignals[pid]
		if len(first) > 64 {
			first = first[:64]
		}
		fmt.Fprintf(w, "  %s  %d  %s\n", name(report, pid), report.SignalingIDs[pid], hex.EncodeToString(first))
	}

	fmt.Fprintf(w, "\nMPT snapshots: %d\n", len(report.MPTs))
	for _, mpt := range report.MPTs {
		fmt.Fprintf(w, "offset=%d service=0x%04x MPT_PID=0x%04x version=%d assets=%d\n",
			mpt.Offset, mpt.ServiceID, mpt.PacketID, mpt.Version, len(mpt.Assets))
		for _, asset := range mpt.Assets {
			tag := "-"
			if asset.ComponentTag != nil {
				tag = fmt.Sprintf("0x%04x", *asset.ComponentTag)
			}
			fmt.Fprintf(w, "  %-4s packet_id=0x%04x component_tag=%s", asset.Type, asset.PacketID, tag)
			if video := asset.Video; video != nil {
				fmt.Fprintf(w, " video={resolution=%d aspect=%d scan=%t frame_rate=%d transfer=%d lang=%s}",
					video.Resolution, video.AspectRatio, video.ScanFlag,
					video.FrameRate, video.Transfer, video.Language)
			}
			if audio := asset.Audio; audio != nil {
				fmt.Fprintf(w, " audio={content=%d type=0x%02x stream_type=0x%02x simulcast=0x%02x flags=0x%02x lang=%s}",
					audio.StreamContent, audio.ComponentType, audio.StreamType,
					audio.SimulcastGroupTag, audio.Flags, audio.Language)
			}
			if group := asset.Group; group != nil {
				fmt.Fprintf(w, " group={id=0x%02x selection=%d}", group.Identification, group.SelectionLevel)
			}
			if hierarchy := asset.Hierarchy; hierarchy != nil {
				fmt.Fprintf(w, " hierarchy={type=%d layer=%d embedded=%d channel=%d}",
					hierarchy.Type, hierarchy.LayerIndex, hierarchy.EmbeddedLayerIndex, hierarchy.Channel)
			}
			for _, d := range asset.Descriptors {
				fmt.Fprintf(w, " desc=0x%04x[%d]", d.Tag, len(d.Data))
			}
			fmt.Fprintln(w)
		}
	}
	writeTimingReport(w, report)
	writeExtendedTimingReport(w, report)
	writeAUValidation(w, report)
}

func writeAUValidation(w io.Writer, report Report) {
	fmt.Fprintln(w, "\nMFU-derived AU count versus extended timestamps:")
	for _, pid := range sortedAssets(report.AUValidation) {
		v := report.AUValidation[pid]
		fmt.Fprintf(w, "  %s MPUs expected=%d matched=%d mismatched=%d missing=%d extra_observed=%d AUs expected=%d observed=%d fragmented=%d aggregated=%d invalid_payload=%d\n",
			name(report, pid), v.ExpectedMPUs, v.MatchedMPUs, v.MismatchedMPUs, v.MissingMPUs, v.ExtraObservedMPUs,
			v.ExpectedAUs, v.ObservedAUs, v.FragmentedPayloads, v.AggregatedPayloads, v.InvalidPayloads)
		fmt.Fprintf(w, "    timed-header nonzero movie_fragment=%d sample=%d offset=%d priority=%d dependency=%d\n",
			v.NonzeroMovieFragment, v.NonzeroSample, v.NonzeroOffset, v.NonzeroPriority, v.NonzeroDependency)
		for _, example := range v.Examples {
			fmt.Fprintf(w, "    %s\n", example)
		}
	}
}

func writeExtendedTimingReport(w io.Writer, report Report) {
	fmt.Fprintln(w, "\nMPU extended timestamp descriptors:")
	for _, pid := range sortedAssets(report.ExtendedTiming) {
		stats := report.ExtendedTiming[pid]
		var scales []string
		for scale, count := range stats.Timescales {
			scales = append(scales, fmt.Sprintf("%d:%d", scale, count))
		}
		sort.Strings(scales)
		minPTS := "n/a"
		if stats.MinPTSInterval != ^uint16(0) {
			minPTS = fmt.Sprintf("%d", stats.MinPTSInterval)
		}
		fmt.Fprintf(w, "  %s descriptors=%d invalid=%d entries=%d matched=%d AUs=%d types=[%d,%d,%d,%d] timescales=%v dts_offset=%d..%d pts_interval=%s..%d leap=%d\n",
			name(report, pid), stats.Descriptors, stats.Invalid, stats.Entries, stats.TimestampMatched, stats.AccessUnits,
			stats.OffsetTypes[0], stats.OffsetTypes[1], stats.OffsetTypes[2], stats.OffsetTypes[3], scales,
			stats.MinDTSOffset, stats.MaxDTSOffset, minPTS, stats.MaxPTSInterval, stats.NonzeroLeap)
	}
}

func writeTimingReport(w io.Writer, report Report) {
	type timingSummary struct {
		pid    AssetKey
		points []MPUTiming
	}
	var summaries []timingSummary
	for pid, points := range report.Timings {
		if len(points) == 0 {
			continue
		}
		points = append([]MPUTiming(nil), points...)
		sort.Slice(points, func(i, j int) bool { return points[i].NTP < points[j].NTP })
		summaries = append(summaries, timingSummary{pid: pid, points: points})
	}
	sort.Slice(summaries, func(i, j int) bool { return less(summaries[i].pid, summaries[j].pid) })
	fmt.Fprintln(w, "\nMPU presentation timelines (NTP 32.32):")
	for _, summary := range summaries {
		points := summary.points
		first, last := points[0], points[len(points)-1]
		backward, duplicate, largeGap := sequenceTimeAnomalies(points)
		var maxGap uint64
		var gapFrom, gapTo uint32
		for i := 1; i < len(points); i++ {
			gap := points[i].NTP - points[i-1].NTP
			if gap > maxGap {
				maxGap, gapFrom, gapTo = gap, points[i-1].Sequence, points[i].Sequence
			}
			if gap > uint64(10)<<32 {
				largeGap++
			}
		}
		fmt.Fprintf(w, "  %s points=%d first_seq=%d last_seq=%d span=%.6fs backward=%d duplicate_time=%d gaps_gt_10s=%d max_gap=%.6fs(%d->%d)\n",
			name(report, summary.pid), len(points), first.Sequence, last.Sequence, ntpSeconds(last.NTP-first.NTP), backward, duplicate, largeGap,
			ntpSeconds(maxGap), gapFrom, gapTo)
	}
	if len(summaries) < 2 {
		return
	}
	base := summaries[0]
	for _, candidate := range summaries {
		if candidate.pid.PacketID == 0xf100 {
			base = candidate
			break
		}
	}
	fmt.Fprintf(w, "  overlapping nearest-boundary offsets relative to %s:\n", name(report, base.pid))
	for _, summary := range summaries {
		if summary.pid == base.pid {
			continue
		}
		deltas := overlappingDeltas(base.points, summary.points)
		if len(deltas) == 0 {
			fmt.Fprintf(w, "    %s no-overlap\n", name(report, summary.pid))
			continue
		}
		window := min(32, len(deltas)/2)
		startMean := meanDelta(deltas[:window])
		endMean := meanDelta(deltas[len(deltas)-window:])
		maxAbs := int64(0)
		for _, delta := range deltas {
			if delta < 0 {
				delta = -delta
			}
			if delta > maxAbs {
				maxAbs = delta
			}
		}
		fmt.Fprintf(w, "    %s overlap_points=%d start_mean=%+.6fs end_mean=%+.6fs boundary_drift=%+.6fs max_abs=%0.6fs\n",
			name(report, summary.pid), len(deltas), ntpSignedSeconds(startMean), ntpSignedSeconds(endMean),
			ntpSignedSeconds(endMean-startMean), ntpSignedSeconds(maxAbs))
	}
}

func sequenceTimeAnomalies(points []MPUTiming) (backward, duplicate, largeGap int) {
	bySequence := append([]MPUTiming(nil), points...)
	sort.Slice(bySequence, func(i, j int) bool { return bySequence[i].Sequence < bySequence[j].Sequence })
	for i := 1; i < len(bySequence); i++ {
		if bySequence[i].NTP < bySequence[i-1].NTP {
			backward++
		}
		if bySequence[i].NTP == bySequence[i-1].NTP {
			duplicate++
		}
	}
	return backward, duplicate, 0
}

func overlappingDeltas(base, candidate []MPUTiming) []int64 {
	if len(base) == 0 || len(candidate) == 0 {
		return nil
	}
	lo, hi := candidate[0].NTP, candidate[len(candidate)-1].NTP
	var out []int64
	for _, point := range base {
		if point.NTP >= lo && point.NTP <= hi {
			out = append(out, nearestNTPDelta(point.NTP, candidate))
		}
	}
	return out
}

func meanDelta(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	var sum int64
	for _, value := range values {
		sum += value
	}
	return sum / int64(len(values))
}

func nearestNTPDelta(value uint64, points []MPUTiming) int64 {
	i := sort.Search(len(points), func(i int) bool { return points[i].NTP >= value })
	if i == 0 {
		return int64(value - points[0].NTP)
	}
	if i == len(points) {
		return int64(value - points[len(points)-1].NTP)
	}
	a := int64(value - points[i-1].NTP)
	b := -int64(points[i].NTP - value)
	if a <= -b {
		return a
	}
	return b
}

func ntpSeconds(value uint64) float64      { return float64(value) / float64(uint64(1)<<32) }
func ntpSignedSeconds(value int64) float64 { return float64(value) / float64(uint64(1)<<32) }

func less(a, b AssetKey) bool {
	if a.Flow != b.Flow {
		return a.Flow < b.Flow
	}
	return a.PacketID < b.PacketID
}

func sortedAssets[V any](m map[AssetKey]V) []AssetKey {
	out := make([]AssetKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

func name(report Report, a AssetKey) string {
	if len(report.Flows) <= 1 {
		return fmt.Sprintf("0x%04x", a.PacketID)
	}
	return fmt.Sprintf("flow%d/0x%04x", a.Flow, a.PacketID)
}
