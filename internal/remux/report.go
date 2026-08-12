// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"mmt2ts/internal/caption"
	"mmt2ts/internal/mpu"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/remux/appdata"
	"mmt2ts/internal/si"
	"mmt2ts/internal/siconv"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/tlv"
)

type StreamStat struct {
	ServiceID          uint16
	AssetType          string
	PacketID           uint16
	PID                uint16
	MMTTag             uint16
	TSTag              byte
	StreamType         byte
	Language           string
	AUsIn              uint64
	AUsOut             uint64
	LossEvents         uint64
	LostPacketsCarried uint64
	AUsNoTiming        uint64
	AUsWaitIRAP        uint64
	AUsAfterLoss       uint64
	AUsDroppedAtEnd    uint64
	AUsCodecError      uint64
	BytesOut           uint64
	FirstDTS           int64
	LastDTS            int64
	HaveDTS            bool
	DTSBackwards       uint64
	DTSGaps            uint64
	MaxGap90k          int64
	Discontinuity      uint64
	PacketIDMoves      uint64
	StreamTypeChanges  uint64
	MPUsSenderClock    uint64
	MPUsDeclared       uint64
	MPUsChecked        uint64
	MPUsAUMatch        uint64
	MPUsAUDiffer       uint64
	MPUsUntrusted      uint64
	UnitsNoAUStart     uint64
	UnitsDiscarded     uint64
	ScrambledPackets   uint64
	InPMT              bool
}

type UnconvertedAsset struct {
	ServiceID uint16
	Type      string
	PacketID  uint16
	Tag       uint16
	HasTag    bool
	Payloads  uint64
	Bytes     uint64
	key       string
	idScheme  uint32
	assetID   []byte
}

type ProgramStat struct {
	ServiceID uint16
	PMTPID    uint16
	PCRPID    uint16
	Streams   int
}

type SIStateStat struct {
	NIT, SDT, EIT, BIT, CDT, AIT int
}

type SITableStat struct {
	Name     string
	PID      uint16
	Sections int
	Sent     uint64
}

type CaptionStat struct {
	ServiceID       uint16
	PID             uint16
	MMTTag          uint16
	Language        string
	Superimposition bool
	TMD             byte
	DMF             byte
	Stats           caption.StreamStats
}

type Report struct {
	TLV       tlv.Stats
	Signaling signaling.Stats
	MPU       mpu.Stats

	InputBytes           uint64
	MMTPPackets          uint64
	NTPPackets           uint64
	MMTPParseErrors      uint64
	UnroutedPackets      uint64
	UnannouncedSignaling uint64
	RepairPackets        uint64
	OtherPayloads        uint64
	AssetDecodeOrder     []string
	AssetGraphIssues     []string
	Flows                int
	Programs             []ProgramStat

	TSPackets   uint64
	TSBytes     uint64
	PATSections uint64
	PMTSections uint64
	PCROnly     uint64
	NullPackets uint64
	PMTVersions uint64

	Carousel            preservation.Stats
	CarouselRealtimePID uint16
	CarouselObjectPID   uint16

	SITables      []SITableStat
	SITableIDs    map[byte]uint64
	SITableErrors map[byte]uint64
	SIState       SIStateStat
	SI            si.Stats
	SIText        siconv.TextStats
	SIDescriptors map[siconv.TagKey]*siconv.TagStat
	SIDiagnostics []string

	Descriptors   []DescriptorStat
	Captions      []CaptionStat
	App           appdata.Stats
	AppItems      []*appdata.Item
	AppReferences []appdata.Reference
	MPTUpdates    uint64
	ServiceID     uint16
	Streams       []StreamStat
	Unconverted   []UnconvertedAsset

	DurationOut90k int64
	ReorderDrops   uint64
	QueuePeak      int
}

func WriteReport(w io.Writer, r Report) {
	fmt.Fprintf(w, "input: %d bytes, %d TLV packets (%d null, %d resync, %d truncated)\n",
		r.TLV.Bytes, r.TLV.Packets, r.TLV.NullPackets, r.TLV.Resyncs, r.TLV.TruncatedPackets)
	fmt.Fprintf(w, "  IP: v4=%d v6=%d compressed-v4=%d compressed-v6=%d control=%d non-UDP=%d malformed=%d fragments=%d reassembled=%d fragment-errors=%d\n",
		r.TLV.IPv4Packets, r.TLV.IPv6Packets, r.TLV.CompressedIPv4, r.TLV.CompressedIPv6,
		r.TLV.ControlPackets, r.TLV.NonUDPPackets, r.TLV.MalformedIP, r.TLV.FragmentPackets,
		r.TLV.ReassembledIP, r.TLV.FragmentErrors)
	if len(r.TLV.UnknownType) > 0 || len(r.TLV.UnknownCIDHeader) > 0 {
		fmt.Fprintf(w, "  unhandled TLV types: %v, compressed header types: %v\n",
			r.TLV.UnknownType, r.TLV.UnknownCIDHeader)
	}
	fmt.Fprintf(w, "MMTP: %d packets, NTP %d, parse errors %d, unrouted %d, FEC repair %d, other payload %d\n",
		r.MMTPPackets, r.NTPPackets, r.MMTPParseErrors, r.UnroutedPackets, r.RepairPackets, r.OtherPayloads)
	if len(r.AssetDecodeOrder) > 0 || len(r.AssetGraphIssues) > 0 {
		fmt.Fprintf(w, "asset dependency decode order: %v, issues: %v\n", r.AssetDecodeOrder, r.AssetGraphIssues)
	}
	fmt.Fprintf(w, "signaling on packet ids the PLT did not announce: %d\n", r.UnannouncedSignaling)
	fmt.Fprintf(w, "signaling: %d messages, %d tables, malformed %d, dropped fragments %d, unknown %v\n",
		r.Signaling.Messages, r.Signaling.Tables, r.Signaling.MalformedTables,
		r.Signaling.DroppedFragments, r.Signaling.UnknownTables)
	fmt.Fprintf(w, "MPU: payloads %d, data units %d, sequence gaps %d (%d packets), out of order %d, fragment errors %d\n",
		r.MPU.Payloads, r.MPU.Units, r.MPU.SequenceGaps, r.MPU.LostPackets,
		r.MPU.OutOfOrderPackets, r.MPU.FragmentErrors)
	fmt.Fprintf(w, "  metadata fragments %d, non-timed units %d, parse errors %d, scrambled packets %d\n",
		r.MPU.MetadataFragments, r.MPU.NonTimedUnits, r.MPU.ParseErrors, r.MPU.ScrambledPackets)
	var carried uint64
	for _, s := range r.Streams {
		carried += s.LostPacketsCarried
	}
	if r.MPU.LostPackets > 0 || carried > 0 {
		fmt.Fprintf(w, "  input drops: %d MMTP packet(s) lost, %d carried into continuity counters\n",
			r.MPU.LostPackets, carried)
	}
	fmt.Fprintf(w, "  transport MFU header non-zero: movie fragments %d, sample numbers %d, offsets %d, priorities %d, dependencies %d\n",
		r.MPU.NonZeroMovieFragments, r.MPU.NonZeroSamples, r.MPU.NonZeroOffsets,
		r.MPU.NonZeroPriorities, r.MPU.NonZeroDependencies)

	writeSIReport(w, r)

	fmt.Fprintf(w, "\nservice_id: %#04x, MPT updates: %d, PMT versions: %d\n", r.ServiceID, r.MPTUpdates, r.PMTVersions)
	if len(r.Programs) > 1 {
		fmt.Fprintf(w, "programs: %d, on %d IP data flow(s)\n", len(r.Programs), r.Flows)
		for _, p := range r.Programs {
			fmt.Fprintf(w, "  service %#04x: PMT PID %#04x, PCR PID %#04x, %d elementary stream(s)\n",
				p.ServiceID, p.PMTPID, p.PCRPID, p.Streams)
		}
	}
	fmt.Fprintf(w, "output: %d TS packets (%d bytes), PAT %d, PMT %d, PCR-only %d, null %d\n",
		r.TSPackets, r.TSBytes, r.PATSections, r.PMTSections, r.PCROnly, r.NullPackets)
	if r.DurationOut90k > 0 {
		fmt.Fprintf(w, "output timeline: %.3f s\n", float64(r.DurationOut90k)/90000)
	}
	writeCarouselReport(w, r)
	writeEncryptedReport(w, r)

	fmt.Fprintln(w, "\nelementary streams:")
	fmt.Fprintln(w, " service   PID  type  stream  mmt_tag ts_tag lang    AUs in     out       losses no-timing wait-IRAP  gaps")
	streams := append([]StreamStat(nil), r.Streams...)
	sort.Slice(streams, func(i, j int) bool { return streams[i].PID < streams[j].PID })
	for _, s := range streams {
		lang := s.Language
		if lang == "" {
			lang = "-"
		}
		fmt.Fprintf(w, "  %#04x  %04x  %-4s  %#04x   %#06x  %#04x  %-4s %9d %9d %10d %9d %9d %5d\n",
			s.ServiceID, s.PID, s.AssetType, s.StreamType, s.MMTTag, s.TSTag, lang,
			s.AUsIn, s.AUsOut, s.LossEvents, s.AUsNoTiming, s.AUsWaitIRAP, s.DTSGaps)
	}
	for _, s := range streams {
		if !s.HaveDTS {
			continue
		}
		fmt.Fprintf(w, "  %04x span %.3f s, largest DTS gap %.3f s, backwards %d, discontinuities %d, packet_id changes %d\n",
			s.PID, float64(s.LastDTS-s.FirstDTS)/90000, float64(s.MaxGap90k)/90000,
			s.DTSBackwards, s.Discontinuity, s.PacketIDMoves)
		if s.StreamTypeChanges > 0 {
			fmt.Fprintf(w, "  %04x stream type changed %d times; it is now %#04x and the PMT follows it\n",
				s.PID, s.StreamTypeChanges, s.StreamType)
		}
	}
	for _, s := range streams {
		if s.MPUsSenderClock > 0 {
			fmt.Fprintf(w, "  %04x %d MPUs had no MPU timestamp descriptor and were placed by the sender clock\n",
				s.PID, s.MPUsSenderClock)
		}
	}
	fmt.Fprintln(w, "\nMPU access unit count against num_of_au:")
	for _, s := range streams {
		if s.MPUsChecked == 0 && s.MPUsUntrusted == 0 {
			continue
		}
		rate := 100.0
		if s.MPUsChecked > 0 {
			rate = 100 * float64(s.MPUsAUMatch) / float64(s.MPUsChecked)
		}
		delivered := s.MPUsChecked + s.MPUsUntrusted
		fmt.Fprintf(w, "  %04x declared %d, delivered %d, checked %d, matched %d (%.1f%%), differed %d, untrusted %d\n",
			s.PID, s.MPUsDeclared, delivered, s.MPUsChecked, s.MPUsAUMatch, rate, s.MPUsAUDiffer, s.MPUsUntrusted)
		if s.AUsDroppedAtEnd > 0 {
			fmt.Fprintf(w, "       incomplete access unit discarded at end of input %d\n", s.AUsDroppedAtEnd)
		}
		if s.AUsAfterLoss > 0 {
			fmt.Fprintf(w, "       written before a random access point after a loss %d\n", s.AUsAfterLoss)
		}
		if s.UnitsNoAUStart+s.UnitsDiscarded > 0 {
			fmt.Fprintf(w, "       units without an AU start %d, units discarded after loss %d\n",
				s.UnitsNoAUStart, s.UnitsDiscarded)
		}
	}
	if len(r.Unconverted) > 0 {
		fmt.Fprintln(w, "\nassets kept out of the transport stream (no lossless TS mapping yet):")
		for _, a := range r.Unconverted {
			fmt.Fprintf(w, "  %s packet_id=%#04x tag=%#06x payloads=%d bytes=%d\n",
				a.Type, a.PacketID, a.Tag, a.Payloads, a.Bytes)
		}
	}
	writeCaptionReport(w, r)
	writeAppReport(w, r)
	writeDescriptorReport(w, r)
	if r.ReorderDrops > 0 {
		fmt.Fprintf(w, "\nreorder window overflow: %d access units\n", r.ReorderDrops)
	}
}

func writeSIReport(w io.Writer, r Report) {
	fmt.Fprintf(w, "\nMMT-SI: %d messages, %d sections (%d short), CRC errors %d, truncated %d\n",
		r.SI.Messages, r.SI.Sections, r.SI.ShortSections, r.SI.CRCErrors, r.SI.Truncated)
	fmt.Fprintf(w, "  complete tables %d, incomplete versions %d, next-version sections %d, duplicate mismatches %d\n",
		r.SI.CompletedTables, r.SI.IncompleteTables, r.SI.NotCurrent, r.SI.DuplicateMismatch)
	fmt.Fprintf(w, "  current tables: TLV-NIT %d, MH-SDT %d, MH-EIT sections %d, MH-BIT %d, MH-CDT %d, MH-AIT %d\n",
		r.SIState.NIT, r.SIState.SDT, r.SIState.EIT, r.SIState.BIT, r.SIState.CDT, r.SIState.AIT)
	if len(r.SITableIDs) > 0 {
		ids := make([]int, 0, len(r.SITableIDs))
		for id := range r.SITableIDs {
			ids = append(ids, int(id))
		}
		sort.Ints(ids)
		fmt.Fprint(w, "  received table ids:")
		for _, id := range ids {
			fmt.Fprintf(w, " %#02x=%d", id, r.SITableIDs[byte(id)])
			if n := r.SITableErrors[byte(id)]; n > 0 {
				fmt.Fprintf(w, "(%d unparsed)", n)
			}
		}
		fmt.Fprintln(w)
	}
	if len(r.SI.UnknownTables) > 0 || len(r.SI.UnknownMessages) > 0 {
		fmt.Fprintf(w, "  tables with no decoder: %v, messages with no decoder: %v\n",
			r.SI.UnknownTables, r.SI.UnknownMessages)
	}

	if len(r.SITables) > 0 {
		fmt.Fprintln(w, "\ngenerated SI:")
		for _, t := range r.SITables {
			fmt.Fprintf(w, "  %-12s PID %04x  %d sections, sent %d times\n", t.Name, t.PID, t.Sections, t.Sent)
		}
	}
	for _, d := range r.SIDiagnostics {
		fmt.Fprintf(w, "  note: %s\n", d)
	}

	if len(r.SIDescriptors) > 0 {
		keys := make([]siconv.TagKey, 0, len(r.SIDescriptors))
		for k := range r.SIDescriptors {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].TLV != keys[j].TLV {
				return !keys[i].TLV
			}
			return keys[i].Tag < keys[j].Tag
		})
		fmt.Fprintln(w, "\nSI descriptors:")
		for _, k := range keys {
			s := r.SIDescriptors[k]
			space := "MH"
			if k.TLV {
				space = "TLV"
			}
			fmt.Fprintf(w, "  %-3s %#06x converted %d, unsupported %d, invalid %d",
				space, k.Tag, s.Converted, s.Unsupported, s.Invalid)
			if s.Reason != "" {
				fmt.Fprintf(w, " (%s)", s.Reason)
			}
			fmt.Fprintln(w)
		}
	}

	t := r.SIText
	if t.Strings == 0 {
		return
	}
	fmt.Fprintf(w, "\nSI text: %d strings, %d characters, standard %d, normalized %d, substituted %d, DRCS %d, unconvertible %d\n",
		t.Strings, t.Scalars, t.Standard, t.Normalized, t.Substituted, t.DRCS, t.Unconvertible)
	if t.Truncated > 0 {
		fmt.Fprintf(w, "  shortened to fit a descriptor: %d strings, %d characters removed\n", t.Truncated, t.Dropped)
	}
	if len(t.Samples) > 0 {
		fmt.Fprintf(w, "  characters with no encoding: %q\n", string(t.Samples))
	}
}

func writeCaptionReport(w io.Writer, r Report) {
	if len(r.Captions) == 0 {
		return
	}
	fmt.Fprintln(w, "\ncaptions:")
	for _, c := range r.Captions {
		kind := "caption"
		if c.Superimposition {
			kind = "superimposition"
		}
		s := c.Stats
		fmt.Fprintf(w, "  %04x %-15s lang %s TMD %#x DMF %#x: MPUs %d, documents %d, statements %d, management %d\n",
			c.PID, kind, c.Language, c.TMD, c.DMF, s.MPUs, s.Documents, s.Statements, s.ManagementSent)
		fmt.Fprintf(w, "       cues %d (%d without a presentation time), parse errors %d, incomplete MPUs %d\n",
			s.Cues, s.CuesWithoutTime, s.ParseErrors, s.IncompleteMPUs)
		if s.CuesWithoutEnd > 0 {
			fmt.Fprintf(w, "       %d cues carry no end time and rely on a later document to clear them\n",
				s.CuesWithoutEnd)
		}
		ch := s.Writer.Characters
		fmt.Fprintf(w, "       characters: standard %d, normalized %d, substituted %d, DRCS %d, unconvertible %d\n",
			ch[0], ch[1], ch[2], ch[3], ch[4])
		if len(s.Writer.Samples) > 0 {
			fmt.Fprintf(w, "       characters with no encoding: %q\n", string(s.Writer.Samples))
		}
		if len(s.Resources) > 0 {
			fmt.Fprintf(w, "       external resources not converted: %v (%d bytes)\n", s.Resources, s.ResourceBytes)
		}
		for what, n := range s.Unsupported {
			fmt.Fprintf(w, "       unsupported: %s (%d)\n", what, n)
		}
		for what, n := range s.Writer.Unsupported {
			fmt.Fprintf(w, "       unsupported: %s (%d)\n", what, n)
		}
	}
}

func writeAppReport(w io.Writer, r Report) {
	a := r.App
	if a.ItemPayloads == 0 && a.AITSections == 0 && a.DAMTSections == 0 {
		return
	}
	fmt.Fprintf(w, "\napplications and data: MH-AIT %d, DAMT %d, DDMT %d, DCCT %d, EMT %d sections\n",
		a.AITSections, a.DAMTSections, a.DDMTSections, a.DCCTSections, a.EMTSections)
	fmt.Fprintf(w, "  items: %d payloads (%d bytes), announced %d, complete %d, partial %d, never announced %d\n",
		a.ItemPayloads, a.ItemBytes, a.ItemsAnnounced, a.ItemsComplete, a.ItemsPartial, a.ItemsUnknown)
	if a.IndexItems > 0 || a.IndexItemErrors > 0 {
		fmt.Fprintf(w, "  index items: read %d, unparsed %d\n", a.IndexItems, a.IndexItemErrors)
	}
	fmt.Fprintf(w, "  checksums: verified %d, mismatched %d, not declared or incomplete %d\n",
		a.ChecksumOK, a.ChecksumBad, a.ChecksumNone)
	if len(a.ParseErrors) > 0 || len(a.UnknownTables) > 0 {
		fmt.Fprintf(w, "  parse errors %v, tables with no decoder %v\n", a.ParseErrors, a.UnknownTables)
	}
	for _, ref := range r.AppReferences {
		if ref.Resolved {
			if ref.Reason != "" {
				fmt.Fprintf(w, "  application %s -> %s (%s)\n", ref.Application, ref.Target, ref.Reason)
				continue
			}
			fmt.Fprintf(w, "  application %s -> %s\n", ref.Application, ref.Target)
			continue
		}
		fmt.Fprintf(w, "  application %s -> %s unresolved: %s\n", ref.Application, ref.Target, ref.Reason)
	}
	shown := 0
	for _, it := range r.AppItems {
		if shown >= 16 {
			fmt.Fprintf(w, "  ... %d more items\n", len(r.AppItems)-shown)
			break
		}
		state := "complete"
		if !it.Announced {
			state = "not announced by any DAM table"
		} else if !it.Complete() {
			state = fmt.Sprintf("partial, %d of %d bytes", it.Received, it.Size)
		}
		name := itemDisplayName(it.Path + it.Name)
		compression := ""
		if it.Announced && it.Compression != 0xff && it.OriginalSize > 0 {
			compression = fmt.Sprintf(", compressed (type %d, %d bytes uncompressed)", it.Compression, it.OriginalSize)
		}
		fmt.Fprintf(w, "  item %08x %-24s %s, %d repeats%s\n", it.ID, name, state, it.Repeats, compression)
		shown++
	}
}

const itemNameLimit = 48

// itemDisplayName は放送から得たitem名を1行に収める。名前は入力そのものなので、
// 改行や制御文字がレポートの行構造を壊さないようにする。
func itemDisplayName(name string) string {
	if name == "" {
		return "(unnamed)"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r == '\t' || r == ' ':
			b.WriteByte(' ')
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			b.WriteByte('.')
		}
	}
	out := b.String()
	if utf8.RuneCountInString(out) > itemNameLimit {
		runes := []rune(out)
		out = string(runes[:itemNameLimit-1]) + "…"
	}
	return out
}

func writeDescriptorReport(w io.Writer, r Report) {
	if len(r.Descriptors) == 0 {
		return
	}
	list := append([]DescriptorStat(nil), r.Descriptors...)
	sort.Slice(list, func(i, j int) bool { return list[i].Tag < list[j].Tag })
	fmt.Fprintln(w, "\nMPT descriptors:")
	for _, d := range list {
		fmt.Fprintf(w, "  %#06x x%-5d %-9s %s\n", d.Tag, d.Count, d.Disposition, d.Note)
	}
}

func writeCarouselReport(w io.Writer, r Report) {
	if r.CarouselRealtimePID == 0 && r.CarouselObjectPID == 0 {
		fmt.Fprintln(w, "preservation carousel: disabled")
		return
	}
	c := r.Carousel
	fmt.Fprintf(w, "preservation carousel: realtime PID %#04x (%d modules), object PID %#04x (%d modules), %d bytes\n",
		r.CarouselRealtimePID, c.RealtimeModule, r.CarouselObjectPID, c.ObjectModule, c.CarouselBytes)
	fmt.Fprintf(w, "  segments %d, records %d, AV map entries %d, codec configs %d, losses %d\n",
		c.Segments, c.Records, c.AVMapEntries, c.CodecConfigs, c.LossEntries)
	window := "profile default"
	if c.ShortSegments {
		window = "shortened for the preserved bitrate"
	}
	fmt.Fprintf(w, "  time window %d ms (%s), windows sent once %d\n", c.SegmentDurationMS, window, c.BulkSegments)
	fmt.Fprintf(w, "  objects %d (%d bytes), commits %d\n", c.Objects, c.ObjectBytes, c.Commits)
	fmt.Fprintf(w, "  sections: realtime DII %d / DDB %d, object DII %d / DDB %d\n",
		c.RealtimeDII, c.RealtimeDDB, c.ObjectDII, c.ObjectDDB)
}

func writeEncryptedReport(w io.Writer, r Report) {
	var encrypted, withheld []StreamStat
	for _, s := range r.Streams {
		if s.ScrambledPackets > 0 {
			encrypted = append(encrypted, s)
		}
		if !s.InPMT {
			withheld = append(withheld, s)
		}
	}
	if len(encrypted) == 0 && len(withheld) == 0 {
		return
	}
	fmt.Fprintln(w, "\nencrypted assets:")
	for _, s := range encrypted {
		fmt.Fprintf(w, "  packet_id %#04x %s: %d encrypted packets preserved in the carousel\n",
			s.PacketID, s.AssetType, s.ScrambledPackets)
	}
	for _, s := range withheld {
		fmt.Fprintf(w, "  packet_id %#04x %s: no clear PES was produced, so it is not in the PMT\n",
			s.PacketID, s.AssetType)
	}
}
