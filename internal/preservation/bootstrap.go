// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

type Role byte

const (
	RoleRealtime Role = 1
	RoleObject   Role = 2
)

func (r Role) String() string {
	switch r {
	case RoleRealtime:
		return "realtime"
	case RoleObject:
		return "object"
	}
	return fmt.Sprintf("role(%d)", byte(r))
}

const NoSegment = ^uint64(0)

const (
	bootstrapFixedLength = 46
	directoryEntryLength = 78
)

type DirectoryEntry struct {
	Role         Role
	Required     bool
	ModuleID     uint16
	Version      byte
	Kind         Kind
	PartNumber   uint16
	PartCount    uint16
	LogicalID    uint64
	StoredSize   uint32
	OriginalSize uint64
	ValidFrom    uint64
	ValidUntil   uint64
	SHA256       [32]byte
}

type Bootstrap struct {
	ServiceID         uint16
	TransportStreamID uint16
	OriginalNetworkID uint16
	EpochID           uint32
	Generation        uint32
	UpdateNumber      uint32
	SegmentDurationMS uint32
	LeadTimeMS        uint16
	PlayoutLimitMS    uint16
	RealtimeDownload  uint32
	ObjectDownload    uint32
	LatestComplete    uint64
	Entries           []DirectoryEntry
}

func sortEntries(entries []DirectoryEntry) {
	slices.SortStableFunc(entries, func(a, b DirectoryEntry) int {
		if a.Role != b.Role {
			return int(a.Role) - int(b.Role)
		}
		return int(a.ModuleID) - int(b.ModuleID)
	})
}

func (b *Bootstrap) Encode() ([]byte, error) {
	sortEntries(b.Entries)
	for i, e := range b.Entries {
		if e.Role != RoleRealtime && e.Role != RoleObject {
			return nil, fmt.Errorf("preservation: entry %d has invalid carousel role %d", i, e.Role)
		}
		if !e.Kind.valid() {
			return nil, fmt.Errorf("preservation: entry %d has invalid module kind %#02x", i, byte(e.Kind))
		}
		if e.Kind == KindBootstrapManifest {
			return nil, errors.New("preservation: the bootstrap must not list itself")
		}
		if e.PartCount == 0 || e.PartNumber >= e.PartCount {
			return nil, fmt.Errorf("preservation: entry %d has part %d of %d", i, e.PartNumber, e.PartCount)
		}
		if i > 0 && b.Entries[i-1].Role == e.Role && b.Entries[i-1].ModuleID == e.ModuleID {
			return nil, fmt.Errorf("preservation: duplicate %s module %#04x in the directory", e.Role, e.ModuleID)
		}
	}

	out := make([]byte, 0, bootstrapFixedLength+directoryEntryLength*len(b.Entries))
	out = binary.BigEndian.AppendUint16(out, b.ServiceID)
	out = binary.BigEndian.AppendUint16(out, b.TransportStreamID)
	out = binary.BigEndian.AppendUint16(out, b.OriginalNetworkID)
	out = binary.BigEndian.AppendUint32(out, b.EpochID)
	out = binary.BigEndian.AppendUint32(out, b.Generation)
	out = binary.BigEndian.AppendUint32(out, b.UpdateNumber)
	out = binary.BigEndian.AppendUint32(out, b.SegmentDurationMS)
	out = binary.BigEndian.AppendUint16(out, b.LeadTimeMS)
	out = binary.BigEndian.AppendUint16(out, b.PlayoutLimitMS)
	out = binary.BigEndian.AppendUint32(out, b.RealtimeDownload)
	out = binary.BigEndian.AppendUint32(out, b.ObjectDownload)
	out = binary.BigEndian.AppendUint64(out, b.LatestComplete)
	out = binary.BigEndian.AppendUint16(out, uint16(len(b.Entries)))
	out = binary.BigEndian.AppendUint16(out, 0)
	for _, e := range b.Entries {
		out = append(out, byte(e.Role), boolByte(e.Required))
		out = binary.BigEndian.AppendUint16(out, e.ModuleID)
		out = append(out, e.Version, byte(e.Kind))
		out = binary.BigEndian.AppendUint16(out, e.PartNumber)
		out = binary.BigEndian.AppendUint16(out, e.PartCount)
		out = binary.BigEndian.AppendUint64(out, e.LogicalID)
		out = binary.BigEndian.AppendUint32(out, e.StoredSize)
		out = binary.BigEndian.AppendUint64(out, e.OriginalSize)
		out = binary.BigEndian.AppendUint64(out, e.ValidFrom)
		out = binary.BigEndian.AppendUint64(out, e.ValidUntil)
		out = append(out, e.SHA256[:]...)
	}
	return out, nil
}

func ParseBootstrap(payload []byte) (*Bootstrap, error) {
	r := &reader{b: payload}
	b := &Bootstrap{
		ServiceID:         r.u16(),
		TransportStreamID: r.u16(),
		OriginalNetworkID: r.u16(),
		EpochID:           r.u32(),
		Generation:        r.u32(),
		UpdateNumber:      r.u32(),
		SegmentDurationMS: r.u32(),
		LeadTimeMS:        r.u16(),
		PlayoutLimitMS:    r.u16(),
		RealtimeDownload:  r.u32(),
		ObjectDownload:    r.u32(),
		LatestComplete:    r.u64(),
	}
	count := int(r.u16())
	r.skip(2)
	if r.err != nil {
		return nil, r.err
	}
	b.Entries = make([]DirectoryEntry, 0, count)
	for range count {
		e := DirectoryEntry{Role: Role(r.u8())}
		e.Required = r.u8() != 0
		e.ModuleID = r.u16()
		e.Version = r.u8()
		e.Kind = Kind(r.u8())
		e.PartNumber = r.u16()
		e.PartCount = r.u16()
		e.LogicalID = r.u64()
		e.StoredSize = r.u32()
		e.OriginalSize = r.u64()
		e.ValidFrom = r.u64()
		e.ValidUntil = r.u64()
		e.SHA256 = r.sha256()
		b.Entries = append(b.Entries, e)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	for i := 1; i < len(b.Entries); i++ {
		p, e := b.Entries[i-1], b.Entries[i]
		if p.Role > e.Role || (p.Role == e.Role && p.ModuleID >= e.ModuleID) {
			return nil, errors.New("preservation: bootstrap directory is not in role and module id order")
		}
	}
	return b, nil
}

func (e DirectoryEntry) Valid(ntp uint64) bool {
	if ntp < e.ValidFrom {
		return false
	}
	return e.ValidUntil == 0 || ntp < e.ValidUntil
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}
