// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
)

type ObjectClass byte

const (
	ClassApplicationItem ObjectClass = 1
	ClassTTML            ObjectClass = 2
	ClassImage           ObjectClass = 3
	ClassFont            ObjectClass = 4
	ClassAudio           ObjectClass = 5
	ClassGenericAsset    ObjectClass = 6
	ClassRawSignalling   ObjectClass = 7
)

func (c ObjectClass) valid() bool { return c >= ClassApplicationItem && c <= ClassRawSignalling }

const (
	ObjectRequired   = 0x01
	ObjectIncomplete = 0x02
	ObjectRawExact   = 0x04

	definedObjectFlags = ObjectRequired | ObjectIncomplete | ObjectRawExact
)

const (
	CompressionNone = 0
	CompressionZlib = 1
)

type ObjectPart struct {
	ModuleID      uint16
	ModuleVersion byte
	PartNumber    uint16
	Offset        uint32
	StoredLength  uint32
	StoredSHA256  [32]byte
}

type ManifestObject struct {
	ID             uint64
	Class          ObjectClass
	Flags          byte
	Compression    byte
	Path           string
	MediaType      string
	Metadata       Metadata
	OriginalSize   uint64
	OriginalSHA256 [32]byte
	Parts          []ObjectPart
}

type Manifest struct {
	Generation   uint32
	UpdateNumber uint32
	Objects      []ManifestObject
}

type PackedModule struct {
	ID      uint16
	Payload []byte
	SHA256  [32]byte
}

type PackInput struct {
	ID             uint64
	Class          ObjectClass
	Flags          byte
	Compression    byte
	Path           string
	MediaType      string
	Metadata       Metadata
	OriginalSize   uint64
	OriginalSHA256 [32]byte
	Stored         []byte
	StoredSHA256   [32]byte
	haveStored     bool
}

func (o *PackInput) storedDigest() [32]byte {
	if !o.haveStored {
		o.StoredSHA256, o.haveStored = sha256.Sum256(o.Stored), true
	}
	return o.StoredSHA256
}

func PackObjects(in []PackInput, firstModuleID uint16, maxModules int) ([]PackedModule, *Manifest, error) {
	in = slices.Clone(in)
	slices.SortStableFunc(in, func(a, b PackInput) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})

	const capacity = MaxModuleSize - HeaderLength
	var (
		modules    []PackedModule
		manifest   = &Manifest{}
		current    []byte
		partsHere  int
		lastDigest [32]byte
	)
	moduleID := func() uint16 { return firstModuleID + uint16(len(modules)) }
	closeModule := func() {
		m := PackedModule{ID: moduleID(), Payload: current}
		if partsHere == 1 {
			m.SHA256 = lastDigest
		} else {
			m.SHA256 = sha256.Sum256(current)
		}
		modules = append(modules, m)
		current, partsHere = nil, 0
	}

	for _, o := range in {
		if err := ValidatePath(o.Path); err != nil {
			return nil, nil, err
		}
		mo := ManifestObject{
			ID: o.ID, Class: o.Class, Flags: o.Flags, Compression: o.Compression,
			Path: o.Path, MediaType: o.MediaType, Metadata: o.Metadata,
			OriginalSize: o.OriginalSize, OriginalSHA256: o.OriginalSHA256,
		}
		rest := o.Stored
		for {
			if len(current) == capacity {
				closeModule()
			}
			room := capacity - len(current)
			n := min(room, len(rest))
			part := ObjectPart{
				ModuleID:     moduleID(),
				PartNumber:   uint16(len(mo.Parts)),
				Offset:       uint32(len(current)),
				StoredLength: uint32(n),
			}
			if o.haveStored && n == len(o.Stored) {
				part.StoredSHA256 = o.StoredSHA256
			} else {
				part.StoredSHA256 = sha256.Sum256(rest[:n])
			}
			mo.Parts = append(mo.Parts, part)
			lastDigest, partsHere = part.StoredSHA256, partsHere+1
			current = append(current, rest[:n]...)
			rest = rest[n:]
			if len(rest) == 0 {
				break
			}
			closeModule()
		}
		if len(mo.Parts) > 0xffff {
			return nil, nil, fmt.Errorf("%w: object %d needs %d parts", ErrCapacityExceeded, o.ID, len(mo.Parts))
		}
		manifest.Objects = append(manifest.Objects, mo)
	}
	if len(current) > 0 {
		closeModule()
	}
	if len(modules) > maxModules {
		return nil, nil, fmt.Errorf("%w: %d static object modules, room for %d", ErrCapacityExceeded, len(modules), maxModules)
	}
	return modules, manifest, nil
}

func (m *Manifest) SetModuleVersion(moduleID uint16, version byte) {
	for i := range m.Objects {
		for j := range m.Objects[i].Parts {
			if m.Objects[i].Parts[j].ModuleID == moduleID {
				m.Objects[i].Parts[j].ModuleVersion = version
			}
		}
	}
}

func ValidatePath(p string) error {
	if p == "" {
		return nil
	}
	if strings.ContainsRune(p, 0) {
		return errors.New("preservation: object path contains NUL")
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return fmt.Errorf("preservation: object path %q is absolute", p)
	}
	if len(p) >= 2 && p[1] == ':' {
		return fmt.Errorf("preservation: object path %q has a drive prefix", p)
	}
	for _, e := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if e == ".." {
			return fmt.Errorf("preservation: object path %q traverses out of the origin", p)
		}
	}
	return nil
}

func (m *Manifest) Encode() ([]byte, error) {
	slices.SortStableFunc(m.Objects, func(a, b ManifestObject) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})
	out := binary.BigEndian.AppendUint32(nil, m.Generation)
	out = binary.BigEndian.AppendUint32(out, m.UpdateNumber)
	out = binary.BigEndian.AppendUint32(out, uint32(len(m.Objects)))
	for i := range m.Objects {
		o := &m.Objects[i]
		if !o.Class.valid() {
			return nil, fmt.Errorf("preservation: object %d has invalid class %d", o.ID, o.Class)
		}
		if o.Flags&^definedObjectFlags != 0 {
			return nil, fmt.Errorf("preservation: object %d has undefined flags %#02x", o.ID, o.Flags)
		}
		if o.Compression != CompressionNone && o.Compression != CompressionZlib {
			return nil, fmt.Errorf("preservation: object %d uses compression %d", o.ID, o.Compression)
		}
		if err := ValidatePath(o.Path); err != nil {
			return nil, err
		}
		if i > 0 && m.Objects[i-1].ID == o.ID {
			return nil, fmt.Errorf("preservation: duplicate object id %d", o.ID)
		}
		slices.SortStableFunc(o.Parts, func(a, b ObjectPart) int { return int(a.PartNumber) - int(b.PartNumber) })
		if len(o.Parts) == 0 {
			return nil, fmt.Errorf("preservation: object %d has no parts", o.ID)
		}
		for n, p := range o.Parts {
			if int(p.PartNumber) != n {
				return nil, fmt.Errorf("preservation: object %d part numbers are not consecutive from zero", o.ID)
			}
		}
		meta, err := o.Metadata.encode()
		if err != nil {
			return nil, err
		}
		if len(o.Path) > 0xffff || len(o.MediaType) > 0xffff || len(meta) > 0xffff || len(o.Parts) > 0xffff {
			return nil, fmt.Errorf("preservation: object %d has a field that does not fit its length", o.ID)
		}

		out = binary.BigEndian.AppendUint64(out, o.ID)
		out = append(out, byte(o.Class), o.Flags, o.Compression, 0)
		out = binary.BigEndian.AppendUint16(out, uint16(len(o.Parts)))
		out = binary.BigEndian.AppendUint16(out, uint16(len(o.Path)))
		out = binary.BigEndian.AppendUint16(out, uint16(len(o.MediaType)))
		out = binary.BigEndian.AppendUint16(out, uint16(len(meta)))
		out = binary.BigEndian.AppendUint64(out, o.OriginalSize)
		out = append(out, o.OriginalSHA256[:]...)
		out = append(out, o.Path...)
		out = append(out, o.MediaType...)
		out = append(out, meta...)
		for _, p := range o.Parts {
			out = binary.BigEndian.AppendUint16(out, p.ModuleID)
			out = append(out, p.ModuleVersion, 0)
			out = binary.BigEndian.AppendUint16(out, p.PartNumber)
			out = binary.BigEndian.AppendUint16(out, 0)
			out = binary.BigEndian.AppendUint32(out, p.Offset)
			out = binary.BigEndian.AppendUint32(out, p.StoredLength)
			out = append(out, p.StoredSHA256[:]...)
		}
	}
	if len(out) > MaxModuleSize-HeaderLength {
		return nil, fmt.Errorf("%w: object manifest is %d bytes and must not be split", ErrCapacityExceeded, len(out))
	}
	return out, nil
}

func ParseManifest(payload []byte) (*Manifest, error) {
	r := &reader{b: payload}
	m := &Manifest{Generation: r.u32(), UpdateNumber: r.u32()}
	count := int(r.u32())
	if r.err != nil {
		return nil, r.err
	}
	if count > len(payload) {
		return nil, errTruncated
	}
	m.Objects = make([]ManifestObject, 0, count)
	for range count {
		var o ManifestObject
		o.ID = r.u64()
		o.Class = ObjectClass(r.u8())
		o.Flags = r.u8()
		o.Compression = r.u8()
		r.skip(1)
		parts := int(r.u16())
		pathLen := int(r.u16())
		mediaLen := int(r.u16())
		metaLen := int(r.u16())
		o.OriginalSize = r.u64()
		o.OriginalSHA256 = r.sha256()
		o.Path = r.text(pathLen)
		o.MediaType = r.text(mediaLen)
		meta := r.take(metaLen)
		if r.err != nil {
			return nil, r.err
		}
		var err error
		if o.Metadata, err = ParseMetadata(meta); err != nil {
			return nil, err
		}
		o.Parts = make([]ObjectPart, 0, parts)
		for range parts {
			var p ObjectPart
			p.ModuleID = r.u16()
			p.ModuleVersion = r.u8()
			r.skip(1)
			p.PartNumber = r.u16()
			r.skip(2)
			p.Offset = r.u32()
			p.StoredLength = r.u32()
			p.StoredSHA256 = r.sha256()
			o.Parts = append(o.Parts, p)
		}
		if r.err != nil {
			return nil, r.err
		}
		m.Objects = append(m.Objects, o)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	for i, o := range m.Objects {
		if i > 0 && m.Objects[i-1].ID >= o.ID {
			return nil, errors.New("preservation: object manifest is not in object id order")
		}
		for n, p := range o.Parts {
			if int(p.PartNumber) != n {
				return nil, fmt.Errorf("preservation: object %d part numbers are not consecutive from zero", o.ID)
			}
		}
	}
	return m, nil
}
