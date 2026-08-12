// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package carouselin

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"mmt2ts/internal/preservation"
)

var (
	ErrObjectIncomplete   = errors.New("carouselin: object part module not yet received")
	ErrObjectHashMismatch = errors.New("carouselin: object hash does not match the manifest")
)

func ResolveObject(st *State, obj preservation.ManifestObject) ([]byte, error) {
	joined := make([]byte, 0, obj.OriginalSize)
	for _, part := range obj.Parts {
		host, ok := st.Objects[part.ModuleID]
		if !ok {
			return nil, ErrObjectIncomplete
		}
		if version, ok := st.ObjectVersions[part.ModuleID]; !ok || version != part.ModuleVersion {
			return nil, ErrObjectIncomplete
		}
		offset, length := int(part.Offset), int(part.StoredLength)
		if offset+length > len(host) {
			return nil, fmt.Errorf("carouselin: object %d part %d runs past module %#04x", obj.ID, part.PartNumber, part.ModuleID)
		}
		run := host[offset : offset+length]
		if sha256.Sum256(run) != part.StoredSHA256 {
			return nil, fmt.Errorf("%w: object %d part %d", ErrObjectHashMismatch, obj.ID, part.PartNumber)
		}
		joined = append(joined, run...)
	}

	switch obj.Compression {
	case preservation.CompressionNone:
	case preservation.CompressionZlib:
		zr, err := zlib.NewReader(bytes.NewReader(joined))
		if err != nil {
			return nil, fmt.Errorf("carouselin: object %d: %w", obj.ID, err)
		}
		defer zr.Close()
		out, err := io.ReadAll(zr)
		if err != nil {
			return nil, fmt.Errorf("carouselin: object %d: %w", obj.ID, err)
		}
		joined = out
	default:
		return nil, fmt.Errorf("carouselin: object %d uses unsupported compression %d", obj.ID, obj.Compression)
	}

	if uint64(len(joined)) != obj.OriginalSize {
		return nil, fmt.Errorf("%w: object %d is %d bytes, manifest says %d", ErrObjectHashMismatch, obj.ID, len(joined), obj.OriginalSize)
	}
	if sha256.Sum256(joined) != obj.OriginalSHA256 {
		return nil, fmt.Errorf("%w: object %d", ErrObjectHashMismatch, obj.ID)
	}
	return joined, nil
}

func ResolvedObjects(st *State) map[uint64]ResolvedObject {
	out := make(map[uint64]ResolvedObject)
	for _, snapshot := range st.Snapshots {
		for id, obj := range snapshot.Objects {
			out[id] = obj
		}
	}
	if len(out) == 0 && st.Manifest != nil {
		for _, obj := range st.Manifest.Objects {
			if data, err := ResolveObject(st, obj); err == nil {
				out[obj.ID] = ResolvedObject{Manifest: obj, Data: data}
			}
		}
	}
	return out
}
