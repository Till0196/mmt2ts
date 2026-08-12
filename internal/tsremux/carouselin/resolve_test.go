// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package carouselin

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"testing"

	"mmt2ts/internal/preservation"
)

func TestResolveObjectUsesTheWritersOwnPacking(t *testing.T) {
	plain := bytes.Repeat([]byte("plain object content "), 50)
	original := []byte("this text compresses fine because it repeats a lot repeats a lot repeats a lot")
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write(original); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := zbuf.Bytes()

	inputs := []preservation.PackInput{
		{ID: 1, Class: preservation.ClassGenericAsset, Path: "plain.bin",
			OriginalSize: uint64(len(plain)), OriginalSHA256: sha256.Sum256(plain), Stored: plain},
		{ID: 2, Class: preservation.ClassTTML, Compression: preservation.CompressionZlib, Path: "doc.ttml",
			OriginalSize: uint64(len(original)), OriginalSHA256: sha256.Sum256(original), Stored: compressed},
	}
	modules, manifest, err := preservation.PackObjects(inputs, 0x0100, 254)
	if err != nil {
		t.Fatalf("PackObjects: %v", err)
	}
	manifest.UpdateNumber = 1

	r := New()
	downloadID := uint32(downloadObject)<<16 | testServiceID
	for _, m := range modules {
		manifest.SetModuleVersion(m.ID, 0)
		pushModule(t, r, 0x1d01, downloadID, m.ID, preservation.Header{Kind: preservation.KindStaticObject}, m.Payload)
	}
	manifestPayload, err := manifest.Encode()
	if err != nil {
		t.Fatalf("Manifest.Encode: %v", err)
	}
	pushModule(t, r, 0x1d01, downloadID, 0x0001, preservation.Header{Kind: preservation.KindObjectManifest, Flags: preservation.FlagCommit}, manifestPayload)

	if r.Object.Manifest == nil {
		t.Fatal("manifest not decoded")
	}
	if len(r.Problems) > 0 {
		t.Fatalf("unexpected problems: %v", r.Problems)
	}

	for _, obj := range r.Object.Manifest.Objects {
		got, err := ResolveObject(&r.Object, obj)
		if err != nil {
			t.Fatalf("ResolveObject(%d): %v", obj.ID, err)
		}
		var want []byte
		if obj.ID == 1 {
			want = plain
		} else {
			want = original
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("object %d = %d bytes, want %d bytes", obj.ID, len(got), len(want))
		}
	}
}
