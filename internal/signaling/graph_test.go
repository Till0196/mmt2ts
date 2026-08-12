// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package signaling

import "testing"

func graphAsset(id byte, layer, embedded byte) Asset {
	return Asset{
		IdentifierType: 0, IDScheme: 1, ID: []byte{id}, Type: "hev1",
		Hierarchy: &Hierarchy{Type: 1, LayerIndex: layer, EmbeddedLayerIndex: embedded},
	}
}

func TestAssetGraphOrdersBaseBeforeEnhancement(t *testing.T) {
	base := graphAsset(1, 1, 1)
	enhancement := graphAsset(2, 2, 1)
	enhancement.Dependencies = []AssetReference{{Scheme: 1, ID: []byte{1}}}
	g := BuildAssetGraph(&MPT{Assets: []Asset{enhancement, base}})
	if len(g.Issues) != 0 {
		t.Fatalf("issues = %v", g.Issues)
	}
	if len(g.Order) != 2 || g.Order[0] != base.Key() || g.Order[1] != enhancement.Key() {
		t.Fatalf("decode order = %v", g.Order)
	}
	n := g.Nodes[enhancement.Key()]
	if len(n.DependsOn) != 1 || n.DependsOn[0] != base.Key() {
		t.Fatalf("enhancement dependencies = %v", n.DependsOn)
	}
}

func TestAssetGraphReportsMissingDuplicateAndCycle(t *testing.T) {
	a := graphAsset(1, 1, 2)
	b := graphAsset(2, 1, 1)
	a.Dependencies = []AssetReference{{Scheme: 1, ID: []byte{2}}, {Scheme: 1, ID: []byte{9}}}
	b.Dependencies = []AssetReference{{Scheme: 1, ID: []byte{1}}}
	g := BuildAssetGraph(&MPT{Assets: []Asset{a, b}})
	if len(g.Issues) < 3 {
		t.Fatalf("issues = %v, want duplicate, missing target and cycle", g.Issues)
	}
}

func TestDependencyDescriptorIsFullyConsumed(t *testing.T) {
	d := []byte{1, 0, 0, 0, 7, 2, 0xaa, 0xbb}
	refs, ok := parseDependencies(d)
	if !ok || len(refs) != 1 || refs[0].Scheme != 7 || string(refs[0].ID) != "\xaa\xbb" {
		t.Fatalf("dependencies = %+v, ok = %v", refs, ok)
	}
	if _, ok := parseDependencies(append(d, 0)); ok {
		t.Fatal("trailing bytes were accepted")
	}
}
