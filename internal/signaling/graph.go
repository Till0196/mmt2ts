// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package signaling

import "fmt"

type AssetGraph struct {
	Nodes  map[string]AssetGraphNode
	Order  []string
	Issues []string
}

type AssetGraphNode struct {
	AssetIndex int
	DependsOn  []string
}

func assetReferenceKey(scheme uint32, id []byte) string {
	return fmt.Sprintf("%08x/%x", scheme, id)
}

func BuildAssetGraph(mpt *MPT) AssetGraph {
	g := AssetGraph{Nodes: make(map[string]AssetGraphNode, len(mpt.Assets))}
	byRef := make(map[string]string, len(mpt.Assets))
	byLayer := make(map[byte]string)
	keys := make([]string, len(mpt.Assets))
	for i := range mpt.Assets {
		a := &mpt.Assets[i]
		key := a.Key()
		keys[i] = key
		g.Nodes[key] = AssetGraphNode{AssetIndex: i}
		if len(a.ID) != 0 {
			byRef[assetReferenceKey(a.IDScheme, a.ID)] = key
		}
		if a.Hierarchy != nil {
			if previous, exists := byLayer[a.Hierarchy.LayerIndex]; exists {
				g.Issues = append(g.Issues, fmt.Sprintf("hierarchy layer %d is used by %s and %s", a.Hierarchy.LayerIndex, previous, key))
			} else {
				byLayer[a.Hierarchy.LayerIndex] = key
			}
		}
	}
	for i := range mpt.Assets {
		a, key := &mpt.Assets[i], keys[i]
		n := g.Nodes[key]
		if a.DependencyInvalid {
			g.Issues = append(g.Issues, fmt.Sprintf("%s has a malformed dependency descriptor", key))
		}
		for _, ref := range a.Dependencies {
			dep, ok := byRef[assetReferenceKey(ref.Scheme, ref.ID)]
			if !ok {
				g.Issues = append(g.Issues, fmt.Sprintf("%s refers to missing asset %s", key, assetReferenceKey(ref.Scheme, ref.ID)))
				continue
			}
			n.DependsOn = appendUnique(n.DependsOn, dep)
		}
		if h := a.Hierarchy; h != nil && h.Type != 15 && h.EmbeddedLayerIndex != h.LayerIndex {
			dep, ok := byLayer[h.EmbeddedLayerIndex]
			if !ok {
				g.Issues = append(g.Issues, fmt.Sprintf("%s refers to missing hierarchy layer %d", key, h.EmbeddedLayerIndex))
			} else {
				n.DependsOn = appendUnique(n.DependsOn, dep)
			}
		}
		g.Nodes[key] = n
	}
	state := make(map[string]byte, len(g.Nodes))
	var visit func(string) bool
	visit = func(key string) bool {
		switch state[key] {
		case 1:
			g.Issues = append(g.Issues, "asset dependency cycle at "+key)
			return false
		case 2:
			return true
		}
		state[key] = 1
		valid := true
		for _, dep := range g.Nodes[key].DependsOn {
			if !visit(dep) {
				valid = false
			}
		}
		state[key] = 2
		if valid {
			g.Order = append(g.Order, key)
		}
		return valid
	}
	for _, key := range keys {
		visit(key)
	}
	return g
}

func appendUnique(v []string, s string) []string {
	for _, old := range v {
		if old == s {
			return v
		}
	}
	return append(v, s)
}
