// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package remux

type boundedMap[V any] struct {
	m     map[uint32]V
	order []uint32
	limit int
}

func newBoundedMap[V any](limit int) *boundedMap[V] {
	return &boundedMap[V]{m: make(map[uint32]V, limit), limit: limit}
}

func (b *boundedMap[V]) put(k uint32, v V) bool {
	fresh := false
	if _, exists := b.m[k]; !exists {
		fresh = true
		if len(b.order) >= b.limit {
			delete(b.m, b.order[0])
			b.order = b.order[1:]
		}
		b.order = append(b.order, k)
	}
	b.m[k] = v
	return fresh
}

func (b *boundedMap[V]) get(k uint32) (V, bool) {
	v, ok := b.m[k]
	return v, ok
}
