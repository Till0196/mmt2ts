// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tlv

type ipFragmentKey struct {
	version  byte
	protocol byte
	id       uint32
	src, dst string
}

type ipFragmentSet struct {
	data    []byte
	present []bool
	total   int
}

const (
	maxIPDatagram   = 65535
	maxFragmentSets = 128
)

func (r *Reader) addIPFragment(key ipFragmentKey, offset int, more bool, payload []byte) ([]byte, bool) {
	r.stats.FragmentPackets++
	end := offset + len(payload)
	if offset < 0 || end < offset || end > maxIPDatagram || (more && len(payload)%8 != 0) {
		r.stats.FragmentErrors++
		delete(r.fragments, key)
		return nil, false
	}
	s := r.fragments[key]
	if s == nil {
		if len(r.fragments) >= maxFragmentSets {
			for old := range r.fragments {
				delete(r.fragments, old)
				r.stats.FragmentErrors++
				break
			}
		}
		s = &ipFragmentSet{data: make([]byte, maxIPDatagram), present: make([]bool, maxIPDatagram), total: -1}
		r.fragments[key] = s
	}
	if !more {
		if s.total >= 0 && s.total != end {
			delete(r.fragments, key)
			r.stats.FragmentErrors++
			return nil, false
		}
		s.total = end
	}
	for i, v := range payload {
		p := offset + i
		if s.present[p] && s.data[p] != v {
			delete(r.fragments, key)
			r.stats.FragmentErrors++
			return nil, false
		}
		s.data[p], s.present[p] = v, true
	}
	if s.total < 0 {
		return nil, false
	}
	for _, ok := range s.present[:s.total] {
		if !ok {
			return nil, false
		}
	}
	out := append([]byte(nil), s.data[:s.total]...)
	delete(r.fragments, key)
	r.stats.ReassembledIP++
	return out, true
}
