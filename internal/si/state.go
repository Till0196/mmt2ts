// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package si

import "errors"

type SDTKey struct {
	TableID     byte
	TLVStreamID uint16
}

type EITKey struct {
	TableID   byte
	ServiceID uint16
	Section   byte
}

type State struct {
	col *Collector

	NIT map[uint16]*NIT
	SDT map[SDTKey]*SDT
	EIT map[EITKey]*EIT
	BIT map[uint16]*BIT
	CDT map[uint16]*CDT
	AIT map[uint16]*AIT
	TOT *TOT
	SIT *SIT

	LastDIT *DIT
	DITs    uint64

	Generation uint64

	DataTable func(Section)
	NewAIT    func(*AIT)

	RawTables   map[byte]uint64
	ParseErrors map[byte]uint64
}

func NewState() *State {
	return &State{
		col:         NewCollector(),
		NIT:         make(map[uint16]*NIT),
		SDT:         make(map[SDTKey]*SDT),
		EIT:         make(map[EITKey]*EIT),
		BIT:         make(map[uint16]*BIT),
		CDT:         make(map[uint16]*CDT),
		AIT:         make(map[uint16]*AIT),
		RawTables:   make(map[byte]uint64),
		ParseErrors: make(map[byte]uint64),
	}
}

func (s *State) Stats() Stats { return s.col.Stats() }

func (s *State) PushMessage(id uint16, version byte, body []byte) error {
	if id == MessageIDData {
		return s.pushData(version, body)
	}
	if id != MessageIDM2Section && id != MessageIDM2ShortSection {
		s.col.stats.UnknownMessages[id]++
		return nil
	}
	s.col.stats.Messages++
	var err error
	for len(body) > 0 {
		sec, n, perr := ParseSection(body)
		switch {
		case errors.Is(perr, ErrCRC):
			s.col.stats.CRCErrors++
			body = body[n:]
			continue
		case perr != nil:
			s.col.stats.Truncated++
			return perr
		}
		sec.MessageID, sec.MessageVersion = id, version
		s.push(sec)
		body = body[n:]
	}
	return err
}

func (s *State) pushData(version byte, body []byte) error {
	s.col.stats.Messages++
	for len(body) > 0 {
		sec, n, err := ParseSection(body)
		switch {
		case errors.Is(err, ErrCRC):
			s.col.stats.CRCErrors++
			body = body[n:]
			continue
		case err != nil:
			s.col.stats.Truncated++
			return err
		}
		sec.MessageID, sec.MessageVersion = MessageIDData, version
		s.RawTables[sec.TableID]++
		if s.DataTable != nil {
			s.DataTable(sec)
		}
		body = body[n:]
	}
	return nil
}

func (s *State) PushTLVSection(payload []byte) {
	sec, _, err := ParseSection(payload)
	if err != nil {
		if errors.Is(err, ErrCRC) {
			s.col.stats.CRCErrors++
		} else {
			s.col.stats.Truncated++
		}
		return
	}
	s.push(sec)
}

func (s *State) push(sec Section) {
	s.RawTables[sec.TableID]++
	set, ok := s.col.Push(sec)
	if !ok {
		return
	}
	s.apply(set)
}

func (s *State) apply(set *TableSet) {
	changed := false
	fail := func() { s.ParseErrors[set.TableID]++ }
	switch id := set.TableID; {
	case id == TableIDTLVNITActual || id == TableIDTLVNITOther:
		for _, sec := range set.Sections {
			nit, ok := ParseNIT(sec)
			if !ok {
				fail()
				continue
			}
			if prev, ok := s.NIT[nit.NetworkID]; ok && prev.Version == nit.Version && sec.Number > 0 {
				prev.Streams = append(prev.Streams, nit.Streams...)
			} else {
				s.NIT[nit.NetworkID] = nit
			}
			changed = true
		}
	case isEIT(id):
		for _, sec := range set.Sections {
			eit, ok := ParseEIT(sec)
			if !ok {
				fail()
				continue
			}
			s.EIT[EITKey{id, eit.ServiceID, eit.SectionNumber}] = eit
			changed = true
		}
	case id == TableIDMHSDTActual || id == TableIDMHSDTOther:
		for _, sec := range set.Sections {
			sdt, ok := ParseSDT(sec)
			if !ok {
				fail()
				continue
			}
			key := SDTKey{TableID: sdt.TableID, TLVStreamID: sdt.TLVStreamID}
			if prev, ok := s.SDT[key]; ok && prev.Version == sdt.Version && sec.Number > 0 {
				prev.Services = append(prev.Services, sdt.Services...)
			} else {
				s.SDT[key] = sdt
			}
			changed = true
		}
	case id == TableIDMHTOT:
		if tot, ok := ParseTOT(set.Sections[0]); ok {
			s.TOT, changed = tot, true
		} else {
			fail()
		}
	case id == TableIDMHBIT:
		for _, sec := range set.Sections {
			bit, ok := ParseBIT(sec)
			if !ok {
				fail()
				continue
			}
			if prev, ok := s.BIT[bit.OriginalNetworkID]; ok && prev.Version == bit.Version && sec.Number > 0 {
				prev.Broadcasters = append(prev.Broadcasters, bit.Broadcasters...)
			} else {
				s.BIT[bit.OriginalNetworkID] = bit
			}
			changed = true
		}
	case id == TableIDMHCDT:
		for _, sec := range set.Sections {
			cdt, ok := ParseCDT(sec)
			if !ok {
				fail()
				continue
			}
			if prev, ok := s.CDT[cdt.DownloadDataID]; ok && prev.Version == cdt.Version && sec.Number > 0 {
				prev.Module = append(prev.Module, cdt.Module...)
			} else {
				s.CDT[cdt.DownloadDataID] = cdt
			}
			changed = true
		}
	case id == TableIDMHSIT:
		if sit, ok := ParseSIT(set.Sections[0]); ok {
			s.SIT, changed = sit, true
		} else {
			fail()
		}
	case id == TableIDMHDIT:
		if dit, ok := ParseDIT(set.Sections[0]); ok {
			s.LastDIT = dit
			s.DITs++
			changed = true
		} else {
			fail()
		}
	case id == TableIDMHAIT:
		for _, sec := range set.Sections {
			ait, ok := ParseAIT(sec)
			if !ok {
				fail()
				continue
			}
			s.AIT[ait.ApplicationType] = ait
			if s.NewAIT != nil {
				s.NewAIT(ait)
			}
			changed = true
		}
	default:
		s.col.stats.UnknownTables[set.TableID]++
	}
	if changed {
		s.Generation++
	}
}

func (s *State) SelfNetwork() (*NIT, bool) {
	for _, n := range s.NIT {
		if n.Actual() {
			return n, true
		}
	}
	return nil, false
}

func (s *State) ActualSDT() (*SDT, bool) {
	var fallback *SDT
	for _, sdt := range s.SDT {
		if !sdt.Actual() {
			continue
		}
		// A named stream wins over one that left tlv_stream_id at zero:
		// picking the placeholder would pin the identity to stream 0x0000
		// and turn every properly named table into a conflict.  Zero still
		// answers when it is all the stream ever sends.
		if sdt.TLVStreamID != 0 {
			return sdt, true
		}
		fallback = sdt
	}
	if fallback != nil {
		return fallback, true
	}
	return nil, false
}

func (s *State) ServiceSDT(serviceID uint16) (*SDT, *SDTService, bool) {
	for _, sdt := range s.SDT {
		if !sdt.Actual() {
			continue
		}
		for i := range sdt.Services {
			if sdt.Services[i].ServiceID == serviceID {
				return sdt, &sdt.Services[i], true
			}
		}
	}
	return nil, nil, false
}

func (s *State) PresentEvent(serviceID uint16) (*EIT, *Event, bool) {
	eit, ok := s.EIT[EITKey{TableIDMHEITPF, serviceID, 0}]
	if !ok || len(eit.Events) == 0 {
		return nil, nil, false
	}
	return eit, &eit.Events[0], true
}

func (s *State) ScheduleSections(serviceID uint16) []*EIT {
	var out []*EIT
	for id := TableIDMHEITScheduleFirst; id <= TableIDMHEITScheduleLast; id++ {
		for n := 0; n < 256; n++ {
			if eit, ok := s.EIT[EITKey{byte(id), serviceID, byte(n)}]; ok {
				out = append(out, eit)
			}
		}
	}
	return out
}

type Identity struct {
	NetworkID         uint16
	HaveNetworkID     bool
	OriginalNetworkID uint16
	HaveOriginalID    bool
	TLVStreamID       uint16
	HaveTLVStreamID   bool
	Conflicts         []string
}

func (s *State) Identity(serviceID uint16) Identity {
	var id Identity
	seen := make(map[string]bool)
	set := func(dst *uint16, have *bool, name string, v uint16) {
		if *have && *dst != v {
			if !seen[name] {
				seen[name] = true
				id.Conflicts = append(id.Conflicts, name)
			}
			return
		}
		*dst, *have = v, true
	}
	if sdt, ok := s.ActualSDT(); ok {
		set(&id.TLVStreamID, &id.HaveTLVStreamID, "tlv_stream_id", sdt.TLVStreamID)
		set(&id.OriginalNetworkID, &id.HaveOriginalID, "original_network_id", sdt.OriginalNetworkID)
	}
	for key, eit := range s.EIT {
		if key.ServiceID != serviceID {
			continue
		}
		set(&id.TLVStreamID, &id.HaveTLVStreamID, "tlv_stream_id", eit.TLVStreamID)
		set(&id.OriginalNetworkID, &id.HaveOriginalID, "original_network_id", eit.OriginalNetworkID)
	}
	if nit, ok := s.SelfNetwork(); ok {
		set(&id.NetworkID, &id.HaveNetworkID, "network_id", nit.NetworkID)
		switch {
		case id.HaveTLVStreamID:
			found := false
			for _, st := range nit.Streams {
				if st.TLVStreamID != id.TLVStreamID {
					continue
				}
				found = true
				set(&id.OriginalNetworkID, &id.HaveOriginalID, "original_network_id", st.OriginalNetworkID)
			}
			if !found && len(nit.Streams) > 0 {
				id.Conflicts = append(id.Conflicts, "tlv_stream_id")
			}
		case len(nit.Streams) == 1:
			set(&id.TLVStreamID, &id.HaveTLVStreamID, "tlv_stream_id", nit.Streams[0].TLVStreamID)
			set(&id.OriginalNetworkID, &id.HaveOriginalID, "original_network_id", nit.Streams[0].OriginalNetworkID)
		}
	}
	if s.SIT != nil {
		for _, d := range s.SIT.TransmissionInfo {
			switch d.Tag {
			case TagMHNetworkIdentification:
				if n, ok := ParseNetworkIdentification(d.Data); ok {
					set(&id.NetworkID, &id.HaveNetworkID, "network_id", n.NetworkID)
				}
			case TagMHBroadcastID:
				if b, ok := ParseBroadcastID(d.Data); ok {
					set(&id.OriginalNetworkID, &id.HaveOriginalID, "original_network_id", b.OriginalNetworkID)
					set(&id.TLVStreamID, &id.HaveTLVStreamID, "tlv_stream_id", b.TLVStreamID)
				}
			}
		}
	}
	return id
}
