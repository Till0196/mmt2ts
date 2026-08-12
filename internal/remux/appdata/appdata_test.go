// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package appdata

import (
	"encoding/binary"
	"testing"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/si"
)

func section(tableID byte, extension uint16, body []byte) si.Section {
	s := []byte{tableID, 0, 0}
	s = binary.BigEndian.AppendUint16(s, extension)
	s = append(s, 0xc1, 0, 0)
	s = append(s, body...)
	binary.BigEndian.PutUint16(s[1:3], 0xf000|uint16(len(s)-3+4))
	s = binary.BigEndian.AppendUint32(s, mpegts.CRC32(s))
	sec, _, err := si.ParseSection(s)
	if err != nil {
		panic(err)
	}
	return sec
}

func damtSection(itemID uint32, nodeTag uint16, size uint32, sum uint32) si.Section {
	body := make([]byte, 6)
	body = binary.BigEndian.AppendUint32(body, 0x1234)
	body = append(body, 1)
	body = binary.BigEndian.AppendUint32(body, 1)
	body = binary.BigEndian.AppendUint32(body, size)
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = binary.BigEndian.AppendUint16(body, nodeTag)
	body = binary.BigEndian.AppendUint32(body, itemID)
	body = binary.BigEndian.AppendUint32(body, size)
	body = append(body, 0x01, 0x80)
	body = binary.BigEndian.AppendUint32(body, sum)
	body = append(body, 0x00)
	body = append(body, 0x00)
	body = append(body, 0x00)
	return section(si.TableIDDAMT, 0x0100, body)
}

func ddmtSection(nodeTag uint16, path, name string) si.Section {
	body := []byte{byte(len("/"))}
	body = append(body, '/')
	body = append(body, 1)
	body = binary.BigEndian.AppendUint16(body, 0x0001)
	body = append(body, 0x01, byte(len(path)))
	body = append(body, path...)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = binary.BigEndian.AppendUint16(body, nodeTag)
	body = append(body, byte(len(name)))
	body = append(body, name...)
	return section(si.TableIDDDMT, 0x0100, body)
}

func TestItemIsReassembledNamedAndChecked(t *testing.T) {
	s := New()
	data := []byte("<html>hello</html>")
	sum := checksum32(data)

	s.PushTable(ddmtSection(0x0020, "app/", "index.html"))
	s.PushTable(damtSection(0x11223344, 0x0020, uint32(len(data)), sum))
	s.PushItemData(1, 0x11223344, data[:8])
	s.PushItemData(1, 0x11223344, data[8:])
	s.Finish()

	items := s.Items()
	if len(items) != 1 {
		t.Fatalf("items = %d", len(items))
	}
	it := items[0]
	if !it.Complete() {
		t.Fatalf("item incomplete: %+v", it)
	}
	if it.Name != "index.html" || it.Path != "/app/" {
		t.Fatalf("item name = %q path = %q", it.Name, it.Path)
	}
	valid, ok := it.ChecksumValid()
	if !ok || !valid {
		t.Fatalf("checksum valid = %v, ok = %v", valid, ok)
	}
	st := s.Stats()
	if st.ItemsComplete != 1 || st.ChecksumOK != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestChecksumMismatchIsReported(t *testing.T) {
	s := New()
	data := []byte("abcd")
	s.PushTable(damtSection(1, 5, uint32(len(data)), checksum32(data)+1))
	s.PushItemData(1, 1, data)
	s.Finish()
	if st := s.Stats(); st.ChecksumBad != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestPartialItemIsNotReportedComplete(t *testing.T) {
	s := New()
	s.PushTable(damtSection(2, 6, 100, 0))
	s.PushItemData(1, 2, make([]byte, 40))
	s.Finish()
	st := s.Stats()
	if st.ItemsPartial != 1 || st.ItemsComplete != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if st.ChecksumNone != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestItemWithoutManagementIsCounted(t *testing.T) {
	s := New()
	s.PushItemData(1, 9, []byte("orphan"))
	s.Finish()
	if st := s.Stats(); st.ItemsUnknown != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestApplicationReferenceIsResolvedOrExplained(t *testing.T) {
	s := New()
	loc := si.Descriptor{Tag: tagSimpleApplicationLocation, Data: []byte("/app/index.html")}
	s.PushAIT(&si.AIT{
		ApplicationType: 0x0001,
		Version:         1,
		Applications: []si.Application{{
			OrganizationID: 0x0000000a,
			ApplicationID:  0x0001,
			ControlCode:    0x01,
			Descriptors:    []si.Descriptor{loc},
		}},
	})
	graph := s.Graph()
	if len(graph) != 1 || graph[0].Resolved {
		t.Fatalf("graph = %+v", graph)
	}
	if graph[0].Reason == "" {
		t.Fatal("an unresolved reference has no reason")
	}

	data := []byte("<html/>")
	s.PushTable(ddmtSection(0x0020, "app/", "index.html"))
	s.PushTable(damtSection(0x30, 0x0020, uint32(len(data)), checksum32(data)))
	s.PushItemData(1, 0x30, data)
	s.Finish()
	graph = s.Graph()
	if len(graph) != 1 || !graph[0].Resolved {
		t.Fatalf("graph = %+v", graph)
	}
}

func TestUnknownDataTableIsCounted(t *testing.T) {
	s := New()
	s.PushTable(section(0xaf, 0, []byte{1, 2, 3}))
	if st := s.Stats(); st.UnknownTables[0xaf] != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func damtIndexSection(sequence uint32) si.Section {
	body := make([]byte, 10)
	body = append(body, 1)
	body = binary.BigEndian.AppendUint32(body, sequence)
	body = append(body, 0, 0, 0, 0)
	body = append(body, 0x80)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = append(body, 0x00)
	return section(si.TableIDDAMT, 0x0100, body)
}

func indexEntryBytes(id uint32, name string, size uint32) []byte {
	b := binary.BigEndian.AppendUint32(nil, id)
	b = binary.BigEndian.AppendUint32(b, size)
	b = append(b, 0x01, byte(len(name)))
	b = append(b, name...)
	b = append(b, 0x00, 0x00, 0xff)
	return b
}

func TestIndexItemIsRead(t *testing.T) {
	s := New()
	s.PushTable(damtIndexSection(7))
	payload := binary.BigEndian.AppendUint16(nil, 2)
	payload = append(payload, indexEntryBytes(0x0a, "a.html", 10)...)
	payload = append(payload, indexEntryBytes(0x0b, "b.html", 20)...)
	s.PushItemData(7, 0x99, payload)
	s.Finish()

	if st := s.Stats(); st.IndexItems != 1 || st.IndexItemErrors != 0 {
		t.Fatalf("stats = %+v", st)
	}
	for _, want := range []struct {
		id   uint32
		name string
		size uint32
	}{{0x0a, "a.html", 10}, {0x0b, "b.html", 20}} {
		it := s.Item(want.id)
		if it == nil || !it.Announced || it.Name != want.name || it.Size != want.size {
			t.Fatalf("item %#x = %+v", want.id, it)
		}
	}
}

// index itemが先頭payloadだけでは完結しない場合、解析に成功した前半のentryも
// itemとして残してはいけない。残すと、放送内容の断片がitem名やサイズとして
// レポートへ現れる。
func TestTruncatedIndexItemCommitsNothing(t *testing.T) {
	s := New()
	s.PushTable(damtIndexSection(7))
	first := indexEntryBytes(0x0a, "a.html", 10)
	payload := binary.BigEndian.AppendUint16(nil, 2)
	payload = append(payload, first...)
	payload = append(payload, indexEntryBytes(0x0b, "b.html", 20)[:3]...)
	s.PushItemData(7, 0x99, payload)
	s.Finish()

	if st := s.Stats(); st.IndexItems != 0 || st.IndexItemErrors != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if it := s.Item(0x0a); it != nil {
		t.Fatalf("a partially parsed index entry became item %+v", it)
	}
	if st := s.Stats(); st.ItemsAnnounced != 0 {
		t.Fatalf("announced = %d, want 0", st.ItemsAnnounced)
	}
	if it := s.Item(0x99); it == nil || it.Announced {
		t.Fatalf("the payload was not kept as an unannounced item: %+v", it)
	}
}

// index itemを載せるMPUは、index item自身とコンテンツのitemを一緒に運ぶ。
// DAMTはindex itemのitem idを伝えないので、payloadを解析して選び分ける必要がある。
func TestIndexItemIsPickedOutOfAContentCarryingMPU(t *testing.T) {
	s := New()
	s.PushTable(damtIndexSection(7))
	content := []byte("<!DOCTYPE html>\n<html lang=\"ja\"></html>")
	index := binary.BigEndian.AppendUint16(nil, 1)
	index = append(index, indexEntryBytes(0x30c65, "index.html", uint32(len(content)))...)

	// コンテンツが先に届いても、index itemとして採用してはいけない。
	s.PushItemData(7, 0x30c65, content)
	s.PushItemData(7, 0x00, index)
	s.PushItemData(7, 0x30c65, content)
	s.Finish()

	if st := s.Stats(); st.IndexItems != 1 || st.IndexItemErrors != 0 {
		t.Fatalf("stats = %+v", st)
	}
	it := s.Item(0x30c65)
	if it == nil || it.Name != "index.html" || !it.Complete() {
		t.Fatalf("content item = %+v", it)
	}
	// index itemを運んだitem idは一覧に残さない。
	if it := s.Item(0x00); it != nil {
		t.Fatalf("the index carrier stayed as an item: %+v", it)
	}
	if got := len(s.Items()); got != 1 {
		t.Fatalf("items = %d, want 1", got)
	}
}

func TestFragmentedIndexItemIsReassembled(t *testing.T) {
	s := New()
	s.PushTable(damtIndexSection(7))
	index := binary.BigEndian.AppendUint16(nil, 2)
	index = append(index, indexEntryBytes(0x0a, "a.html", 10)...)
	index = append(index, indexEntryBytes(0x0b, "b.html", 20)...)

	cut := len(index) / 2
	s.PushItemData(7, 0x00, index[:cut])
	if st := s.Stats(); st.IndexItems != 0 {
		t.Fatalf("a fragment was accepted as a whole index item: %+v", st)
	}
	s.PushItemData(7, 0x00, index[cut:])
	s.Finish()

	if st := s.Stats(); st.IndexItems != 1 || st.IndexItemErrors != 0 {
		t.Fatalf("stats = %+v", st)
	}
	for id, name := range map[uint32]string{0x0a: "a.html", 0x0b: "b.html"} {
		if it := s.Item(id); it == nil || it.Name != name {
			t.Fatalf("item %#x = %+v", id, it)
		}
	}
}

func TestUnreadableIndexItemIsCountedOnce(t *testing.T) {
	s := New()
	s.PushTable(damtIndexSection(7))
	s.PushItemData(7, 0x30c65, []byte("<html>not an index</html>"))
	s.PushItemData(7, 0x30c65, []byte("<html>not an index either</html>"))
	s.Finish()

	if st := s.Stats(); st.IndexItems != 0 || st.IndexItemErrors != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if it := s.Item(0x30c65); it == nil || it.Announced {
		t.Fatalf("the content was dropped instead of kept unannounced: %+v", it)
	}
}
