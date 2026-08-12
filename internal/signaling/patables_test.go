// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package signaling

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func paPacket(body []byte) []byte {
	msg := binary.BigEndian.AppendUint16(nil, MessageIDPA)
	msg = append(msg, 1)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(body)))
	return append([]byte{0x00, 0x00}, append(msg, body...)...)
}

func TestTableIndexPastTheMessageIsRejected(t *testing.T) {
	body := append([]byte{3}, make([]byte, 8)...)
	r := NewReassembler()
	messages := r.Push(0, paPacket(body))
	if len(messages) != 1 {
		t.Fatalf("messages = %d", len(messages))
	}
	if messages[0].Tables != nil {
		t.Fatalf("tables = %+v, want none", messages[0].Tables)
	}
	if s := r.Stats(); s.MalformedTables != 1 || s.Tables != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestTableIndexEndingExactlyAtTheMessageEndIsAccepted(t *testing.T) {
	body := append([]byte{2}, make([]byte, 8)...)
	r := NewReassembler()
	messages := r.Push(0, paPacket(body))
	if len(messages) != 1 {
		t.Fatalf("messages = %d", len(messages))
	}
	if len(messages[0].Tables) != 0 {
		t.Fatalf("tables = %+v, want none", messages[0].Tables)
	}
	if s := r.Stats(); s.MalformedTables != 0 {
		t.Fatalf("an index ending on the boundary was rejected: %+v", s)
	}
}

func TestTableIndexIsSkippedAndTheBodiesParsed(t *testing.T) {
	body := append([]byte{1, 0x81, 4, 0, 3}, table(0x81, 4, []byte{1, 2, 3})...)
	r := NewReassembler()
	messages := r.Push(0, paPacket(body))
	if len(messages) != 1 || len(messages[0].Tables) != 1 {
		t.Fatalf("messages = %+v", messages)
	}
	if !bytes.Equal(messages[0].Tables[0].Raw, []byte{1, 2, 3}) {
		t.Fatalf("raw bytes = % x", messages[0].Tables[0].Raw)
	}
	if s := r.Stats(); s.MalformedTables != 0 || s.Tables != 1 {
		t.Fatalf("stats = %+v", s)
	}
}
