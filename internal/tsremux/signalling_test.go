// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package tsremux

import (
	"bytes"
	"testing"

	"mmt2ts/internal/mmtp"
	"mmt2ts/internal/preservation"
	"mmt2ts/internal/signaling"
	"mmt2ts/internal/tlv"
	"mmt2ts/internal/tsremux/mmtwrite"
)

func buildPAMessage() []byte {
	body := []byte{0x00}
	msg := []byte{0x00, 0x00, 0x00}
	msg = append(msg, 0, 0, 0, byte(len(body)))
	return append(msg, body...)
}

func TestReplaySignallingRoundTrip(t *testing.T) {
	pa := buildPAMessage()
	var paMeta preservation.Metadata
	paMeta.AddU16(preservation.MetaPacketID, 0x0000)
	paMeta.AddU8(preservation.MetaSignallingKind, preservation.SignallingPA)
	paMeta.AddIP(preservation.MetaIPSource, []byte{192, 0, 2, 1})
	paMeta.AddIP(preservation.MetaIPDestination, []byte{224, 0, 0, 1})
	paMeta.AddU16(preservation.MetaUDPSourcePort, 12345)
	paMeta.AddU16(preservation.MetaUDPDestPort, 23456)

	nit := append([]byte{0x40, 0x00, 0x00}, bytes.Repeat([]byte{0xAA}, 4)...)
	var nitMeta preservation.Metadata
	nitMeta.AddU8(preservation.MetaSignallingKind, preservation.SignallingTLVSI)

	ntpPacket := []byte{0x01, 0x02, 0x03, 0x04}
	var ntpMeta preservation.Metadata
	ntpMeta.AddU8(preservation.MetaSignallingKind, preservation.SignallingNTP)
	ntpMeta.AddIP(preservation.MetaIPSource, []byte{192, 0, 2, 1})
	ntpMeta.AddIP(preservation.MetaIPDestination, []byte{224, 0, 0, 123})
	ntpMeta.AddU16(preservation.MetaUDPSourcePort, 123)
	ntpMeta.AddU16(preservation.MetaUDPDestPort, 123)

	records := []preservation.Record{
		{Kind: preservation.RecordRawSignalling, Metadata: paMeta, Payload: pa},
		{Kind: preservation.RecordRawSignalling, Metadata: nitMeta, Payload: nit},
		{Kind: preservation.RecordRawSignalling, Metadata: ntpMeta, Payload: ntpPacket},
	}

	var buf bytes.Buffer
	if err := ReplaySignalling(&buf, records, mmtwrite.NewSequencer()); err != nil {
		t.Fatal(err)
	}

	r := tlv.NewReader(&buf)
	var sawControl, sawNTP bool
	var sawPA *signaling.Message
	reasm := signaling.NewReassembler()
	for {
		pkt, err := r.Next()
		if err != nil {
			break
		}
		switch pkt.Type {
		case tlv.TypeControl:
			if !bytes.Equal(pkt.Payload, nit) {
				t.Fatalf("control packet payload = %x, want %x", pkt.Payload, nit)
			}
			sawControl = true
		case tlv.TypeIPv4, tlv.TypeCompressedIP:
			d, ok := r.Datagram(pkt)
			if !ok {
				t.Fatal("Datagram: could not restore the IP packet")
			}
			if d.DstPort == 123 {
				if !bytes.Equal(d.Payload, ntpPacket) {
					t.Fatalf("NTP payload = %x, want %x", d.Payload, ntpPacket)
				}
				sawNTP = true
				continue
			}
			m, err := mmtp.Parse(d.Payload)
			if err != nil {
				t.Fatalf("mmtp.Parse: %v", err)
			}
			if m.PayloadType != mmtp.PayloadTypeSignaling {
				t.Fatalf("payload type = %d, want signalling", m.PayloadType)
			}
			for _, msg := range reasm.Push(m.PacketID, m.Payload) {
				if msg.ID == signaling.MessageIDPA {
					mm := msg
					sawPA = &mm
				}
			}
		}
	}
	if !sawControl {
		t.Error("TLV-NIT control packet not found")
	}
	if !sawNTP {
		t.Error("NTP packet not found")
	}
	if sawPA == nil {
		t.Fatal("PA message not recovered")
	}
	if !bytes.Equal(sawPA.Raw, pa) {
		t.Errorf("recovered PA message = %x, want %x", sawPA.Raw, pa)
	}
}
