// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package tlvwrite はUDPとIPヘッダを付けてTLVパケットを書き出す。
package tlvwrite

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	SyncByte         = 0x7f
	TypeIPv4         = 0x01
	TypeIPv6         = 0x02
	TypeCompressedIP = 0x03
	TypeControl      = 0xfe
)

const protoUDP = 17

var errPacketTooLarge = errors.New("tlvwrite: payload does not fit a TLV packet's 16-bit length")

func WriteControl(w io.Writer, payload []byte) error {
	return writePacket(w, TypeControl, payload)
}

type Endpoint []byte

func WriteIPv4(w io.Writer, src, dst Endpoint, srcPort, dstPort uint16, udpPayload []byte) error {
	return writePacket(w, TypeIPv4, buildIPv4UDP(pad4(src), pad4(dst), srcPort, dstPort, udpPayload))
}

func WriteIPv6(w io.Writer, src, dst Endpoint, srcPort, dstPort uint16, udpPayload []byte) error {
	return writePacket(w, TypeIPv6, buildIPv6UDP(pad16(src), pad16(dst), srcPort, dstPort, udpPayload))
}

func WriteUDP(w io.Writer, src, dst Endpoint, srcPort, dstPort uint16, udpPayload []byte) error {
	return WriteUDPContext(w, DefaultCID, src, dst, srcPort, dstPort, udpPayload)
}

func WriteUDPContext(w io.Writer, cid uint16, src, dst Endpoint, srcPort, dstPort uint16, udpPayload []byte) error {
	if len(src) == 16 || len(dst) == 16 {
		return writeCompressedIPv6(w, cid, src, dst, srcPort, dstPort, udpPayload)
	}
	if len(src) == 4 || len(dst) == 4 {
		return writeCompressedIPv4(w, cid, src, dst, srcPort, dstPort, udpPayload)
	}
	return WriteIPv4(w, src, dst, srcPort, dstPort, udpPayload)
}

func WriteUncompressedUDP(w io.Writer, src, dst Endpoint, srcPort, dstPort uint16, udpPayload []byte) error {
	if len(src) == 16 || len(dst) == 16 {
		return WriteIPv6(w, src, dst, srcPort, dstPort, udpPayload)
	}
	return WriteIPv4(w, src, dst, srcPort, dstPort, udpPayload)
}

const DefaultCID = 1

func cidAndSN(cid uint16, payload []byte) uint16 {
	var sn byte
	if len(payload) >= 12 {
		sn = payload[11] & 0x0f
	}
	return cid<<4 | uint16(sn)
}

func writeCompressedIPv6(w io.Writer, cid uint16, src, dst Endpoint, srcPort, dstPort uint16, payload []byte) error {
	s, d := pad16(src), pad16(dst)
	b := make([]byte, 0, 45+len(payload))
	b = binary.BigEndian.AppendUint16(b, cidAndSN(cid, payload))
	b = append(b, 0x60)
	b = append(b, 0x60, 0, 0, 0, protoUDP, 1)
	b = append(b, s[:]...)
	b = append(b, d[:]...)
	b = binary.BigEndian.AppendUint16(b, srcPort)
	b = binary.BigEndian.AppendUint16(b, dstPort)
	b = append(b, payload...)
	return writePacket(w, TypeCompressedIP, b)
}

func writeCompressedIPv4(w io.Writer, cid uint16, src, dst Endpoint, srcPort, dstPort uint16, payload []byte) error {
	s, d := pad4(src), pad4(dst)
	b := make([]byte, 0, 23+len(payload))
	b = binary.BigEndian.AppendUint16(b, cidAndSN(cid, payload))
	b = append(b, 0x20, 0x45, 0, 0, 0, 0, 0, 1, protoUDP)
	b = append(b, s[:]...)
	b = append(b, d[:]...)
	b = binary.BigEndian.AppendUint16(b, srcPort)
	b = binary.BigEndian.AppendUint16(b, dstPort)
	b = append(b, payload...)
	return writePacket(w, TypeCompressedIP, b)
}

func pad4(e Endpoint) [4]byte {
	var b [4]byte
	copy(b[:], e)
	return b
}

func pad16(e Endpoint) [16]byte {
	var b [16]byte
	copy(b[:], e)
	return b
}

func writePacket(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > 0xffff {
		return errPacketTooLarge
	}
	var hdr [4]byte
	hdr[0] = SyncByte
	hdr[1] = typ
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func buildUDP(srcPort, dstPort uint16, payload []byte) []byte {
	udp := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	return append(udp, payload...)
}

func buildIPv4UDP(src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udp := buildUDP(srcPort, dstPort, payload)
	totalLen := 20 + len(udp)
	ip := make([]byte, 20, totalLen)
	ip[0] = 0x45
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], 0)
	binary.BigEndian.PutUint16(ip[6:8], 0)
	ip[8] = 1
	ip[9] = protoUDP
	binary.BigEndian.PutUint16(ip[10:12], 0)
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[10:12], inetChecksum(ip))
	return append(ip, udp...)
}

func buildIPv6UDP(src, dst [16]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udp := buildUDP(srcPort, dstPort, payload)
	ip := make([]byte, 40, 40+len(udp))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(udp)))
	ip[6] = protoUDP
	ip[7] = 1
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])

	pseudo := make([]byte, 0, 40+8)
	pseudo = append(pseudo, src[:]...)
	pseudo = append(pseudo, dst[:]...)
	pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(udp)))
	pseudo = append(pseudo, 0, 0, 0, protoUDP)
	pseudo = append(pseudo, udp...)
	sum := inetChecksum(pseudo)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return append(ip, udp...)
}

func inetChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
