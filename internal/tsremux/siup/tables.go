// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package siup

import (
	"encoding/binary"

	"mmt2ts/internal/mpegts"
	"mmt2ts/internal/si"
)

const maxSectionBody = 0x0fff - 5 - 4

func longSection(tableID byte, extension uint16, version, number, last byte, body []byte) ([]byte, bool) {
	s := []byte{tableID, 0, 0}
	s = binary.BigEndian.AppendUint16(s, extension)
	s = append(s, 0xc1|version<<1&0x3e, number, last)
	s = append(s, body...)
	if len(s)-3+4 > 0x0fff {
		return nil, false
	}
	binary.BigEndian.PutUint16(s[1:3], 0xf000|uint16(len(s)-3+4))
	return binary.BigEndian.AppendUint32(s, mpegts.CRC32(s)), true
}

func (c *Converter) TLVNIT(section []byte) ([]byte, bool) {
	if len(section) < 14 || section[0] != mpegts.TableIDNITActual {
		return nil, false
	}
	end := len(section) - 4
	networkID := binary.BigEndian.Uint16(section[3:5])
	networkDescLen := int(binary.BigEndian.Uint16(section[8:10]) & 0x0fff)
	p := 10 + networkDescLen
	if p+2 > end {
		return nil, false
	}
	network := c.TLVDescriptors(section[10 : 10+networkDescLen])

	streamLoopLen := int(binary.BigEndian.Uint16(section[p:p+2]) & 0x0fff)
	p += 2
	if p+streamLoopLen > end {
		streamLoopLen = end - p
	}
	var streams []byte
	var keys []remoteControlKey
	for loop := section[p : p+streamLoopLen]; len(loop) >= 6; {
		descLen := int(binary.BigEndian.Uint16(loop[4:6]) & 0x0fff)
		if 6+descLen > len(loop) {
			break
		}
		entry := append([]byte{}, loop[0:4]...)
		keys = append(keys, c.remoteControlKeys(loop[6:6+descLen])...)
		desc := c.TLVDescriptors(loop[6 : 6+descLen])
		if len(desc) > 0x0fff {
			break
		}
		entry = binary.BigEndian.AppendUint16(entry, 0xf000|uint16(len(desc)))
		entry = append(entry, desc...)
		streams = append(streams, entry...)
		loop = loop[6+descLen:]
	}
	network = appendRemoteControlKeyDescriptor(network, keys)
	if len(network) > 0x0fff || len(streams) > 0x0fff {
		return nil, false
	}
	body := binary.BigEndian.AppendUint16(nil, 0xf000|uint16(len(network)))
	body = append(body, network...)
	body = binary.BigEndian.AppendUint16(body, 0xf000|uint16(len(streams)))
	body = append(body, streams...)
	return longSection(si.TableIDTLVNITActual, networkID, 0, 0, 0, body)
}

func (c *Converter) MHSDT(section []byte, logos map[uint16][]byte) ([]byte, bool) {
	var tableID byte
	switch {
	case section[0] == mpegts.TableIDSDTActual:
		tableID = si.TableIDMHSDTActual
	case section[0] == mpegts.TableIDSDTOther:
		tableID = si.TableIDMHSDTOther
	default:
		return nil, false
	}
	if len(section) < 15 {
		return nil, false
	}
	end := len(section) - 4
	streamID := binary.BigEndian.Uint16(section[3:5])
	body := append([]byte{}, section[8:11]...)
	for p := 11; p+5 <= end; {
		descLen := int(binary.BigEndian.Uint16(section[p+3:p+5]) & 0x0fff)
		if p+5+descLen > end {
			break
		}
		desc := c.Descriptors(section[p+5 : p+5+descLen])
		desc = append(desc, logos[binary.BigEndian.Uint16(section[p:p+2])]...)
		if len(desc) > 0x0fff {
			break
		}
		body = append(body, section[p:p+3]...)
		body = binary.BigEndian.AppendUint16(body, uint16(section[p+3])<<8&0xf000|uint16(len(desc)))
		body = append(body, desc...)
		p += 5 + descLen
	}
	if len(body) > maxSectionBody {
		return nil, false
	}
	return longSection(tableID, streamID, section[5]>>1&0x1f, section[6], section[7], body)
}

func (c *Converter) MHEITSchedule(section []byte) ([]byte, bool) {
	if len(section) < 18 ||
		section[0] < mpegts.TableIDEITScheduleFirst || section[0] > mpegts.TableIDEITScheduleLast {
		return nil, false
	}
	end := len(section) - 4
	body := append([]byte{}, section[8:14]...)
	for p := 14; p+12 <= end; {
		descLen := int(binary.BigEndian.Uint16(section[p+10:p+12]) & 0x0fff)
		if p+12+descLen > end {
			break
		}
		desc := c.descriptorsExcept(section[p+12:p+12+descLen], mpegts.DescExtendedEvent)
		if len(body)+12+len(desc) > maxSectionBody {
			break
		}
		body = append(body, section[p:p+10]...)
		body = binary.BigEndian.AppendUint16(body, uint16(section[p+10])<<8&0xf000|uint16(len(desc)))
		body = append(body, desc...)
		p += 12 + descLen
	}
	tableID := si.TableIDMHEITScheduleFirst + (section[0] - mpegts.TableIDEITScheduleFirst)
	return longSection(tableID, binary.BigEndian.Uint16(section[3:5]), section[5]>>1&0x1f, section[6], section[7], body)
}

func (c *Converter) MHBIT(section []byte) ([]byte, bool) {
	if len(section) < 14 || section[0] != mpegts.TableIDBIT {
		return nil, false
	}
	end := len(section) - 4
	firstLen := int(binary.BigEndian.Uint16(section[8:10]) & 0x0fff)
	if 10+firstLen > end {
		return nil, false
	}
	first := c.Descriptors(section[10 : 10+firstLen])
	if len(first) > 0x0fff {
		return nil, false
	}
	body := binary.BigEndian.AppendUint16(nil, uint16(section[8])<<8&0xf000|uint16(len(first)))
	body = append(body, first...)
	for p := 10 + firstLen; p+3 <= end; {
		descLen := int(binary.BigEndian.Uint16(section[p+1:p+3]) & 0x0fff)
		if p+3+descLen > end {
			break
		}
		desc := c.Descriptors(section[p+3 : p+3+descLen])
		if len(desc) > 0x0fff {
			break
		}
		body = append(body, section[p])
		body = binary.BigEndian.AppendUint16(body, 0xf000|uint16(len(desc)))
		body = append(body, desc...)
		p += 3 + descLen
	}
	if len(body) > maxSectionBody {
		return nil, false
	}
	return longSection(si.TableIDMHBIT, binary.BigEndian.Uint16(section[3:5]),
		section[5]>>1&0x1f, section[6], section[7], body)
}

func (c *Converter) MHCDT(section []byte) ([]byte, bool) {
	if len(section) < 17 || section[0] != mpegts.TableIDCDT {
		return nil, false
	}
	end := len(section) - 4
	descLen := int(binary.BigEndian.Uint16(section[11:13]) & 0x0fff)
	if 13+descLen > end {
		return nil, false
	}
	desc := c.Descriptors(section[13 : 13+descLen])
	if len(desc) > 0x0fff {
		return nil, false
	}
	body := append([]byte{}, section[8:11]...)
	body = binary.BigEndian.AppendUint16(body, 0xf000|uint16(len(desc)))
	body = append(body, desc...)
	body = append(body, section[13+descLen:end]...)
	if len(body) > maxSectionBody {
		return nil, false
	}
	return longSection(si.TableIDMHCDT, binary.BigEndian.Uint16(section[3:5]),
		section[5]>>1&0x1f, section[6], section[7], body)
}

func (c *Converter) descriptorsExcept(loop []byte, skip ...byte) []byte {
	var kept []byte
	for _, d := range splitTS(loop) {
		drop := false
		for _, tag := range skip {
			if d.tag == tag {
				drop = true
			}
		}
		if drop {
			continue
		}
		kept = append(kept, d.tag, byte(len(d.body)))
		kept = append(kept, d.body...)
	}
	return c.Descriptors(kept)
}
