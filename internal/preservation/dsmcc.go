// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

package preservation

import (
	"encoding/binary"
	"errors"
	"fmt"

	"mmt2ts/internal/mpegts"
)

const (
	BlockSize     = 4066
	MaxBlocks     = 256
	MaxModuleSize = BlockSize * MaxBlocks
	MaxModules    = 256

	MaxDIISectionLength = 45 + 8*MaxModules
	MaxDDBSectionLength = 5 + 12 + 6 + BlockSize + 4

	dsmccHeaderLen = 12

	protocolDiscriminator = 0x11
	dsmccTypeDownload     = 0x03
	messageIDDII          = 0x1002
	messageIDDDB          = 0x1003
)

var ErrCapacityExceeded = errors.New("preservation: carousel capacity exceeded")

func TransactionID(number uint32) uint32 {
	return 0x80000000 | number&0x3fffffff
}

type ModuleEntry struct {
	ID      uint16
	Size    uint32
	Version byte
}

func BuildDII(downloadID, transactionID, downloadScenario uint32, modules []ModuleEntry) ([]byte, error) {
	if len(modules) > MaxModules {
		return nil, fmt.Errorf("%w: %d modules", ErrCapacityExceeded, len(modules))
	}
	if downloadScenario == 0 {
		return nil, errors.New("preservation: tCDownloadScenario must be at least 1")
	}
	for _, m := range modules {
		if m.Size == 0 {
			return nil, fmt.Errorf("preservation: module %#04x has moduleSize 0", m.ID)
		}
		if m.Size > MaxModuleSize {
			return nil, fmt.Errorf("%w: module %#04x is %d bytes", ErrCapacityExceeded, m.ID, m.Size)
		}
	}

	body := make([]byte, 0, 24+8*len(modules))
	body = binary.BigEndian.AppendUint32(body, downloadID)
	body = binary.BigEndian.AppendUint16(body, BlockSize)
	body = append(body, 0x00, 0x00)
	body = binary.BigEndian.AppendUint32(body, 0)
	body = binary.BigEndian.AppendUint32(body, downloadScenario)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(modules)))
	for _, m := range modules {
		body = binary.BigEndian.AppendUint16(body, m.ID)
		body = binary.BigEndian.AppendUint32(body, m.Size)
		body = append(body, m.Version, 0x00)
	}
	body = binary.BigEndian.AppendUint16(body, 0)

	section := make([]byte, 0, mpegts.LongSectionOverhead+dsmccHeaderLen+len(body))
	section = mpegts.AppendLongSectionHeader(section, mpegts.TableIDDII, uint16(transactionID&0xffff), 0, 0, 0)
	section = appendMessageHeader(section, messageIDDII, transactionID, len(body))
	section = append(section, body...)
	section = mpegts.FinishSection(section)
	if len(section)-3 > mpegts.MaxSectionLength {
		return nil, fmt.Errorf("%w: DII section is %d bytes", ErrCapacityExceeded, len(section))
	}
	return section, nil
}

func BuildDDB(downloadID uint32, moduleID uint16, moduleVersion byte, blockNumber, last uint16, block []byte) ([]byte, error) {
	if len(block) > BlockSize {
		return nil, fmt.Errorf("preservation: block of %d bytes exceeds blockSize", len(block))
	}
	if blockNumber > last || int(last) >= MaxBlocks {
		return nil, fmt.Errorf("preservation: block %d of %d is out of range", blockNumber, last)
	}
	const ddbBodyHeader = 6
	body := ddbBodyHeader + len(block)
	s := make([]byte, 0, mpegts.LongSectionOverhead+dsmccHeaderLen+body)
	s = mpegts.AppendLongSectionHeader(s, mpegts.TableIDDDB, moduleID, moduleVersion&0x1f, byte(blockNumber), byte(last))
	s = appendMessageHeader(s, messageIDDDB, downloadID, body)
	s = binary.BigEndian.AppendUint16(s, moduleID)
	s = append(s, moduleVersion, 0xff)
	s = binary.BigEndian.AppendUint16(s, blockNumber)
	s = append(s, block...)
	return mpegts.FinishSection(s), nil
}

func appendMessageHeader(dst []byte, messageID uint16, id uint32, bodyLength int) []byte {
	dst = append(dst, protocolDiscriminator, dsmccTypeDownload)
	dst = binary.BigEndian.AppendUint16(dst, messageID)
	dst = binary.BigEndian.AppendUint32(dst, id)
	dst = append(dst, 0xff, 0x00)
	return binary.BigEndian.AppendUint16(dst, uint16(bodyLength))
}

func BlockCount(size int) int {
	if size <= 0 {
		return 0
	}
	return (size + BlockSize - 1) / BlockSize
}

func SplitModule(downloadID uint32, m ModuleEntry, module []byte) ([][]byte, error) {
	if len(module) != int(m.Size) {
		return nil, fmt.Errorf("preservation: module %#04x is %d bytes but the DII says %d", m.ID, len(module), m.Size)
	}
	blocks := BlockCount(len(module))
	if blocks == 0 || blocks > MaxBlocks {
		return nil, fmt.Errorf("%w: module %#04x needs %d blocks", ErrCapacityExceeded, m.ID, blocks)
	}
	out := make([][]byte, 0, blocks)
	for i := range blocks {
		end := min((i+1)*BlockSize, len(module))
		s, err := BuildDDB(downloadID, m.ID, m.Version, uint16(i), uint16(blocks-1), module[i*BlockSize:end])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
