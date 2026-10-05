package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ntPrstatus = 1
	ntFile     = 0x46494c45
)

// threadInfo holds the per-thread register state from NT_PRSTATUS.
type threadInfo struct {
	TID    int
	Signal int
	RIP    uint64
	RSP    uint64
	RBP    uint64
}

// fileMapping is one NT_FILE entry: a file-backed virtual range.
type fileMapping struct {
	Start      uint64
	End        uint64
	FileOffset uint64 // page units of pageSize
	Path       string
}

// noteSet is everything we extract from PT_NOTE segments.
type noteSet struct {
	Threads  []threadInfo
	Mappings []fileMapping
	PageSize uint64
}

// x86-64 elf_prstatus layout offsets (after the note header).
const (
	prCursigOff = 12  // short pr_cursig
	prPidOff    = 32  // pid_t pr_pid
	prRegOff    = 112 // elf_gregset_t pr_reg[27]
	prRegCount  = 27
	// elf_gregset_t register indexes (sys/ucontext.h ordering).
	regRBP = 4
	regRIP = 16
	regRSP = 19
)

// parseNotes walks all PT_NOTE segments and extracts NT_PRSTATUS and
// NT_FILE. Unknown note types are skipped. Malformed known notes and
// duplicate TIDs reject the whole core.
func parseNotes(f *elfFile) (*noteSet, error) {
	ns := &noteSet{}
	seenTID := map[int]bool{}
	le := binary.LittleEndian

	for _, ph := range f.phdrs {
		if ph.typ != ptNote {
			continue
		}
		buf, err := f.bytes(ph.off, ph.filesz)
		if err != nil {
			return nil, fmt.Errorf("PT_NOTE: %w", err)
		}
		for len(buf) > 0 {
			if len(buf) < 12 {
				return nil, errors.New("truncated note header")
			}
			namesz := le.Uint32(buf[0:4])
			descsz := le.Uint32(buf[4:8])
			ntype := le.Uint32(buf[8:12])
			buf = buf[12:]
			nameLen := align4(uint64(namesz))
			descLen := align4(uint64(descsz))
			if nameLen > uint64(len(buf)) {
				return nil, errors.New("truncated note name")
			}
			name := buf[:nameLen]
			buf = buf[nameLen:]
			if descLen > uint64(len(buf)) {
				return nil, errors.New("truncated note descriptor")
			}
			desc := buf[:descLen]
			buf = buf[descLen:]

			switch ntype {
			case ntPrstatus:
				ti, err := parsePrstatus(desc)
				if err != nil {
					return nil, err
				}
				if seenTID[ti.TID] {
					return nil, fmt.Errorf("duplicate TID %d in NT_PRSTATUS", ti.TID)
				}
				seenTID[ti.TID] = true
				ns.Threads = append(ns.Threads, ti)
			case ntFile:
				maps, ps, err := parseNTFile(desc)
				if err != nil {
					return nil, err
				}
				ns.Mappings = append(ns.Mappings, maps...)
				ns.PageSize = ps
			default:
				_ = name // unknown note: skip
			}
		}
	}
	if len(ns.Threads) == 0 {
		return nil, errors.New("no NT_PRSTATUS notes found")
	}
	return ns, nil
}

func align4(v uint64) uint64 { return (v + 3) &^ 3 }

// parsePrstatus decodes an x86-64 NT_PRSTATUS descriptor.
func parsePrstatus(desc []byte) (threadInfo, error) {
	var ti threadInfo
	need := prRegOff + prRegCount*8
	if len(desc) < need {
		return ti, fmt.Errorf("NT_PRSTATUS descriptor too small: %d < %d", len(desc), need)
	}
	le := binary.LittleEndian
	ti.Signal = int(le.Uint16(desc[prCursigOff:]))
	ti.TID = int(int32(le.Uint32(desc[prPidOff:])))
	reg := func(i int) uint64 {
		return le.Uint64(desc[prRegOff+i*8:])
	}
	ti.RBP = reg(regRBP)
	ti.RIP = reg(regRIP)
	ti.RSP = reg(regRSP)
	return ti, nil
}

// parseNTFile decodes an NT_FILE descriptor: count, page size, the
// (start, end, offset) triples, then the NUL-separated filename table.
func parseNTFile(desc []byte) ([]fileMapping, uint64, error) {
	if len(desc) < 16 {
		return nil, 0, errors.New("NT_FILE descriptor too small")
	}
	le := binary.LittleEndian
	count := le.Uint64(desc[0:8])
	pageSize := le.Uint64(desc[8:16])
	if pageSize == 0 {
		return nil, 0, errors.New("NT_FILE page size is zero")
	}
	tableBytes := count * 24
	if count > (1<<20) || tableBytes > uint64(len(desc))-16 {
		return nil, 0, errors.New("NT_FILE mapping table out of range")
	}
	entries := desc[16 : 16+tableBytes]
	names := desc[16+tableBytes:]

	// Split the filename table into NUL-terminated strings.
	var paths []string
	start := 0
	for i, b := range names {
		if b == 0 {
			paths = append(paths, string(names[start:i]))
			start = i + 1
		}
	}
	if uint64(len(paths)) < count {
		return nil, 0, errors.New("NT_FILE filename table truncated")
	}

	maps := make([]fileMapping, 0, count)
	for i := uint64(0); i < count; i++ {
		b := entries[i*24:]
		maps = append(maps, fileMapping{
			Start:      le.Uint64(b[0:8]),
			End:        le.Uint64(b[8:16]),
			FileOffset: le.Uint64(b[16:24]),
			Path:       paths[i],
		})
	}
	return maps, pageSize, nil
}
