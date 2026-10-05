package main

import (
	"encoding/binary"
	"errors"
	"sort"
)

// errUnmapped is returned when an address falls outside every stored
// PT_LOAD range. Undumped regions are never zero-filled.
var errUnmapped = errors.New("address not in any dumped PT_LOAD range")

// segment is one stored PT_LOAD range of the core.
type segment struct {
	start uint64
	end   uint64 // start + filesz
	data  []byte
}

// coreMemory reads process memory from the core's stored PT_LOAD bytes.
type coreMemory struct {
	segs []segment // sorted by start
}

// newCoreMemory builds the address space from PT_LOAD stored bytes only.
func newCoreMemory(f *elfFile) (*coreMemory, error) {
	m := &coreMemory{}
	for _, ph := range f.phdrs {
		if ph.typ != ptLoad || ph.filesz == 0 {
			continue
		}
		b, err := f.bytes(ph.off, ph.filesz)
		if err != nil {
			return nil, err
		}
		m.segs = append(m.segs, segment{start: ph.vaddr, end: ph.vaddr + ph.filesz, data: b})
	}
	sort.Slice(m.segs, func(i, j int) bool { return m.segs[i].start < m.segs[j].start })
	return m, nil
}

// read copies n bytes at addr; fails if any byte is outside stored ranges.
func (m *coreMemory) read(addr uint64, n uint64) ([]byte, error) {
	for _, s := range m.segs {
		if addr >= s.start && addr < s.end {
			if n <= s.end-addr {
				return s.data[addr-s.start : addr-s.start+n], nil
			}
			return nil, errUnmapped
		}
	}
	return nil, errUnmapped
}

// u64 reads one little-endian uint64 at addr.
func (m *coreMemory) u64(addr uint64) (uint64, error) {
	b, err := m.read(addr, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}
