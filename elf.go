package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	elfClass64 = 2
	elfDataLSB = 1
	etExec     = 2
	etDyn      = 3
	etCore     = 4
	ptLoad     = 1
	ptNote     = 4
	emX86_64   = 62
)

var errNotELF = errors.New("not an ELF64 file")

// progHeader is a parsed ELF64 program header.
type progHeader struct {
	typ    uint32
	flags  uint32
	off    uint64
	vaddr  uint64
	filesz uint64
	memsz  uint64
	align  uint64
}

// sectionHeader is a parsed ELF64 section header.
type sectionHeader struct {
	name    uint32
	typ     uint32
	flags   uint64
	addr    uint64
	off     uint64
	size    uint64
	link    uint32
	entsize uint64
	nameStr string
}

// elfFile is a validated, fully in-memory little-endian x86-64 ELF64 file.
type elfFile struct {
	data  []byte
	typ   uint16
	phdrs []progHeader
	shdrs []sectionHeader
}

// parseELF validates the ELF header and parses program/section headers.
// Any malformed, truncated or out-of-range structure rejects the whole file.
func parseELF(data []byte) (*elfFile, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("%w: file too small (%d bytes)", errNotELF, len(data))
	}
	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, fmt.Errorf("%w: bad magic", errNotELF)
	}
	if data[4] != elfClass64 {
		return nil, fmt.Errorf("%w: not ELF64", errNotELF)
	}
	if data[5] != elfDataLSB {
		return nil, fmt.Errorf("%w: not little-endian", errNotELF)
	}
	if data[6] != 1 {
		return nil, fmt.Errorf("%w: bad ELF version", errNotELF)
	}
	le := binary.LittleEndian
	typ := le.Uint16(data[16:18])
	machine := le.Uint16(data[18:20])
	if machine != emX86_64 {
		return nil, fmt.Errorf("unsupported machine %d (want x86-64)", machine)
	}
	phoff := le.Uint64(data[32:40])
	shoff := le.Uint64(data[40:48])
	phentsize := le.Uint16(data[54:56])
	phnum := le.Uint16(data[56:58])
	shentsize := le.Uint16(data[58:60])
	shnum := le.Uint16(data[60:62])
	shstrndx := le.Uint16(data[62:64])

	f := &elfFile{data: data, typ: typ}

	if phnum > 0 {
		if phentsize < 56 {
			return nil, fmt.Errorf("program header entry size %d too small", phentsize)
		}
		if _, ok := checkedRange(phoff, uint64(phentsize)*uint64(phnum), uint64(len(data))); !ok {
			return nil, errors.New("program header table out of range")
		}
		for i := 0; i < int(phnum); i++ {
			off := phoff + uint64(i)*uint64(phentsize)
			b := data[off : off+56]
			ph := progHeader{
				typ:    le.Uint32(b[0:4]),
				flags:  le.Uint32(b[4:8]),
				off:    le.Uint64(b[8:16]),
				vaddr:  le.Uint64(b[16:24]),
				filesz: le.Uint64(b[32:40]),
				memsz:  le.Uint64(b[40:48]),
				align:  le.Uint64(b[48:56]),
			}
			if ph.typ == ptLoad && ph.filesz > ph.memsz {
				return nil, fmt.Errorf("phdr %d: filesz > memsz", i)
			}
			if _, ok := checkedRange(ph.off, ph.filesz, uint64(len(data))); !ok {
				return nil, fmt.Errorf("phdr %d: file range out of bounds", i)
			}
			f.phdrs = append(f.phdrs, ph)
		}
	}

	if shnum > 0 {
		if shentsize < 64 {
			return nil, fmt.Errorf("section header entry size %d too small", shentsize)
		}
		if _, ok := checkedRange(shoff, uint64(shentsize)*uint64(shnum), uint64(len(data))); !ok {
			return nil, errors.New("section header table out of range")
		}
		for i := 0; i < int(shnum); i++ {
			off := shoff + uint64(i)*uint64(shentsize)
			b := data[off : off+64]
			sh := sectionHeader{
				name:    le.Uint32(b[0:4]),
				typ:     le.Uint32(b[4:8]),
				flags:   le.Uint64(b[8:16]),
				addr:    le.Uint64(b[16:24]),
				off:     le.Uint64(b[24:32]),
				size:    le.Uint64(b[32:40]),
				link:    le.Uint32(b[40:44]),
				entsize: le.Uint64(b[56:64]),
			}
			if sh.typ != 8 { // SHT_NOBITS occupies no file bytes
				if _, ok := checkedRange(sh.off, sh.size, uint64(len(data))); !ok {
					return nil, fmt.Errorf("section %d out of range", i)
				}
			}
			f.shdrs = append(f.shdrs, sh)
		}
		if int(shstrndx) < len(f.shdrs) {
			str := f.shdrs[shstrndx]
			if str.typ != 8 {
				tab := data[str.off : str.off+str.size]
				for i := range f.shdrs {
					f.shdrs[i].nameStr = cstr(tab, f.shdrs[i].name)
				}
			}
		}
	}
	return f, nil
}

// checkedRange verifies [off, off+size) lies within limit without overflow.
func checkedRange(off, size, limit uint64) (uint64, bool) {
	if off > limit || size > limit-off {
		return 0, false
	}
	return off + size, true
}

// cstr reads a NUL-terminated string from a string table at offset off.
func cstr(tab []byte, off uint32) string {
	if uint64(off) >= uint64(len(tab)) {
		return ""
	}
	s := tab[off:]
	for i, c := range s {
		if c == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}

// bytes returns the file bytes backing [off, off+size).
func (f *elfFile) bytes(off, size uint64) ([]byte, error) {
	if _, ok := checkedRange(off, size, uint64(len(f.data))); !ok {
		return nil, errors.New("file range out of bounds")
	}
	return f.data[off : off+size], nil
}
