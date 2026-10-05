// Package corefile parses 64-bit little-endian x86-64 ELF core files.
package corefile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

const (
	elfClass64 = 2
	elfDataLSB = 1
	emX86_64   = 62
	etCore     = 4

	ptLoad = 1
	ptNote = 4

	ntPrstatus = 1
	ntFile     = 0x46494c65
	ntFileAlt  = 0x46494c45

	// Offsets inside linux elf_prstatus (x86-64).
	prstatusCursigOff = 12
	prstatusPidOff    = 32
	prstatusRegOff    = 112

	// Indices inside user_regs_struct (x86-64).
	regRBP = 4
	regRIP = 16
	regRSP = 19
)

// Thread holds the register state of one NT_PRSTATUS note.
type Thread struct {
	TID    int32
	Signal int16
	RIP    uint64
	RSP    uint64
	RBP    uint64
}

// Segment is one PT_LOAD range; only Filesz bytes are backed by the file.
type Segment struct {
	Vaddr  uint64
	Off    uint64
	Filesz uint64
	Memsz  uint64
	data   []byte
}

// FileMap is one NT_FILE mapping entry.
type FileMap struct {
	Start   uint64
	End     uint64
	PageOff uint64
	Path    string
}

// Core is a parsed core file.
type Core struct {
	Threads  []Thread
	Segments []Segment
	Files    []FileMap
	PageSize uint64
}

var le = binary.LittleEndian

// Parse validates and parses a whole core file image.
func Parse(data []byte) (*Core, error) {
	if len(data) < 64 {
		return nil, errors.New("truncated ELF header")
	}
	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, errors.New("not an ELF file")
	}
	if data[4] != elfClass64 || data[5] != elfDataLSB {
		return nil, errors.New("only 64-bit little-endian ELF is supported")
	}
	if et := le.Uint16(data[16:]); et != etCore {
		return nil, fmt.Errorf("ELF type %d is not ET_CORE", et)
	}
	if m := le.Uint16(data[18:]); m != emX86_64 {
		return nil, fmt.Errorf("machine %d is not x86-64", m)
	}
	phoff := le.Uint64(data[32:])
	phentsize := uint64(le.Uint16(data[54:]))
	phnum := uint64(le.Uint16(data[56:]))
	if phentsize < 56 {
		return nil, fmt.Errorf("program header entry size %d too small", phentsize)
	}
	if phnum > 0 && (phoff > uint64(len(data)) || phnum > (uint64(len(data))-phoff)/phentsize) {
		return nil, errors.New("program header table out of bounds")
	}

	c := &Core{}
	seenTID := map[int32]bool{}
	for i := uint64(0); i < phnum; i++ {
		ph := data[phoff+i*phentsize:]
		ptype := le.Uint32(ph[0:])
		poff := le.Uint64(ph[8:])
		vaddr := le.Uint64(ph[16:])
		filesz := le.Uint64(ph[32:])
		memsz := le.Uint64(ph[40:])
		if ptype == ptLoad && filesz > memsz {
			return nil, fmt.Errorf("phdr %d: filesz exceeds memsz", i)
		}
		if poff > uint64(len(data)) || filesz > uint64(len(data))-poff {
			return nil, fmt.Errorf("phdr %d: file range out of bounds", i)
		}
		switch ptype {
		case ptLoad:
			c.Segments = append(c.Segments, Segment{
				Vaddr: vaddr, Off: poff, Filesz: filesz, Memsz: memsz,
				data: data[poff : poff+filesz],
			})
		case ptNote:
			if err := c.parseNotes(data[poff:poff+filesz], seenTID); err != nil {
				return nil, err
			}
		}
	}
	if len(c.Threads) == 0 {
		return nil, errors.New("no NT_PRSTATUS notes found")
	}
	sort.Slice(c.Segments, func(i, j int) bool { return c.Segments[i].Vaddr < c.Segments[j].Vaddr })
	return c, nil
}

func (c *Core) parseNotes(notes []byte, seenTID map[int32]bool) error {
	for len(notes) >= 12 {
		namesz := le.Uint32(notes[0:])
		descsz := le.Uint32(notes[4:])
		ntype := le.Uint32(notes[8:])
		if namesz == 0 && descsz == 0 && ntype == 0 {
			break // trailing zero padding
		}
		rest := notes[12:]
		if uint64(namesz) > uint64(len(rest)) {
			return errors.New("note name out of bounds")
		}
		rest = rest[align4(uint64(namesz)):]
		if uint64(descsz) > uint64(len(rest)) {
			return errors.New("note descriptor out of bounds")
		}
		desc := rest[:descsz]
		var err error
		switch ntype {
		case ntPrstatus:
			err = c.parsePrstatus(desc, seenTID)
		case ntFile, ntFileAlt:
			err = c.parseNTFile(desc)
		default: // unknown notes are skipped
		}
		if err != nil {
			return err
		}
		notes = rest[align4(uint64(descsz)):]
	}
	return nil
}

func align4(v uint64) uint64 { return (v + 3) &^ 3 }

func (c *Core) parsePrstatus(desc []byte, seenTID map[int32]bool) error {
	need := prstatusRegOff + 27*8
	if len(desc) < need {
		return fmt.Errorf("NT_PRSTATUS descriptor too small: %d", len(desc))
	}
	tid := int32(le.Uint32(desc[prstatusPidOff:]))
	if seenTID[tid] {
		return fmt.Errorf("duplicate TID %d", tid)
	}
	seenTID[tid] = true
	regs := desc[prstatusRegOff:]
	c.Threads = append(c.Threads, Thread{
		TID:    tid,
		Signal: int16(le.Uint16(desc[prstatusCursigOff:])),
		RBP:    le.Uint64(regs[regRBP*8:]),
		RIP:    le.Uint64(regs[regRIP*8:]),
		RSP:    le.Uint64(regs[regRSP*8:]),
	})
	return nil
}

func (c *Core) parseNTFile(desc []byte) error {
	if len(desc) < 16 {
		return errors.New("NT_FILE descriptor too small")
	}
	count := le.Uint64(desc[0:])
	c.PageSize = le.Uint64(desc[8:])
	if count > (uint64(len(desc))-16)/24 {
		return errors.New("NT_FILE entries out of bounds")
	}
	names := desc[16+count*24:]
	paths := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		j := 0
		for j < len(names) && names[j] != 0 {
			j++
		}
		if j >= len(names) {
			return errors.New("NT_FILE filenames truncated")
		}
		paths = append(paths, string(names[:j]))
		names = names[j+1:]
	}
	for i := uint64(0); i < count; i++ {
		e := desc[16+i*24:]
		c.Files = append(c.Files, FileMap{
			Start:   le.Uint64(e[0:]),
			End:     le.Uint64(e[8:]),
			PageOff: le.Uint64(e[16:]),
			Path:    paths[i],
		})
	}
	return nil
}

// ReadAt reads len(buf) bytes at virtual address addr. It returns the
// number of bytes actually available from stored (dumped) ranges; memory
// that was not dumped is never zero-filled.
func (c *Core) ReadAt(addr uint64, buf []byte) int {
	n := 0
	for n < len(buf) {
		a := addr + uint64(n)
		i := sort.Search(len(c.Segments), func(i int) bool {
			return c.Segments[i].Vaddr+c.Segments[i].Filesz > a
		})
		if i >= len(c.Segments) || c.Segments[i].Vaddr > a {
			return n
		}
		s := &c.Segments[i]
		off := a - s.Vaddr
		avail := s.Filesz - off
		want := uint64(len(buf) - n)
		if avail > want {
			avail = want
		}
		copy(buf[n:], s.data[off:off+avail])
		n += int(avail)
	}
	return n
}

// ReadU64 reads one 8-byte word; ok is false if it is not fully stored.
func (c *Core) ReadU64(addr uint64) (v uint64, ok bool) {
	var b [8]byte
	if c.ReadAt(addr, b[:]) != 8 {
		return 0, false
	}
	return le.Uint64(b[:]), true
}
