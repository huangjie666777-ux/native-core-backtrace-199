package main

import (
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	shtSymtab = 2
	shtDynsym = 11
	sttFunc   = 2
)

// sym is one relocated STT_FUNC range.
type sym struct {
	start uint64 // relocated virtual address
	end   uint64
	name  string
}

// image is an uploaded ET_EXEC/ET_DYN file with its computed load bias.
type image struct {
	path string
	bias uint64
	syms []sym // sorted by start
}

// imageSet resolves addresses to images and functions.
type imageSet struct {
	images []*image
}

// newImageSet parses uploaded images and computes each one's load bias
// from the core's NT_FILE mappings combined with the image's PT_LOADs.
func newImageSet(files map[string][]byte, ns *noteSet) (*imageSet, error) {
	set := &imageSet{}
	for path, data := range files {
		ef, err := parseELF(data)
		if err != nil {
			return nil, fmt.Errorf("image %s: %w", path, err)
		}
		if ef.typ != etExec && ef.typ != etDyn {
			return nil, fmt.Errorf("image %s: not ET_EXEC/ET_DYN (type %d)", path, ef.typ)
		}
		img := &image{path: path}
		img.bias = loadBias(ef, ns, path)
		if err := img.loadSymbols(ef); err != nil {
			return nil, fmt.Errorf("image %s: %w", path, err)
		}
		set.images = append(set.images, img)
	}
	return set, nil
}

// loadBias derives the relocation delta for an image by matching NT_FILE
// mappings of its path against PT_LOAD segments. It never assumes the
// lowest mapping start is the bias: the mapped file offset is subtracted
// via the containing PT_LOAD's p_vaddr/p_offset relationship.
func loadBias(ef *elfFile, ns *noteSet, path string) uint64 {
	for _, m := range ns.Mappings {
		if m.Path != path {
			continue
		}
		fileOff := m.FileOffset * ns.PageSize
		for _, ph := range ef.phdrs {
			if ph.typ != ptLoad {
				continue
			}
			// Does this mapping's file offset fall inside the segment?
			if fileOff < ph.off || fileOff-ph.off >= max64(ph.filesz, 1) {
				continue
			}
			vaddrAtMap := ph.vaddr + (fileOff - ph.off)
			if m.Start >= vaddrAtMap {
				return m.Start - vaddrAtMap
			}
		}
	}
	return 0
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// loadSymbols reads .symtab and .dynsym, keeping non-zero-size STT_FUNC
// symbols relocated by the load bias.
func (img *image) loadSymbols(ef *elfFile) error {
	le := binary.LittleEndian
	for _, sh := range ef.shdrs {
		if sh.typ != shtSymtab && sh.typ != shtDynsym {
			continue
		}
		if sh.entsize < 24 || sh.size == 0 {
			continue
		}
		if int(sh.link) >= len(ef.shdrs) {
			return fmt.Errorf("%s: bad string table link", sh.nameStr)
		}
		strSh := ef.shdrs[sh.link]
		symtab, err := ef.bytes(sh.off, sh.size)
		if err != nil {
			return err
		}
		strtab, err := ef.bytes(strSh.off, strSh.size)
		if err != nil {
			return err
		}
		count := sh.size / sh.entsize
		for i := uint64(0); i < count; i++ {
			b := symtab[i*sh.entsize:]
			info := b[4]
			if info&0xf != sttFunc {
				continue
			}
			value := le.Uint64(b[8:16])
			size := le.Uint64(b[16:24])
			if size == 0 {
				continue
			}
			nameOff := le.Uint32(b[0:4])
			name := cstr(strtab, nameOff)
			if name == "" {
				continue
			}
			img.syms = append(img.syms, sym{
				start: value + img.bias,
				end:   value + img.bias + size,
				name:  name,
			})
		}
	}
	sort.Slice(img.syms, func(i, j int) bool { return img.syms[i].start < img.syms[j].start })
	return nil
}

// lookup finds the image and function containing addr.
func (set *imageSet) lookup(addr uint64) (imgPath, fnName string, fnOff uint64, ok bool) {
	for _, img := range set.images {
		// Binary search for the last sym with start <= addr.
		i := sort.Search(len(img.syms), func(i int) bool { return img.syms[i].start > addr }) - 1
		if i >= 0 && addr < img.syms[i].end {
			return img.path, img.syms[i].name, addr - img.syms[i].start, true
		}
	}
	return "", "", 0, false
}
