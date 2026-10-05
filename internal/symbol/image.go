// Package symbol parses uploaded ELF images and resolves addresses to
// functions using NT_FILE mappings and PT_LOAD-derived load biases.
package symbol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/huangjie666777-ux/native-core-backtrace-199/internal/corefile"
)

const (
	etExec    = 2
	etDyn     = 3
	ptLoad    = 1
	shtSymtab = 2
	shtDynsym = 11
	sttFunc   = 2
	shnUndef  = 0
)

var le = binary.LittleEndian

type loadSeg struct {
	off    uint64
	vaddr  uint64
	filesz uint64
}

type sym struct {
	name  string
	value uint64
	size  uint64
}

// Image is one uploaded executable or shared library.
type Image struct {
	Path    string
	bias    uint64
	biasSet bool
	segs    []loadSeg
	funcs   []sym // sorted by value, non-zero size STT_FUNC
}

// ParseImage validates an uploaded ELF image (ET_EXEC or ET_DYN).
func ParseImage(path string, data []byte) (*Image, error) {
	if len(data) < 64 {
		return nil, errors.New("truncated ELF header")
	}
	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, errors.New("not an ELF file")
	}
	if data[4] != 2 || data[5] != 1 {
		return nil, errors.New("only 64-bit little-endian ELF is supported")
	}
	if et := le.Uint16(data[16:]); et != etExec && et != etDyn {
		return nil, fmt.Errorf("ELF type %d is not ET_EXEC/ET_DYN", et)
	}
	if m := le.Uint16(data[18:]); m != 62 {
		return nil, fmt.Errorf("machine %d is not x86-64", m)
	}
	img := &Image{Path: path}

	phoff := le.Uint64(data[32:])
	phentsize := uint64(le.Uint16(data[54:]))
	phnum := uint64(le.Uint16(data[56:]))
	if phentsize < 56 {
		return nil, errors.New("program header entry size too small")
	}
	if phnum > 0 && (phoff > uint64(len(data)) || phnum > (uint64(len(data))-phoff)/phentsize) {
		return nil, errors.New("program header table out of bounds")
	}
	for i := uint64(0); i < phnum; i++ {
		ph := data[phoff+i*phentsize:]
		if le.Uint32(ph[0:]) != ptLoad {
			continue
		}
		img.segs = append(img.segs, loadSeg{
			off:    le.Uint64(ph[8:]),
			vaddr:  le.Uint64(ph[16:]),
			filesz: le.Uint64(ph[32:]),
		})
	}

	shoff := le.Uint64(data[40:])
	shentsize := uint64(le.Uint16(data[58:]))
	shnum := uint64(le.Uint16(data[60:]))
	if shnum == 0 {
		return img, nil
	}
	if shentsize < 64 || shoff > uint64(len(data)) || shnum > (uint64(len(data))-shoff)/shentsize {
		return nil, errors.New("section header table out of bounds")
	}
	shdr := func(i uint64) []byte { return data[shoff+i*shentsize:] }
	var syms []sym
	for _, want := range []uint32{shtSymtab, shtDynsym} {
		if len(syms) > 0 {
			break // prefer .symtab over .dynsym
		}
		for i := uint64(0); i < shnum; i++ {
			sh := shdr(i)
			if le.Uint32(sh[4:]) != want {
				continue
			}
			off := le.Uint64(sh[24:])
			size := le.Uint64(sh[32:])
			link := le.Uint32(sh[40:])
			entsize := le.Uint64(sh[56:])
			if entsize < 24 || off > uint64(len(data)) || size > uint64(len(data))-off {
				return nil, errors.New("symbol table out of bounds")
			}
			if uint64(link) >= shnum {
				return nil, errors.New("string table index out of bounds")
			}
			strsh := shdr(uint64(link))
			stroff := le.Uint64(strsh[24:])
			strsize := le.Uint64(strsh[32:])
			if stroff > uint64(len(data)) || strsize > uint64(len(data))-stroff {
				return nil, errors.New("string table out of bounds")
			}
			strs := data[stroff : stroff+strsize]
			for o := uint64(0); o+24 <= size; o += entsize {
				e := data[off+o:]
				if e[4]&0xf != sttFunc {
					continue
				}
				if le.Uint16(e[6:]) == shnUndef {
					continue
				}
				sz := le.Uint64(e[16:])
				if sz == 0 {
					continue
				}
				nameOff := le.Uint32(e[0:])
				if uint64(nameOff) >= uint64(len(strs)) {
					continue
				}
				name := cstr(strs[nameOff:])
				syms = append(syms, sym{name: name, value: le.Uint64(e[8:]), size: sz})
			}
		}
	}
	sort.Slice(syms, func(i, j int) bool { return syms[i].value < syms[j].value })
	img.funcs = syms
	return img, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// computeBias derives the load bias from an NT_FILE mapping: the mapping's
// file offset must fall inside a PT_LOAD segment; bias = mapStart -
// (segVaddr + (fileOff - segOff)). It never assumes the lowest mapping
// start is the bias.
func (img *Image) computeBias(m corefile.FileMap, pageSize uint64) bool {
	if pageSize == 0 {
		return false
	}
	foff := m.PageOff * pageSize
	for _, s := range img.segs {
		if foff >= s.off && foff < s.off+s.filesz {
			img.bias = m.Start - (s.vaddr + (foff - s.off))
			img.biasSet = true
			return true
		}
	}
	return false
}

// contains reports whether vaddr (pre-relocation) lies in a PT_LOAD range.
func (img *Image) contains(vaddr uint64) bool {
	for _, s := range img.segs {
		if vaddr >= s.vaddr && vaddr < s.vaddr+s.filesz {
			return true
		}
	}
	return false
}

// lookup finds the innermost STT_FUNC covering vaddr (pre-relocation).
func (img *Image) lookup(vaddr uint64) (sym, bool) {
	i := sort.Search(len(img.funcs), func(i int) bool { return img.funcs[i].value > vaddr }) - 1
	for ; i >= 0; i-- {
		s := img.funcs[i]
		if vaddr >= s.value && vaddr < s.value+s.size {
			return s, true
		}
		if s.value+s.size <= vaddr && i < len(img.funcs)-1 {
			break
		}
	}
	return sym{}, false
}

// Resolver maps runtime addresses to images and functions.
type Resolver struct {
	mappings []mapping
}

type mapping struct {
	start, end uint64
	img        *Image
}

// NewResolver binds uploaded images to NT_FILE mappings by path.
func NewResolver(c *corefile.Core, images []*Image) *Resolver {
	r := &Resolver{}
	byPath := map[string]*Image{}
	byBase := map[string]*Image{}
	for _, img := range images {
		byPath[img.Path] = img
		base := img.Path
		if i := len(base) - 1; i >= 0 {
			for i >= 0 && base[i] != '/' {
				i--
			}
			base = base[i+1:]
		}
		if _, dup := byBase[base]; !dup {
			byBase[base] = img
		}
	}
	for _, fm := range c.Files {
		img := byPath[fm.Path]
		if img == nil {
			base := fm.Path
			if i := len(base) - 1; i >= 0 {
				for i >= 0 && base[i] != '/' {
					i--
				}
				base = base[i+1:]
			}
			img = byBase[base]
		}
		if img == nil {
			continue
		}
		if !img.biasSet && !img.computeBias(fm, c.PageSize) {
			continue
		}
		r.mappings = append(r.mappings, mapping{start: fm.Start, end: fm.End, img: img})
	}
	return r
}

// FrameInfo describes one resolved frame.
type FrameInfo struct {
	Address  string `json:"address"`
	Image    string `json:"image"`
	Function string `json:"function"`
	Offset   string `json:"offset"`
}

// Resolve converts a runtime PC to image/function information.
func (r *Resolver) Resolve(pc uint64) FrameInfo {
	fi := FrameInfo{
		Address:  fmt.Sprintf("0x%x", pc),
		Image:    "unknown",
		Function: "unknown",
		Offset:   "0x0",
	}
	for _, m := range r.mappings {
		if pc < m.start || pc >= m.end {
			continue
		}
		vaddr := pc - m.img.bias
		if !m.img.contains(vaddr) {
			continue
		}
		fi.Image = m.img.Path
		if s, ok := m.img.lookup(vaddr); ok {
			fi.Function = s.name
			fi.Offset = fmt.Sprintf("0x%x", vaddr-s.value)
		}
		return fi
	}
	return fi
}
