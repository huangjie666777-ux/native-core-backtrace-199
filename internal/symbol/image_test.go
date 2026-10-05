package symbol

import (
	"encoding/binary"
	"testing"

	"github.com/huangjie666777-ux/native-core-backtrace-199/internal/corefile"
)

// buildImage creates a minimal ET_DYN with two PT_LOAD segments and a
// .symtab holding two STT_FUNC symbols.
func buildImage() []byte {
	const (
		phoff  = 64
		phnum  = 2
		symoff = 0x400
		stroff = 0x500
		shoff  = 0x600
		shnum  = 3 // null, .symtab, .strtab
	)
	data := make([]byte, 0x800)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(data[16:], 3)  // ET_DYN
	binary.LittleEndian.PutUint16(data[18:], 62) // x86-64
	binary.LittleEndian.PutUint64(data[32:], phoff)
	binary.LittleEndian.PutUint64(data[40:], shoff)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[56:], phnum)
	binary.LittleEndian.PutUint16(data[58:], 64)
	binary.LittleEndian.PutUint16(data[60:], shnum)
	// PT_LOAD #1: file 0x0-0x200 -> vaddr 0x0
	ph := data[phoff:]
	binary.LittleEndian.PutUint32(ph[0:], 1)
	binary.LittleEndian.PutUint64(ph[8:], 0)
	binary.LittleEndian.PutUint64(ph[16:], 0)
	binary.LittleEndian.PutUint64(ph[32:], 0x200)
	// PT_LOAD #2: file 0x1000-0x1200 -> vaddr 0x2000 (non-zero p_offset)
	ph = data[phoff+56:]
	binary.LittleEndian.PutUint32(ph[0:], 1)
	binary.LittleEndian.PutUint64(ph[8:], 0x1000)
	binary.LittleEndian.PutUint64(ph[16:], 0x2000)
	binary.LittleEndian.PutUint64(ph[32:], 0x200)
	// .strtab
	strs := []byte("\x00alpha\x00beta\x00")
	copy(data[stroff:], strs)
	// .symtab: null + alpha@0x2100 size 0x30 + beta@0x40 size 0x10
	sym := func(i int, nameOff uint32, value, size uint64) {
		e := data[symoff+i*24:]
		binary.LittleEndian.PutUint32(e[0:], nameOff)
		e[4] = 0x12 // STB_GLOBAL|STT_FUNC
		e[5] = 0
		binary.LittleEndian.PutUint16(e[6:], 1)
		binary.LittleEndian.PutUint64(e[8:], value)
		binary.LittleEndian.PutUint64(e[16:], size)
	}
	sym(1, 1, 0x2100, 0x30)
	sym(2, 7, 0x40, 0x10)
	// section headers
	sh := func(i int, shtype uint32, off, size, link, entsize uint64) {
		h := data[shoff+i*64:]
		binary.LittleEndian.PutUint32(h[4:], shtype)
		binary.LittleEndian.PutUint64(h[24:], off)
		binary.LittleEndian.PutUint64(h[32:], size)
		binary.LittleEndian.PutUint32(h[40:], uint32(link))
		binary.LittleEndian.PutUint64(h[56:], entsize)
	}
	sh(1, 2, symoff, 3*24, 2, 24) // .symtab
	sh(2, 3, stroff, uint64(len(strs)), 0, 0)
	return data
}

func TestBiasAndResolve(t *testing.T) {
	img, err := ParseImage("/lib/libx.so", buildImage())
	if err != nil {
		t.Fatal(err)
	}
	if len(img.funcs) != 2 {
		t.Fatalf("funcs: %+v", img.funcs)
	}
	// Runtime maps file offset 0x1000 (page 1) at 0x7f0000001000, so the
	// bias must be 0x7f0000001000 - 0x2000 - (0x1000-0x1000) ... derived
	// from the PT_LOAD containing file offset 0x1000: vaddr 0x2000.
	core := &corefile.Core{
		PageSize: 0x1000,
		Files: []corefile.FileMap{
			{Start: 0x7f0000000000, End: 0x7f0000000200, PageOff: 0, Path: "/lib/libx.so"},
			{Start: 0x7f0000002000, End: 0x7f0000002200, PageOff: 1, Path: "/lib/libx.so"},
		},
	}
	res := NewResolver(core, []*Image{img})
	// alpha at vaddr 0x2100 -> runtime 0x7f0000002100
	fi := res.Resolve(0x7f0000002104)
	if fi.Image != "/lib/libx.so" || fi.Function != "alpha" || fi.Offset != "0x4" {
		t.Fatalf("%+v", fi)
	}
	// beta at vaddr 0x40 -> runtime 0x7f0000000040
	fi = res.Resolve(0x7f000000004f)
	if fi.Function != "beta" || fi.Offset != "0xf" {
		t.Fatalf("%+v", fi)
	}
	// outside any mapping
	fi = res.Resolve(0xdeadbeef)
	if fi.Image != "unknown" || fi.Function != "unknown" {
		t.Fatalf("%+v", fi)
	}
	// inside mapping but outside any function
	fi = res.Resolve(0x7f0000002180)
	if fi.Image != "/lib/libx.so" || fi.Function != "unknown" {
		t.Fatalf("%+v", fi)
	}
}

func TestBiasNotLowestMapping(t *testing.T) {
	img, err := ParseImage("/lib/libx.so", buildImage())
	if err != nil {
		t.Fatal(err)
	}
	// Only the second mapping is present; bias must still be derived
	// from the PT_LOAD covering file offset 0x1000.
	core := &corefile.Core{
		PageSize: 0x1000,
		Files: []corefile.FileMap{
			{Start: 0x550000000000, End: 0x550000000200, PageOff: 1, Path: "/lib/libx.so"},
		},
	}
	res := NewResolver(core, []*Image{img})
	// bias = 0x550000000000 - (0x2000 + 0) ; alpha runtime = bias+0x2100
	fi := res.Resolve(0x550000000000 - 0x2000 + 0x2100)
	if fi.Function != "alpha" {
		t.Fatalf("%+v", fi)
	}
}

func TestRejectNonImage(t *testing.T) {
	d := buildImage()
	binary.LittleEndian.PutUint16(d[16:], 4) // ET_CORE not allowed as image
	if _, err := ParseImage("x", d); err == nil {
		t.Fatal("expected error")
	}
}
