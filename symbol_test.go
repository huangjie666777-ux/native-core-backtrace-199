package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// compileTestPIE builds a tiny PIE binary for symbol/bias tests.
func compileTestPIE(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "m.c")
	bin := filepath.Join(dir, "m")
	code := "static int inner(int x){return x+1;} int main(){return inner(41);}"
	if err := os.WriteFile(src, []byte(code), 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("gcc", "-g", "-fno-omit-frame-pointer", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("gcc: %v %s", err, out)
	}
	return bin
}

func TestLoadBiasAndSymbols(t *testing.T) {
	bin := compileTestPIE(t)
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	ef, err := parseELF(data)
	if err != nil {
		t.Fatal(err)
	}
	if ef.typ != etDyn {
		t.Fatalf("test binary should be PIE (ET_DYN), got %d", ef.typ)
	}
	const base = 0x555555554000
	ns := &noteSet{
		PageSize: 0x1000,
		Mappings: []fileMapping{{Start: base, End: base + 0x1000, FileOffset: 0, Path: bin}},
	}
	set, err := newImageSet(map[string][]byte{bin: data}, ns)
	if err != nil {
		t.Fatal(err)
	}
	img := set.images[0]
	if img.bias != base {
		t.Fatalf("bias: got %#x want %#x", img.bias, base)
	}
	var mainAddr uint64
	for _, s := range img.syms {
		if s.name == "main" {
			mainAddr = s.start
		}
	}
	if mainAddr == 0 {
		t.Fatal("main not found in symbols")
	}
	p, fn, off, ok := set.lookup(mainAddr + 5)
	if !ok || fn != "main" || off != 5 || p != bin {
		t.Fatalf("lookup: %q %q %#x %v", p, fn, off, ok)
	}
	if _, _, _, ok := set.lookup(0x1234); ok {
		t.Fatal("lookup of unmapped address should fail")
	}
}

func TestLoadBiasNonZeroFileOffset(t *testing.T) {
	bin := compileTestPIE(t)
	data, _ := os.ReadFile(bin)
	ef, _ := parseELF(data)
	var seg *progHeader
	for i := range ef.phdrs {
		if ef.phdrs[i].typ == ptLoad && ef.phdrs[i].off > 0 && ef.phdrs[i].flags&1 != 0 {
			seg = &ef.phdrs[i]
			break
		}
	}
	if seg == nil {
		t.Skip("no suitable PT_LOAD")
	}
	const base = 0x7f0000000000
	if seg.off%0x1000 != 0 {
		t.Skip("segment file offset not page aligned")
	}
	mapStart := base + seg.vaddr
	ns := &noteSet{
		PageSize: 0x1000,
		Mappings: []fileMapping{{
			Start:      mapStart,
			End:        mapStart + 0x2000,
			FileOffset: seg.off / 0x1000,
			Path:       bin,
		}},
	}
	set, err := newImageSet(map[string][]byte{bin: data}, ns)
	if err != nil {
		t.Fatal(err)
	}
	if set.images[0].bias != base {
		t.Fatalf("bias with file offset: got %#x want %#x", set.images[0].bias, base)
	}
}

func TestNTFileRoundTrip(t *testing.T) {
	le := binary.LittleEndian
	var desc bytes.Buffer
	binary.Write(&desc, le, uint64(2))      // count
	binary.Write(&desc, le, uint64(0x1000)) // page size
	binary.Write(&desc, le, uint64(0x1000))
	binary.Write(&desc, le, uint64(0x2000))
	binary.Write(&desc, le, uint64(0))
	binary.Write(&desc, le, uint64(0x3000))
	binary.Write(&desc, le, uint64(0x4000))
	binary.Write(&desc, le, uint64(4))
	desc.WriteString("/bin/a" + string(byte(0)) + "/lib/b.so" + string(byte(0)))
	maps, ps, err := parseNTFile(desc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if ps != 0x1000 || len(maps) != 2 {
		t.Fatalf("bad NT_FILE: %d %d", ps, len(maps))
	}
	if maps[1].Path != "/lib/b.so" || maps[1].FileOffset != 4 {
		t.Fatalf("bad mapping: %+v", maps[1])
	}
}
