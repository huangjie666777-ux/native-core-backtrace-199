package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildCore synthesizes a minimal ET_CORE with given notes and loads.
func buildCore(t *testing.T, notes []noteRec, loads []loadRec) []byte {
	t.Helper()
	le := binary.LittleEndian
	var noteBuf bytes.Buffer
	for _, n := range notes {
		var nb bytes.Buffer
		binary.Write(&nb, le, uint32(len(n.name)+1))
		binary.Write(&nb, le, uint32(len(n.desc)))
		binary.Write(&nb, le, n.typ)
		nb.WriteString(n.name)
		nb.WriteByte(0)
		for nb.Len()%4 != 0 {
			nb.WriteByte(0)
		}
		nb.Write(n.desc)
		for nb.Len()%4 != 0 {
			nb.WriteByte(0)
		}
		noteBuf.Write(nb.Bytes())
	}
	phnum := 1 + len(loads)
	phoff := 64
	off := uint64(64 + 56*phnum)
	noteOff := off
	off += uint64(noteBuf.Len())
	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', elfClass64, elfDataLSB, 1})
	le.PutUint16(hdr[16:], etCore)
	le.PutUint16(hdr[18:], emX86_64)
	le.PutUint64(hdr[32:], uint64(phoff))
	le.PutUint16(hdr[54:], 56)
	le.PutUint16(hdr[56:], uint16(phnum))
	var ph bytes.Buffer
	binary.Write(&ph, le, progHeaderRaw{typ: ptNote, off: noteOff, filesz: uint64(noteBuf.Len()), memsz: uint64(noteBuf.Len())})
	var loadData bytes.Buffer
	for _, l := range loads {
		binary.Write(&ph, le, progHeaderRaw{typ: ptLoad, off: off, vaddr: l.vaddr, filesz: uint64(len(l.data)), memsz: uint64(len(l.data))})
		loadData.Write(l.data)
		off += uint64(len(l.data))
	}
	var out bytes.Buffer
	out.Write(hdr)
	out.Write(ph.Bytes())
	out.Write(noteBuf.Bytes())
	out.Write(loadData.Bytes())
	return out.Bytes()
}

type progHeaderRaw struct {
	typ    uint32
	flags  uint32
	off    uint64
	vaddr  uint64
	paddr  uint64
	filesz uint64
	memsz  uint64
	align  uint64
}

type noteRec struct {
	typ  uint32
	name string
	desc []byte
}

type loadRec struct {
	vaddr uint64
	data  []byte
}

// prstatusDesc builds an x86-64 NT_PRSTATUS descriptor.
func prstatusDesc(tid int, sig int, rip, rsp, rbp uint64) []byte {
	d := make([]byte, prRegOff+prRegCount*8)
	le := binary.LittleEndian
	le.PutUint16(d[prCursigOff:], uint16(sig))
	le.PutUint32(d[prPidOff:], uint32(tid))
	le.PutUint64(d[prRegOff+regRBP*8:], rbp)
	le.PutUint64(d[prRegOff+regRIP*8:], rip)
	le.PutUint64(d[prRegOff+regRSP*8:], rsp)
	return d
}

func TestParseELFBadMagic(t *testing.T) {
	if _, err := parseELF([]byte("not an elf at all, definitely")); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestParseELFTruncated(t *testing.T) {
	if _, err := parseELF([]byte{0x7f, 'E', 'L', 'F'}); err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestParseNotesThreads(t *testing.T) {
	core := buildCore(t, []noteRec{
		{typ: ntPrstatus, name: "CORE", desc: prstatusDesc(101, 11, 0xaaaa, 0x7000, 0)},
		{typ: 0x200, name: "CORE", desc: []byte{1, 2, 3}}, // unknown: skipped
		{typ: ntPrstatus, name: "CORE", desc: prstatusDesc(102, 6, 0xbbbb, 0x8000, 0)},
	}, nil)
	f, err := parseELF(core)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := parseNotes(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(ns.Threads) != 2 {
		t.Fatalf("want 2 threads, got %d", len(ns.Threads))
	}
	if ns.Threads[0].TID != 101 || ns.Threads[0].Signal != 11 || ns.Threads[0].RIP != 0xaaaa {
		t.Fatalf("bad thread: %+v", ns.Threads[0])
	}
}

func TestParseNotesDuplicateTID(t *testing.T) {
	core := buildCore(t, []noteRec{
		{typ: ntPrstatus, name: "CORE", desc: prstatusDesc(7, 11, 1, 2, 0)},
		{typ: ntPrstatus, name: "CORE", desc: prstatusDesc(7, 11, 1, 2, 0)},
	}, nil)
	f, _ := parseELF(core)
	if _, err := parseNotes(f); err == nil {
		t.Fatal("expected duplicate TID rejection")
	}
}

func TestParseNotesTruncatedDesc(t *testing.T) {
	core := buildCore(t, []noteRec{
		{typ: ntPrstatus, name: "CORE", desc: make([]byte, 10)},
	}, nil)
	f, _ := parseELF(core)
	if _, err := parseNotes(f); err == nil {
		t.Fatal("expected truncated prstatus rejection")
	}
}

// stackLoad builds a fake stack: frames chained via saved rbp/retaddr.
func stackLoad(base uint64, frames [][2]uint64) loadRec {
	data := make([]byte, 0x1000)
	le := binary.LittleEndian
	for _, fr := range frames {
		off := fr[0] - base
		le.PutUint64(data[off:], fr[1])     // saved rbp
		le.PutUint64(data[off+8:], fr[1]+9) // fake return address derived from next rbp
	}
	return loadRec{vaddr: base, data: data}
}

func TestUnwindZeroRBP(t *testing.T) {
	core := buildCore(t, []noteRec{{typ: ntPrstatus, name: "CORE", desc: prstatusDesc(1, 11, 0x1000, 0x9000, 0)}}, nil)
	f, _ := parseELF(core)
	ns, _ := parseNotes(f)
	mem, _ := newCoreMemory(f)
	res := unwind(mem, ns.Threads[0])
	if len(res.Frames) != 1 || res.Frames[0].Address != 0x1000 {
		t.Fatalf("bad frames: %+v", res.Frames)
	}
}

func TestUnwindChain(t *testing.T) {
	const base = 0x7fff0000
	// rbp chain: 0x100 -> 0x200 -> 0
	load := loadRec{vaddr: base, data: make([]byte, 0x1000)}
	le := binary.LittleEndian
	le.PutUint64(load.data[0x100:], base+0x200)
	le.PutUint64(load.data[0x108:], 0xdead)
	le.PutUint64(load.data[0x200:], 0)
	le.PutUint64(load.data[0x208:], 0xbeef)
	core := buildCore(t,
		[]noteRec{{typ: ntPrstatus, name: "CORE", desc: prstatusDesc(1, 11, 0xaaa, base+0x180, base+0x100)}},
		[]loadRec{load})
	f, _ := parseELF(core)
	ns, _ := parseNotes(f)
	mem, _ := newCoreMemory(f)
	res := unwind(mem, ns.Threads[0])
	if len(res.Frames) != 3 {
		t.Fatalf("want 3 frames, got %d (%+v)", len(res.Frames), res.Frames)
	}
	if res.Frames[1].Address != 0xdead || res.Frames[2].Address != 0xbeef {
		t.Fatalf("bad return addresses: %+v", res.Frames)
	}
	if res.Stop == "" {
		t.Fatal("expected stop reason")
	}
}

func TestUnwindUnmappedMemory(t *testing.T) {
	// rbp points outside all loads.
	core := buildCore(t,
		[]noteRec{{typ: ntPrstatus, name: "CORE", desc: prstatusDesc(1, 11, 0xaaa, 0x9000, 0x500000)}},
		nil)
	f, _ := parseELF(core)
	ns, _ := parseNotes(f)
	mem, _ := newCoreMemory(f)
	res := unwind(mem, ns.Threads[0])
	if len(res.Frames) != 1 {
		t.Fatalf("frames should keep only RIP, got %+v", res.Frames)
	}
	if res.Stop == "" {
		t.Fatal("expected stop reason for unmapped rbp")
	}
}

func TestUnwindCycle(t *testing.T) {
	const base = 0x7fff0000
	load := loadRec{vaddr: base, data: make([]byte, 0x1000)}
	le := binary.LittleEndian
	le.PutUint64(load.data[0x100:], base+0x200)
	le.PutUint64(load.data[0x108:], 0x1)
	le.PutUint64(load.data[0x200:], base+0x100) // cycle back
	le.PutUint64(load.data[0x208:], 0x2)
	core := buildCore(t,
		[]noteRec{{typ: ntPrstatus, name: "CORE", desc: prstatusDesc(1, 11, 0xaaa, base+0x180, base+0x100)}},
		[]loadRec{load})
	f, _ := parseELF(core)
	ns, _ := parseNotes(f)
	mem, _ := newCoreMemory(f)
	res := unwind(mem, ns.Threads[0])
	if len(res.Frames) != 3 {
		t.Fatalf("cycle should keep prior frames, got %+v", res.Frames)
	}
}

func TestUnwindMisaligned(t *testing.T) {
	core := buildCore(t,
		[]noteRec{{typ: ntPrstatus, name: "CORE", desc: prstatusDesc(1, 11, 0xaaa, 0x9000, 0x1003)}},
		nil)
	f, _ := parseELF(core)
	ns, _ := parseNotes(f)
	mem, _ := newCoreMemory(f)
	res := unwind(mem, ns.Threads[0])
	if len(res.Frames) != 1 || res.Stop == "" {
		t.Fatalf("misaligned rbp should stop: %+v", res)
	}
}
