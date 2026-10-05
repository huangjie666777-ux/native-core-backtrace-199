package corefile

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildCore(t *testing.T, mutate func(*coreBuilder)) []byte {
	t.Helper()
	b := newCoreBuilder()
	if mutate != nil {
		mutate(b)
	}
	return b.build()
}

type coreBuilder struct {
	threads  []Thread
	segs     []Segment
	files    []FileMap
	pageSize uint64
	extra    []byte // extra unknown note
}

func newCoreBuilder() *coreBuilder {
	return &coreBuilder{
		threads: []Thread{{TID: 1, Signal: 11, RIP: 0x1000, RSP: 0x8000, RBP: 0x8000}},
		segs: []Segment{
			{Vaddr: 0x8000, Filesz: 0x30, Memsz: 0x30, data: make([]byte, 0x30)},
		},
		files:    []FileMap{{Start: 0x400000, End: 0x401000, PageOff: 0, Path: "/bin/app"}},
		pageSize: 0x1000,
	}
}

func (b *coreBuilder) build() []byte {
	var notes bytes.Buffer
	put := func(ntype uint32, name string, desc []byte) {
		n := make([]byte, 12)
		binary.LittleEndian.PutUint32(n[0:], uint32(len(name)+1))
		binary.LittleEndian.PutUint32(n[4:], uint32(len(desc)))
		binary.LittleEndian.PutUint32(n[8:], ntype)
		notes.Write(n)
		notes.WriteString(name)
		notes.WriteByte(0)
		for notes.Len()%4 != 0 {
			notes.WriteByte(0)
		}
		notes.Write(desc)
		for notes.Len()%4 != 0 {
			notes.WriteByte(0)
		}
	}
	for _, th := range b.threads {
		desc := make([]byte, prstatusRegOff+27*8)
		binary.LittleEndian.PutUint16(desc[prstatusCursigOff:], uint16(th.Signal))
		binary.LittleEndian.PutUint32(desc[prstatusPidOff:], uint32(th.TID))
		binary.LittleEndian.PutUint64(desc[prstatusRegOff+regRIP*8:], th.RIP)
		binary.LittleEndian.PutUint64(desc[prstatusRegOff+regRSP*8:], th.RSP)
		binary.LittleEndian.PutUint64(desc[prstatusRegOff+regRBP*8:], th.RBP)
		put(ntPrstatus, "CORE", desc)
	}
	put(0x200, "CORE", make([]byte, 16)) // unknown note must be skipped
	if b.extra != nil {
		notes.Write(b.extra)
	}
	fdesc := make([]byte, 16+24*len(b.files))
	binary.LittleEndian.PutUint64(fdesc[0:], uint64(len(b.files)))
	binary.LittleEndian.PutUint64(fdesc[8:], b.pageSize)
	var names []byte
	for i, f := range b.files {
		e := fdesc[16+24*i:]
		binary.LittleEndian.PutUint64(e[0:], f.Start)
		binary.LittleEndian.PutUint64(e[8:], f.End)
		binary.LittleEndian.PutUint64(e[16:], f.PageOff)
		names = append(names, f.Path...)
		names = append(names, 0)
	}
	put(ntFile, "CORE", append(fdesc, names...))

	phnum := 1 + len(b.segs)
	phoff := 64
	dataOff := phoff + phnum*56
	var loads bytes.Buffer
	segOffs := make([]uint64, len(b.segs))
	for i, s := range b.segs {
		segOffs[i] = uint64(dataOff) + uint64(loads.Len())
		loads.Write(s.data[:s.Filesz])
	}
	noteOff := uint64(dataOff) + uint64(loads.Len())

	out := make([]byte, 64)
	copy(out, []byte{0x7f, 'E', 'L', 'F', elfClass64, elfDataLSB, 1, 0})
	binary.LittleEndian.PutUint16(out[16:], etCore)
	binary.LittleEndian.PutUint16(out[18:], emX86_64)
	binary.LittleEndian.PutUint64(out[32:], uint64(phoff))
	binary.LittleEndian.PutUint16(out[54:], 56)
	binary.LittleEndian.PutUint16(out[56:], uint16(phnum))
	out = append(out, make([]byte, dataOff-len(out))...)
	ph := func(i int) []byte { return out[phoff+i*56:] }
	for i, s := range b.segs {
		p := ph(i)
		binary.LittleEndian.PutUint32(p[0:], ptLoad)
		binary.LittleEndian.PutUint64(p[8:], segOffs[i])
		binary.LittleEndian.PutUint64(p[16:], s.Vaddr)
		binary.LittleEndian.PutUint64(p[32:], s.Filesz)
		binary.LittleEndian.PutUint64(p[40:], s.Memsz)
	}
	np := ph(len(b.segs))
	binary.LittleEndian.PutUint32(np[0:], ptNote)
	binary.LittleEndian.PutUint64(np[8:], noteOff)
	binary.LittleEndian.PutUint64(np[32:], uint64(notes.Len()))
	binary.LittleEndian.PutUint64(np[40:], uint64(notes.Len()))

	out = append(out, loads.Bytes()...)
	out = append(out, notes.Bytes()...)
	return out
}

func TestParseValidCore(t *testing.T) {
	c, err := Parse(buildCore(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Threads) != 1 || c.Threads[0].TID != 1 || c.Threads[0].Signal != 11 {
		t.Fatalf("threads: %+v", c.Threads)
	}
	if c.Threads[0].RIP != 0x1000 || c.Threads[0].RBP != 0x8000 {
		t.Fatalf("regs: %+v", c.Threads[0])
	}
	if len(c.Files) != 1 || c.Files[0].Path != "/bin/app" || c.PageSize != 0x1000 {
		t.Fatalf("files: %+v", c.Files)
	}
}

func TestRejectBadMagic(t *testing.T) {
	d := buildCore(t, nil)
	d[0] = 0
	if _, err := Parse(d); err == nil {
		t.Fatal("expected error")
	}
}

func TestRejectTruncated(t *testing.T) {
	d := buildCore(t, nil)
	if _, err := Parse(d[:len(d)/2]); err == nil {
		t.Fatal("expected error")
	}
}

func TestRejectDuplicateTID(t *testing.T) {
	d := buildCore(t, func(b *coreBuilder) {
		b.threads = append(b.threads, b.threads[0])
	})
	if _, err := Parse(d); err == nil {
		t.Fatal("expected duplicate TID error")
	}
}

func TestReadAtSkipsUndumped(t *testing.T) {
	b := newCoreBuilder()
	copy(b.segs[0].data, bytes.Repeat([]byte{0xAB}, 0x30))
	c, err := Parse(b.build())
	if err != nil {
		t.Fatal(err)
	}
	var buf [4]byte
	if n := c.ReadAt(0x8000, buf[:]); n != 4 {
		t.Fatalf("read %d", n)
	}
	if n := c.ReadAt(0x9000, buf[:]); n != 0 {
		t.Fatalf("undumped read %d", n)
	}
}
