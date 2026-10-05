package unwind

import (
	"encoding/binary"
	"testing"

	"github.com/huangjie666777-ux/native-core-backtrace-199/internal/corefile"
)

// stackCore builds a core whose single PT_LOAD is a synthetic stack.
func stackCore(t *testing.T, stackBase uint64, stack []byte) *corefile.Core {
	t.Helper()
	hdr := make([]byte, 64+2*56)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(hdr[16:], 4)
	binary.LittleEndian.PutUint16(hdr[18:], 62)
	binary.LittleEndian.PutUint64(hdr[32:], 64)
	binary.LittleEndian.PutUint16(hdr[54:], 56)
	binary.LittleEndian.PutUint16(hdr[56:], 2)
	// PT_LOAD with the stack
	ph := hdr[64:]
	binary.LittleEndian.PutUint32(ph[0:], 1)
	binary.LittleEndian.PutUint64(ph[8:], uint64(len(hdr)))
	binary.LittleEndian.PutUint64(ph[16:], stackBase)
	binary.LittleEndian.PutUint64(ph[32:], uint64(len(stack)))
	binary.LittleEndian.PutUint64(ph[40:], uint64(len(stack)))
	// PT_NOTE with one NT_PRSTATUS
	desc := make([]byte, 112+27*8)
	binary.LittleEndian.PutUint32(desc[32:], 7)
	note := make([]byte, 12)
	binary.LittleEndian.PutUint32(note[0:], 5)
	binary.LittleEndian.PutUint32(note[4:], uint32(len(desc)))
	binary.LittleEndian.PutUint32(note[8:], 1)
	note = append(note, []byte("CORE\x00\x00\x00\x00")...)
	note = append(note, desc...)
	np := hdr[64+56:]
	binary.LittleEndian.PutUint32(np[0:], 4)
	binary.LittleEndian.PutUint64(np[8:], uint64(len(hdr)+len(stack)))
	binary.LittleEndian.PutUint64(np[32:], uint64(len(note)))
	binary.LittleEndian.PutUint64(np[40:], uint64(len(note)))
	data := append(hdr, stack...)
	data = append(data, note...)
	c, err := corefile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const base = 0x7000

func putChain(stack []byte, rbp uint64, savedRBP, ret uint64) {
	binary.LittleEndian.PutUint64(stack[rbp-base:], savedRBP)
	binary.LittleEndian.PutUint64(stack[rbp-base+8:], ret)
}

func thread(rbp uint64) corefile.Thread {
	return corefile.Thread{TID: 7, RIP: 0xaaaa, RBP: rbp}
}

func TestWalkCleanEnd(t *testing.T) {
	stack := make([]byte, 0x100)
	putChain(stack, base+0x10, base+0x40, 0xbbbb)
	putChain(stack, base+0x40, 0, 0xcccc)
	c := stackCore(t, base, stack)
	r := Walk(c, thread(base+0x10))
	if r.StopReason != "" {
		t.Fatalf("stop: %s", r.StopReason)
	}
	want := []uint64{0xaaaa, 0xbbbb, 0xcccc}
	if len(r.Frames) != len(want) {
		t.Fatalf("frames %+v", r.Frames)
	}
	for i, w := range want {
		if r.Frames[i].PC != w {
			t.Fatalf("frame %d = %#x want %#x", i, r.Frames[i].PC, w)
		}
	}
}

func TestWalkUnaligned(t *testing.T) {
	c := stackCore(t, base, make([]byte, 0x100))
	r := Walk(c, thread(base+3))
	if r.StopReason != "unaligned frame pointer" || len(r.Frames) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestWalkCycle(t *testing.T) {
	stack := make([]byte, 0x100)
	putChain(stack, base+0x10, base+0x10, 0xbbbb)
	c := stackCore(t, base, stack)
	r := Walk(c, thread(base+0x10))
	if r.StopReason != "frame pointer chain not increasing" || len(r.Frames) != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestWalkMissingMemory(t *testing.T) {
	c := stackCore(t, base, make([]byte, 0x100))
	r := Walk(c, thread(0xdead0000))
	if r.StopReason != "saved rbp not in dumped memory" || len(r.Frames) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestWalkFrameLimit(t *testing.T) {
	stack := make([]byte, MaxFrames*0x10+0x10)
	for i := 0; i < MaxFrames+1; i++ {
		putChain(stack, base+uint64(i)*0x10, base+uint64(i+1)*0x10, uint64(0x1000+i))
	}
	c := stackCore(t, base, stack)
	r := Walk(c, thread(base))
	if len(r.Frames) != MaxFrames || r.StopReason != "frame limit reached" {
		t.Fatalf("frames=%d stop=%s", len(r.Frames), r.StopReason)
	}
}
