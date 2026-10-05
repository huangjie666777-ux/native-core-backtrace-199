// Package unwind walks call stacks using the frame-pointer ABI.
package unwind

import "github.com/huangjie666777-ux/native-core-backtrace-199/internal/corefile"

// MaxFrames caps the number of frames per thread.
const MaxFrames = 64

// Frame is one return address on the call chain.
type Frame struct {
	PC uint64
}

// Result is the outcome of unwinding one thread.
type Result struct {
	Frames []Frame
	// StopReason is empty on a clean finish (frame pointer became zero).
	StopReason string
}

// Walk follows saved RBP/return-address pairs starting from the thread's
// registers. It never scans the stack for plausible addresses.
func Walk(c *corefile.Core, t corefile.Thread) Result {
	res := Result{Frames: []Frame{{PC: t.RIP}}}
	rbp := t.RBP
	seen := map[uint64]bool{}
	for len(res.Frames) < MaxFrames {
		if rbp == 0 {
			return res // normal end of chain
		}
		if rbp%8 != 0 {
			res.StopReason = "unaligned frame pointer"
			return res
		}
		if seen[rbp] {
			res.StopReason = "frame pointer cycle"
			return res
		}
		seen[rbp] = true
		savedRBP, ok := c.ReadU64(rbp)
		if !ok {
			res.StopReason = "saved rbp not in dumped memory"
			return res
		}
		ret, ok := c.ReadU64(rbp + 8)
		if !ok {
			res.StopReason = "return address not in dumped memory"
			return res
		}
		res.Frames = append(res.Frames, Frame{PC: ret})
		if savedRBP != 0 && savedRBP <= rbp {
			res.StopReason = "frame pointer chain not increasing"
			return res
		}
		rbp = savedRBP
	}
	res.StopReason = "frame limit reached"
	return res
}
