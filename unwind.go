package main

import "fmt"

const maxFrames = 64

// frame is one call-site in a thread's call chain.
type frame struct {
	Address uint64 // RIP of this frame
}

// unwindResult is the per-thread backtrace plus why walking stopped.
type unwindResult struct {
	Frames []frame
	Stop   string
}

// unwind walks the frame-pointer chain starting at the thread's RIP.
// It never scans the stack for plausible addresses; only the classic
// x86-64 frame-pointer ABI ([rbp]=saved rbp, [rbp+8]=return address).
func unwind(mem *coreMemory, ti threadInfo) unwindResult {
	res := unwindResult{}
	res.Frames = append(res.Frames, frame{Address: ti.RIP})

	rbp := ti.RBP
	if rbp == 0 {
		res.Stop = "frame pointer is zero (end of chain)"
		return res
	}
	seen := map[uint64]bool{rbp: true}

	for len(res.Frames) < maxFrames {
		if rbp%8 != 0 {
			res.Stop = fmt.Sprintf("frame pointer %#x is not 8-byte aligned", rbp)
			return res
		}
		savedRBP, err := mem.u64(rbp)
		if err != nil {
			res.Stop = fmt.Sprintf("cannot read saved rbp at %#x: %v", rbp, err)
			return res
		}
		retAddr, err := mem.u64(rbp + 8)
		if err != nil {
			res.Stop = fmt.Sprintf("cannot read return address at %#x: %v", rbp+8, err)
			return res
		}
		res.Frames = append(res.Frames, frame{Address: retAddr})
		if savedRBP == 0 {
			res.Stop = "frame pointer is zero (end of chain)"
			return res
		}
		if savedRBP <= rbp {
			res.Stop = fmt.Sprintf("frame pointer chain not increasing: %#x -> %#x", rbp, savedRBP)
			return res
		}
		if seen[savedRBP] {
			res.Stop = fmt.Sprintf("frame pointer cycle at %#x", savedRBP)
			return res
		}
		seen[savedRBP] = true
		rbp = savedRBP
	}
	res.Stop = fmt.Sprintf("frame limit %d reached", maxFrames)
	return res
}
