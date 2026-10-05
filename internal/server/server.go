// Package server exposes the core backtrace HTTP API.
package server

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/huangjie666777-ux/native-core-backtrace-199/internal/corefile"
	"github.com/huangjie666777-ux/native-core-backtrace-199/internal/symbol"
	"github.com/huangjie666777-ux/native-core-backtrace-199/internal/unwind"
)

// MaxRequestSize caps uploaded request bodies at 64 MiB.
const MaxRequestSize = 64 << 20

type threadResult struct {
	TID        int32              `json:"tid"`
	Signal     int16              `json:"signal"`
	RIP        string             `json:"rip"`
	RSP        string             `json:"rsp"`
	RBP        string             `json:"rbp"`
	Frames     []symbol.FrameInfo `json:"frames"`
	StopReason string             `json:"stop_reason,omitempty"`
}

type response struct {
	Threads []threadResult `json:"threads"`
}

// NewRouter builds the chi router.
func NewRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Post("/api/backtrace", handleBacktrace)
	r.Get("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return r
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func handleBacktrace(w http.ResponseWriter, req *http.Request) {
	req.Body = http.MaxBytesReader(w, req.Body, MaxRequestSize)
	mr, err := req.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "multipart form required: "+err.Error())
		return
	}
	var coreData []byte
	var images []*symbol.Image
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "reading form: "+err.Error())
			return
		}
		data, err := io.ReadAll(io.LimitReader(part, MaxRequestSize))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "reading part: "+err.Error())
			return
		}
		switch part.FormName() {
		case "core":
			coreData = data
		case "image":
			path := part.Header.Get("X-Image-Path")
			if path == "" {
				// The filename carries the original on-target path; it is
				// only used for matching against NT_FILE entries.
				path = part.FileName()
			}
			img, err := symbol.ParseImage(path, data)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "image "+path+": "+err.Error())
				return
			}
			images = append(images, img)
		}
		part.Close()
	}
	if coreData == nil {
		writeErr(w, http.StatusBadRequest, "missing core part")
		return
	}
	core, err := corefile.Parse(coreData)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "core: "+err.Error())
		return
	}
	res := symbol.NewResolver(core, images)
	out := response{Threads: []threadResult{}}
	for _, t := range core.Threads {
		uw := unwind.Walk(core, t)
		tr := threadResult{
			TID:        t.TID,
			Signal:     t.Signal,
			RIP:        hex(t.RIP),
			RSP:        hex(t.RSP),
			RBP:        hex(t.RBP),
			Frames:     make([]symbol.FrameInfo, 0, len(uw.Frames)),
			StopReason: uw.StopReason,
		}
		for _, f := range uw.Frames {
			tr.Frames = append(tr.Frames, res.Resolve(f.PC))
		}
		out.Threads = append(out.Threads, tr)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func hex(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0x0"
	}
	var b [16]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v&0xf]
		v >>= 4
	}
	return "0x" + string(b[i:])
}
