package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const maxRequestBytes = 64 << 20 // 64 MiB

type frameJSON struct {
	Address  string `json:"address"`
	Image    string `json:"image"`
	Function string `json:"function"`
	Offset   string `json:"offset"`
}

type threadJSON struct {
	TID    int         `json:"tid"`
	Signal int         `json:"signal"`
	RIP    string      `json:"rip"`
	RSP    string      `json:"rsp"`
	RBP    string      `json:"rbp"`
	Stop   string      `json:"stop_reason"`
	Frames []frameJSON `json:"frames"`
}

type responseJSON struct {
	Threads []threadJSON `json:"threads"`
}

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Post("/backtrace", handleBacktrace)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// handleBacktrace accepts multipart/form-data with one "core" file and
// any number of "images" files whose filenames are their original
// on-disk paths (used for matching only; host files are never read and
// uploaded files are never executed).
func handleBacktrace(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "multipart form required: "+err.Error(), http.StatusBadRequest)
		return
	}
	var coreData []byte
	images := map[string][]byte{}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, "reading form: "+err.Error(), http.StatusBadRequest)
			return
		}
		data, err := io.ReadAll(part)
		if err != nil {
			http.Error(w, "reading part: "+err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		switch part.FormName() {
		case "core":
			coreData = data
		case "images":
			path := rawFilename(part)
			if path == "" {
				http.Error(w, "image part missing original-path filename", http.StatusBadRequest)
				return
			}
			images[path] = data
		}
	}
	if len(coreData) == 0 {
		http.Error(w, "missing core file", http.StatusBadRequest)
		return
	}

	resp, err := analyze(coreData, images)
	if err != nil {
		http.Error(w, "analysis failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// analyze runs the full pipeline: parse core, notes, memory, unwind,
// then symbolize each frame against the uploaded images.
func analyze(coreData []byte, imageFiles map[string][]byte) (*responseJSON, error) {
	core, err := parseELF(coreData)
	if err != nil {
		return nil, fmt.Errorf("core: %w", err)
	}
	if core.typ != etCore {
		return nil, fmt.Errorf("core: not ET_CORE (type %d)", core.typ)
	}
	ns, err := parseNotes(core)
	if err != nil {
		return nil, fmt.Errorf("core notes: %w", err)
	}
	mem, err := newCoreMemory(core)
	if err != nil {
		return nil, fmt.Errorf("core memory: %w", err)
	}
	imgs, err := newImageSet(imageFiles, ns)
	if err != nil {
		return nil, err
	}

	resp := &responseJSON{}
	for _, ti := range ns.Threads {
		uw := unwind(mem, ti)
		tj := threadJSON{
			TID:    ti.TID,
			Signal: ti.Signal,
			RIP:    hex(ti.RIP),
			RSP:    hex(ti.RSP),
			RBP:    hex(ti.RBP),
			Stop:   uw.Stop,
		}
		for _, fr := range uw.Frames {
			fj := frameJSON{
				Address:  hex(fr.Address),
				Image:    "unknown",
				Function: "unknown",
				Offset:   "0x0",
			}
			if p, fn, off, ok := imgs.lookup(fr.Address); ok {
				fj.Image = p
				fj.Function = fn
				fj.Offset = hex(off)
			}
			tj.Frames = append(tj.Frames, fj)
		}
		resp.Threads = append(resp.Threads, tj)
	}
	return resp, nil
}

func hex(v uint64) string { return fmt.Sprintf("0x%x", v) }

// rawFilename extracts the filename parameter from Content-Disposition
// without stripping directory components: the original on-disk path is
// the image's identity. (mime/multipart's FileName applies filepath.Base.)
func rawFilename(part *multipart.Part) string {
	_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
	if err != nil {
		return ""
	}
	return params["filename"]
}
