package server

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

func tinyCore() []byte {
	desc := make([]byte, 112+27*8)
	binary.LittleEndian.PutUint32(desc[32:], 42)             // tid
	binary.LittleEndian.PutUint16(desc[12:], 11)             // signal
	binary.LittleEndian.PutUint64(desc[112+16*8:], 0x401234) // rip
	note := make([]byte, 12)
	binary.LittleEndian.PutUint32(note[0:], 5)
	binary.LittleEndian.PutUint32(note[4:], uint32(len(desc)))
	binary.LittleEndian.PutUint32(note[8:], 1)
	note = append(note, []byte("CORE\x00\x00\x00\x00")...)
	note = append(note, desc...)
	hdr := make([]byte, 64+56)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(hdr[16:], 4)
	binary.LittleEndian.PutUint16(hdr[18:], 62)
	binary.LittleEndian.PutUint64(hdr[32:], 64)
	binary.LittleEndian.PutUint16(hdr[54:], 56)
	binary.LittleEndian.PutUint16(hdr[56:], 1)
	ph := hdr[64:]
	binary.LittleEndian.PutUint32(ph[0:], 4)
	binary.LittleEndian.PutUint64(ph[8:], uint64(len(hdr)))
	binary.LittleEndian.PutUint64(ph[32:], uint64(len(note)))
	binary.LittleEndian.PutUint64(ph[40:], uint64(len(note)))
	return append(hdr, note...)
}

func post(t *testing.T, body *bytes.Buffer, ct string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/backtrace", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	NewRouter().ServeHTTP(rec, req)
	return rec
}

func TestBacktraceEndpoint(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("core", "core.1")
	fw.Write(tinyCore())
	mw.Close()
	rec := post(t, &body, mw.FormDataContentType())
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var out response
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Threads) != 1 || out.Threads[0].TID != 42 || out.Threads[0].Signal != 11 {
		t.Fatalf("%+v", out)
	}
	fr := out.Threads[0].Frames
	if len(fr) != 1 || fr[0].Address != "0x401234" || fr[0].Image != "unknown" {
		t.Fatalf("frames %+v", fr)
	}
}

func TestRejectsGarbage(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("core", "core.1")
	fw.Write([]byte("not an elf"))
	mw.Close()
	rec := post(t, &body, mw.FormDataContentType())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d", rec.Code)
	}
}
