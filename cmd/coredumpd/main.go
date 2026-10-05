package main

import (
	"log"
	"net/http"
	"os"

	"github.com/huangjie666777-ux/native-core-backtrace-199/internal/server"
)

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, server.NewRouter()))
}
