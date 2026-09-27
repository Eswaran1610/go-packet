package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"

	"go-packet-explorer/internal/server"
)

//go:embed web/*
var webAssets embed.FS

func main() {
	addr := flag.String("addr", "localhost:8080", "HTTP server address")
	flag.Parse()

	// Extract the "web" subdirectory from the embedded filesystem
	webFS, err := fs.Sub(webAssets, "web")
	if err != nil {
		log.Fatal("Failed to load embedded web assets:", err)
	}

	srv := server.New()

	fmt.Printf("\n=== Go Packet Explorer (Web Edition) ===\n")
	fmt.Printf("Starting server on http://%s\n", *addr)
	fmt.Printf("Note: Live capture typically requires elevated privileges (e.g. sudo or CAP_NET_RAW)\n\n")

	// Start server (blocks)
	if err := srv.Start(*addr, http.FS(webFS)); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
