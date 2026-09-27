// Package handler is the Vercel Go serverless entrypoint. It reuses the same
// internal/server API handler as the standalone binary, minus static file
// serving (Vercel serves web/ directly, see vercel.json) and minus real
// packet capture (this binary is built with -tags nopcap; see
// internal/capture/capture_stub.go).
package handler

import (
	"net/http"

	"go-packet-explorer/internal/server"
)

var srv = server.New().Handler(nil)

// Handler is the exported entrypoint Vercel's Go runtime invokes per request.
func Handler(w http.ResponseWriter, r *http.Request) {
	srv.ServeHTTP(w, r)
}
