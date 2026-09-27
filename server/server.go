// Package server provides the HTTP and WebSocket API for the web UI.
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"go-packet-explorer/internal/capture"
	"go-packet-explorer/internal/conversation"
	"go-packet-explorer/internal/packet"
	"go-packet-explorer/internal/pcapio"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Server coordinates capture, processing, and WebSocket clients.
type Server struct {
	capSession *capture.Session
	tracker    *conversation.Tracker

	// Packet storage
	mu           sync.RWMutex
	packets      []gopacket.Packet // raw packets
	decodedMsgs  []packet.PacketInfo // pre-decoded info for quick send
	
	// Client management
	clientMu sync.Mutex
	clients  map[chan<- interface{}]struct{}
	nextID   int
}

// New returns a new Server.
func New() *Server {
	return &Server{
		capSession: capture.NewSession(),
		tracker:    conversation.NewTracker(),
		clients:    make(map[chan<- interface{}]struct{}),
	}
}

// WSMessage is the envelope for WebSocket messages.
type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// Handler builds the HTTP mux for the API and, if staticFS is non-nil, the
// static web UI. staticFS is nil in deployments (e.g. Vercel) where static
// assets are served separately from this Go handler.
func (s *Server) Handler(staticFS http.FileSystem) http.Handler {
	mux := http.NewServeMux()

	// API
	mux.HandleFunc("/api/interfaces", s.handleInterfaces)
	mux.HandleFunc("/api/start", s.handleStartCapture)
	mux.HandleFunc("/api/stop", s.handleStopCapture)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/clear", s.handleClear)
	mux.HandleFunc("/api/conversations", s.handleConversations)
	mux.HandleFunc("/api/export", s.handleExport)
	mux.HandleFunc("/api/import", s.handleImport)

	// WebSocket
	mux.HandleFunc("/ws", s.handleWS)

	if staticFS != nil {
		mux.Handle("/", http.FileServer(staticFS))
	}

	return mux
}

// Start runs the HTTP server standalone, blocking until it exits.
func (s *Server) Start(addr string, staticFS http.FileSystem) error {
	log.Printf("Server listening on http://%s", addr)
	return http.ListenAndServe(addr, s.Handler(staticFS))
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(ifaces)
}

func (s *Server) handleStartCapture(w http.ResponseWriter, r *http.Request) {
	iface := r.URL.Query().Get("interface")
	bpf := r.URL.Query().Get("bpf")
	if iface == "" {
		http.Error(w, "interface parameter required", http.StatusBadRequest)
		return
	}

	if s.capSession.Active() {
		s.capSession.Stop()
	}

	err := s.capSession.Start(iface, bpf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go s.processPackets()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Capture started"))
}

func (s *Server) handleStopCapture(w http.ResponseWriter, r *http.Request) {
	s.capSession.Stop()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Capture stopped"))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	recv, drop, ifDrop, err := s.capSession.Stats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.RLock()
	count := len(s.packets)
	s.mu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"received":  recv,
		"dropped":   drop,
		"ifDropped": ifDrop,
		"saved":     count,
		"active":    s.capSession.Active(),
	})
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.packets = nil
	s.decodedMsgs = nil
	s.mu.Unlock()
	s.tracker.Clear()
	s.nextID = 0
	
	s.broadcast(WSMessage{Type: "clear"})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleConversations(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(s.tracker.List())
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	packets := s.packets
	s.mu.RUnlock()

	if len(packets) == 0 {
		http.Error(w, "no packets to export", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="capture.pcap"`)

	// Assuming Ethernet link type for now.
	pcapio.WriteTo(w, layers.LinkTypeEthernet, packets)
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Need a ReadSeeker for pcapio
	tmpFile, err := os.CreateTemp("", "import-*.pcap")
	if err != nil {
		http.Error(w, "failed to create temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	io.Copy(tmpFile, file)
	tmpFile.Seek(0, io.SeekStart)

	packets, err := pcapio.ReadFromReader(tmpFile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.capSession.Stop() // stop any active capture
	
	s.handleClear(w, r) // Clear state

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, pkt := range packets {
		s.nextID++
		id := s.nextID
		s.packets = append(s.packets, pkt)
		info := packet.Decode(pkt, id)

		// Track conversation
		conv := s.tracker.Track(info.Protocol, info.SrcAddr, info.SrcPort, info.DstAddr, info.DstPort,
			info.ID, info.Length, info.TCPFlags, info.Timestamp, pkt.Metadata().Timestamp)
		info.ConversationID = conv.ID
		s.decodedMsgs = append(s.decodedMsgs, info)
		
		s.broadcast(WSMessage{Type: "packet", Payload: info})
	}
	
	w.WriteHeader(http.StatusOK)
}


func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	// Simple polling fallback instead of full websockets to avoid external dependencies
	// For production, use gorilla/websocket.
	
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	msgChan := make(chan interface{}, 100)
	s.clientMu.Lock()
	s.clients[msgChan] = struct{}{}
	s.clientMu.Unlock()

	defer func() {
		s.clientMu.Lock()
		delete(s.clients, msgChan)
		s.clientMu.Unlock()
	}()

	// Send backlog
	s.mu.RLock()
	for _, info := range s.decodedMsgs {
		msgChan <- WSMessage{Type: "packet", Payload: info}
	}
	s.mu.RUnlock()

	notify := r.Context().Done()

	for {
		select {
		case <-notify:
			return
		case msg := <-msgChan:
			data, _ := json.Marshal(msg)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *Server) processPackets() {
	pktCh := s.capSession.Packets()
	if pktCh == nil {
		return
	}
	
	// Batch updates
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var batch []packet.PacketInfo
	batchLimit := 100

	for {
		select {
		case pkt, ok := <-pktCh:
			if !ok {
				return // capture stopped
			}
			
			s.mu.Lock()
			s.nextID++
			id := s.nextID
			s.packets = append(s.packets, pkt)
			
			// Prevent unbounded memory growth in browser/backend for long captures
			if len(s.packets) > 10000 {
				s.packets = s.packets[1:]
				s.decodedMsgs = s.decodedMsgs[1:]
			}
			s.mu.Unlock()

			info := packet.Decode(pkt, id)
			
			// Track conversation
			conv := s.tracker.Track(info.Protocol, info.SrcAddr, info.SrcPort, info.DstAddr, info.DstPort,
				info.ID, info.Length, info.TCPFlags, info.Timestamp, pkt.Metadata().Timestamp)
			info.ConversationID = conv.ID

			s.mu.Lock()
			s.decodedMsgs = append(s.decodedMsgs, info)
			s.mu.Unlock()

			batch = append(batch, info)
			if len(batch) >= batchLimit {
				s.broadcastBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				s.broadcastBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (s *Server) broadcastBatch(infos []packet.PacketInfo) {
	msg := WSMessage{Type: "packets", Payload: infos}
	s.broadcast(msg)
}

func (s *Server) broadcast(msg interface{}) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- msg:
		default:
		}
	}
}
