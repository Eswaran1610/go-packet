// Package conversation tracks network conversations (flows) between endpoints.
package conversation

import (
	"sync"
	"time"
)

// TCPState represents the observed TCP connection state.
type TCPState int

const (
	TCPUnknown      TCPState = iota
	TCPSynSent               // SYN observed
	TCPSynAckSeen            // SYN+ACK observed
	TCPEstablished           // Three-way handshake completed
	TCPFinWait               // FIN observed
	TCPClosed                // RST or both FINs observed
)

// String returns a human-readable TCP state name.
func (s TCPState) String() string {
	switch s {
	case TCPSynSent:
		return "SYN Sent"
	case TCPSynAckSeen:
		return "SYN-ACK Seen"
	case TCPEstablished:
		return "Established"
	case TCPFinWait:
		return "FIN Wait"
	case TCPClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// Key uniquely identifies a bidirectional conversation.
type Key struct {
	Protocol string
	AddrA    string
	PortA    string
	AddrB    string
	PortB    string
}

// MakeKey builds a direction-independent conversation key.
func MakeKey(proto, srcAddr, srcPort, dstAddr, dstPort string) Key {
	a := srcAddr + ":" + srcPort
	b := dstAddr + ":" + dstPort
	if a > b {
		return Key{proto, dstAddr, dstPort, srcAddr, srcPort}
	}
	return Key{proto, srcAddr, srcPort, dstAddr, dstPort}
}

// HandshakeStep records one step in a TCP handshake or teardown.
type HandshakeStep struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Flags    string `json:"flags"`
	PacketID int    `json:"packetId"`
	Time     string `json:"time"`
}

// Conversation holds the state for a single tracked flow.
type Conversation struct {
	ID          int             `json:"id"`
	Protocol    string          `json:"protocol"`
	AddrA       string          `json:"addrA"`
	PortA       string          `json:"portA"`
	AddrB       string          `json:"addrB"`
	PortB       string          `json:"portB"`
	PacketIDs   []int           `json:"packetIds"`
	PacketCount int             `json:"packetCount"`
	ByteCount   int             `json:"byteCount"`
	StartTime   time.Time       `json:"startTime"`
	LastTime    time.Time       `json:"lastTime"`
	TCPState    TCPState        `json:"tcpState"`
	TCPStateStr string          `json:"tcpStateStr"`
	Handshake   []HandshakeStep `json:"handshake"`
}

// Tracker maintains a map of active conversations.
type Tracker struct {
	mu     sync.RWMutex
	convos map[Key]*Conversation
	nextID int
}

// NewTracker returns an empty conversation tracker.
func NewTracker() *Tracker {
	return &Tracker{
		convos: make(map[Key]*Conversation),
	}
}

// Track records a packet in the appropriate conversation and returns it.
func (t *Tracker) Track(proto, srcAddr, srcPort, dstAddr, dstPort string,
	packetID, length int, tcpFlags, timestamp string, ts time.Time) *Conversation {

	key := MakeKey(proto, srcAddr, srcPort, dstAddr, dstPort)

	t.mu.Lock()
	defer t.mu.Unlock()

	conv, exists := t.convos[key]
	if !exists {
		t.nextID++
		conv = &Conversation{
			ID:        t.nextID,
			Protocol:  proto,
			AddrA:     key.AddrA,
			PortA:     key.PortA,
			AddrB:     key.AddrB,
			PortB:     key.PortB,
			StartTime: ts,
		}
		t.convos[key] = conv
	}

	conv.PacketIDs = append(conv.PacketIDs, packetID)
	conv.PacketCount++
	conv.ByteCount += length
	conv.LastTime = ts

	// Track TCP handshake and state transitions.
	if tcpFlags != "" {
		from := srcAddr + ":" + srcPort
		to := dstAddr + ":" + dstPort
		conv.Handshake = append(conv.Handshake, HandshakeStep{
			From:     from,
			To:       to,
			Flags:    tcpFlags,
			PacketID: packetID,
			Time:     timestamp,
		})
		conv.updateTCPState(tcpFlags)
		conv.TCPStateStr = conv.TCPState.String()
	}

	return conv
}

func (c *Conversation) updateTCPState(flags string) {
	switch c.TCPState {
	case TCPUnknown:
		if flags == "SYN" {
			c.TCPState = TCPSynSent
		}
	case TCPSynSent:
		if flags == "SYN, ACK" {
			c.TCPState = TCPSynAckSeen
		} else if flags == "RST" || flags == "RST, ACK" {
			c.TCPState = TCPClosed
		}
	case TCPSynAckSeen:
		if flags == "ACK" {
			c.TCPState = TCPEstablished
		} else if flags == "RST" || flags == "RST, ACK" {
			c.TCPState = TCPClosed
		}
	case TCPEstablished:
		if flags == "FIN" || flags == "FIN, ACK" {
			c.TCPState = TCPFinWait
		} else if flags == "RST" || flags == "RST, ACK" {
			c.TCPState = TCPClosed
		}
	case TCPFinWait:
		if flags == "FIN" || flags == "FIN, ACK" || flags == "RST" || flags == "RST, ACK" {
			c.TCPState = TCPClosed
		}
	}
}

// List returns all tracked conversations.
func (t *Tracker) List() []*Conversation {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*Conversation, 0, len(t.convos))
	for _, c := range t.convos {
		result = append(result, c)
	}
	return result
}

// Get returns a conversation by ID, or nil if not found.
func (t *Tracker) Get(id int) *Conversation {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, c := range t.convos {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// Clear removes all tracked conversations.
func (t *Tracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.convos = make(map[Key]*Conversation)
	t.nextID = 0
}
