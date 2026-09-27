//go:build nopcap

package capture

import (
	"sync"

	"github.com/google/gopacket"
)

// ListInterfaces reports no interfaces: this build has no libpcap access.
// It does not fake interfaces — the caller must surface ErrUnavailable as-is.
func ListInterfaces() ([]InterfaceInfo, error) {
	return nil, ErrUnavailable
}

// Session is a no-op stand-in that always reports itself as inactive.
type Session struct {
	mu sync.Mutex
}

// NewSession returns a new, always-idle session.
func NewSession() *Session {
	return &Session{}
}

// Start always fails: this build cannot open a live capture device.
func (s *Session) Start(ifaceName, bpfFilter string) error {
	return ErrUnavailable
}

// Stop is a no-op; there is never an active capture to stop.
func (s *Session) Stop() {}

// Packets returns nil: no capture session ever starts in this build.
func (s *Session) Packets() <-chan gopacket.Packet {
	return nil
}

// Active always reports false.
func (s *Session) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return false
}

// Interface always reports "".
func (s *Session) Interface() string {
	return ""
}

// Stats always reports zero; there is nothing to measure.
func (s *Session) Stats() (received, dropped, ifDropped int, err error) {
	return 0, 0, 0, nil
}
