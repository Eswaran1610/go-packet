// Package capture manages live packet capture using libpcap.
package capture

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// InterfaceInfo holds metadata about a network interface available for capture.
type InterfaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// ListInterfaces returns the network interfaces that libpcap can capture on.
func ListInterfaces() ([]InterfaceInfo, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("finding capture devices (try running with sudo or set CAP_NET_RAW): %w", err)
	}

	interfaces := make([]InterfaceInfo, 0, len(devs))
	for _, d := range devs {
		info := InterfaceInfo{Name: d.Name}
		for _, addr := range d.Addresses {
			info.Addresses = append(info.Addresses, addr.IP.String())
		}
		interfaces = append(interfaces, info)
	}
	return interfaces, nil
}

// Session manages a single live packet capture.
type Session struct {
	mu     sync.Mutex
	handle *pcap.Handle
	stopCh chan struct{}
	pktCh  chan gopacket.Packet
	active bool
	iface  string
}

// NewSession returns a new, idle capture session.
func NewSession() *Session {
	return &Session{}
}

// Start begins capturing packets on the named interface.
// An optional BPF filter expression narrows what is captured.
// The returned packet channel is closed when the session stops.
func (s *Session) Start(ifaceName, bpfFilter string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active {
		return fmt.Errorf("capture already running on %s", s.iface)
	}

	handle, err := pcap.OpenLive(ifaceName, 65535, true, time.Second)
	if err != nil {
		return fmt.Errorf("opening %s: %w", ifaceName, err)
	}

	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			return fmt.Errorf("setting BPF filter %q: %w", bpfFilter, err)
		}
	}

	s.handle = handle
	s.stopCh = make(chan struct{})
	s.pktCh = make(chan gopacket.Packet, 2000)
	s.active = true
	s.iface = ifaceName

	go s.loop()
	return nil
}

// loop reads packets until the session is stopped or the handle is closed.
func (s *Session) loop() {
	defer close(s.pktCh)

	source := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	packets := source.Packets()

	for {
		select {
		case <-s.stopCh:
			return
		case pkt, ok := <-packets:
			if !ok {
				return
			}
			select {
			case s.pktCh <- pkt:
			default:
				// Channel full — drop to avoid blocking capture.
			}
		}
	}
}

// Stop ends the capture and closes the packet channel.
func (s *Session) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return
	}
	close(s.stopCh)
	s.handle.Close()
	s.active = false
	s.iface = ""
}

// Packets returns the channel that delivers captured packets.
// Only valid after a successful Start; nil before Start is called.
func (s *Session) Packets() <-chan gopacket.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pktCh
}

// Active reports whether a capture is in progress.
func (s *Session) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Interface returns the name of the interface being captured, or "".
func (s *Session) Interface() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.iface
}

// Stats returns pcap capture statistics (received, dropped, if-dropped).
func (s *Session) Stats() (received, dropped, ifDropped int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active || s.handle == nil {
		return 0, 0, 0, nil
	}
	stats, err := s.handle.Stats()
	if err != nil {
		return 0, 0, 0, err
	}
	return stats.PacketsReceived, stats.PacketsDropped, stats.PacketsIfDropped, nil
}
