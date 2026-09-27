// Package capture manages live packet capture.
//
// Two implementations exist behind the "nopcap" build tag:
//   - capture_pcap.go (default): real libpcap-backed capture via gopacket/pcap.
//     Requires cgo and libpcap headers; used for local/native deployments.
//   - capture_stub.go (-tags nopcap): a cloud-safe stub with the same API
//     that reports live capture as unavailable instead of failing to build.
//     Used for environments without libpcap, such as Vercel.
package capture

import "errors"

// InterfaceInfo holds metadata about a network interface available for capture.
type InterfaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// ErrUnavailable is returned by capture_stub.go's implementation of every
// operation in this package. It is declared here (not in capture_stub.go) so
// callers can check for it with errors.Is regardless of which build tag
// compiled in — the real implementation never returns it.
var ErrUnavailable = errors.New("live network-interface access is unavailable in this deployment")
