// Package capture manages live packet capture.
//
// Two implementations exist behind the "nopcap" build tag:
//   - capture_pcap.go (default): real libpcap-backed capture via gopacket/pcap.
//     Requires cgo and libpcap headers; used for local/native deployments.
//   - capture_stub.go (-tags nopcap): a cloud-safe stub with the same API
//     that reports live capture as unavailable instead of failing to build.
//     Used for environments without libpcap, such as Vercel.
package capture

// InterfaceInfo holds metadata about a network interface available for capture.
type InterfaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}
