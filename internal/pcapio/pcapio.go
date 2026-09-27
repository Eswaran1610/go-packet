// Package pcapio provides PCAP/PCAPNG file reading and writing.
package pcapio

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// packetDataReader abstracts pcap and pcapng readers.
type packetDataReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

// ReadFile opens a PCAP or PCAPNG file and returns the decoded packets.
func ReadFile(path string) ([]gopacket.Packet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()
	return ReadFromReader(f)
}

// ReadFromReader reads PCAP or PCAPNG from an io.ReadSeeker.
// It tries PCAPNG first, then falls back to PCAP.
func ReadFromReader(r io.ReadSeeker) ([]gopacket.Packet, error) {
	// Try PCAP first (more common).
	reader, err := pcapgo.NewReader(r)
	if err == nil {
		return readPackets(reader)
	}

	// Fall back to PCAPNG.
	if _, seekErr := r.Seek(0, io.SeekStart); seekErr != nil {
		return nil, fmt.Errorf("seeking: %w", seekErr)
	}
	ngReader, ngErr := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
	if ngErr != nil {
		return nil, fmt.Errorf("not a valid pcap/pcapng file (pcap: %v, pcapng: %v)", err, ngErr)
	}
	return readPackets(ngReader)
}

func readPackets(r packetDataReader) ([]gopacket.Packet, error) {
	linkType := r.LinkType()
	var packets []gopacket.Packet

	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return packets, fmt.Errorf("reading packet data: %w", err)
		}

		pkt := gopacket.NewPacket(data, linkType, gopacket.Default)
		m := pkt.Metadata()
		m.CaptureInfo = ci
		m.Timestamp = ci.Timestamp
		packets = append(packets, pkt)
	}
	return packets, nil
}

// WriteFile saves packets to a PCAP file at the given path.
func WriteFile(path string, linkType layers.LinkType, packets []gopacket.Packet) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()
	return WriteTo(f, linkType, packets)
}

// WriteTo writes packets in PCAP format to the given writer.
func WriteTo(w io.Writer, linkType layers.LinkType, packets []gopacket.Packet) error {
	writer := pcapgo.NewWriter(w)
	if err := writer.WriteFileHeader(65535, linkType); err != nil {
		return fmt.Errorf("writing pcap header: %w", err)
	}

	for _, pkt := range packets {
		ci := pkt.Metadata().CaptureInfo
		if ci.Timestamp.IsZero() {
			ci.Timestamp = time.Now()
		}
		data := pkt.Data()
		if ci.CaptureLength == 0 {
			ci.CaptureLength = len(data)
		}
		if ci.Length == 0 {
			ci.Length = len(data)
		}
		if err := writer.WritePacket(ci, data); err != nil {
			return fmt.Errorf("writing packet: %w", err)
		}
	}
	return nil
}
