// Package packet decodes raw gopacket data into JSON-friendly structures.
package packet

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// KeyValue is a single decoded field in a protocol layer.
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// LayerDetail holds the decoded fields for one protocol layer.
type LayerDetail struct {
	Name   string     `json:"name"`
	Fields []KeyValue `json:"fields"`
}

// PacketInfo is a JSON-friendly summary of a decoded packet.
type PacketInfo struct {
	ID             int           `json:"id"`
	Timestamp      string        `json:"timestamp"`
	Protocol       string        `json:"protocol"`
	SrcAddr        string        `json:"srcAddr"`
	DstAddr        string        `json:"dstAddr"`
	SrcPort        string        `json:"srcPort"`
	DstPort        string        `json:"dstPort"`
	Length         int           `json:"length"`
	Info           string        `json:"info"`
	Layers         []LayerDetail `json:"layers"`
	HexDump        string        `json:"hexDump"`
	TCPFlags       string        `json:"tcpFlags,omitempty"`
	ConversationID int           `json:"conversationId,omitempty"`
}

// Decode converts a raw gopacket.Packet into a PacketInfo.
func Decode(pkt gopacket.Packet, id int) PacketInfo {
	info := PacketInfo{
		ID:        id,
		Timestamp: pkt.Metadata().Timestamp.Format(time.StampMicro),
		Length:    pkt.Metadata().Length,
	}

	if info.Length == 0 {
		info.Length = len(pkt.Data())
	}

	decodeEthernet(pkt, &info)
	decodeARP(pkt, &info)
	decodeIPv4(pkt, &info)
	decodeIPv6(pkt, &info)
	decodeTCP(pkt, &info)
	decodeUDP(pkt, &info)
	decodeICMPv4(pkt, &info)
	decodeICMPv6(pkt, &info)
	decodeDNS(pkt, &info)

	// Fallback protocol and info
	if info.Protocol == "" {
		if nl := pkt.NetworkLayer(); nl != nil {
			info.Protocol = nl.LayerType().String()
		} else if ll := pkt.LinkLayer(); ll != nil {
			info.Protocol = ll.LayerType().String()
		} else {
			info.Protocol = "Unknown"
		}
	}
	if info.Info == "" {
		info.Info = info.Protocol
	}

	// Hex dump of the raw packet bytes
	info.HexDump = formatHexDump(pkt.Data())

	return info
}

func decodeEthernet(pkt gopacket.Packet, info *PacketInfo) {
	layer := pkt.Layer(layers.LayerTypeEthernet)
	if layer == nil {
		return
	}
	eth, ok := layer.(*layers.Ethernet)
	if !ok {
		return
	}
	info.Layers = append(info.Layers, LayerDetail{
		Name: "Ethernet II",
		Fields: []KeyValue{
			{"Source MAC", eth.SrcMAC.String()},
			{"Destination MAC", eth.DstMAC.String()},
			{"EtherType", eth.EthernetType.String()},
		},
	})
}

func decodeARP(pkt gopacket.Packet, info *PacketInfo) {
	layer := pkt.Layer(layers.LayerTypeARP)
	if layer == nil {
		return
	}
	arp, ok := layer.(*layers.ARP)
	if !ok {
		return
	}
	info.Protocol = "ARP"
	op := "Request"
	if arp.Operation == 2 {
		op = "Reply"
	}
	srcIP := formatIPBytes(arp.SourceProtAddress)
	dstIP := formatIPBytes(arp.DstProtAddress)
	info.SrcAddr = srcIP
	info.DstAddr = dstIP
	if op == "Request" {
		info.Info = fmt.Sprintf("Who has %s? Tell %s", dstIP, srcIP)
	} else {
		info.Info = fmt.Sprintf("%s is at %s", srcIP, formatMACBytes(arp.SourceHwAddress))
	}
	info.Layers = append(info.Layers, LayerDetail{
		Name: "ARP",
		Fields: []KeyValue{
			{"Operation", op},
			{"Sender MAC", formatMACBytes(arp.SourceHwAddress)},
			{"Sender IP", srcIP},
			{"Target MAC", formatMACBytes(arp.DstHwAddress)},
			{"Target IP", dstIP},
		},
	})
}

func decodeIPv4(pkt gopacket.Packet, info *PacketInfo) {
	layer := pkt.Layer(layers.LayerTypeIPv4)
	if layer == nil {
		return
	}
	ip4, ok := layer.(*layers.IPv4)
	if !ok {
		return
	}
	info.SrcAddr = ip4.SrcIP.String()
	info.DstAddr = ip4.DstIP.String()
	info.Layers = append(info.Layers, LayerDetail{
		Name: "IPv4",
		Fields: []KeyValue{
			{"Source", ip4.SrcIP.String()},
			{"Destination", ip4.DstIP.String()},
			{"Version", "4"},
			{"Header Length", fmt.Sprintf("%d bytes", ip4.IHL*4)},
			{"Total Length", fmt.Sprintf("%d", ip4.Length)},
			{"TTL", fmt.Sprintf("%d", ip4.TTL)},
			{"Protocol", ip4.Protocol.String()},
			{"Identification", fmt.Sprintf("0x%04x (%d)", ip4.Id, ip4.Id)},
			{"Flags", ip4.Flags.String()},
			{"Fragment Offset", fmt.Sprintf("%d", ip4.FragOffset)},
			{"Checksum", fmt.Sprintf("0x%04x", ip4.Checksum)},
		},
	})
}

func decodeIPv6(pkt gopacket.Packet, info *PacketInfo) {
	layer := pkt.Layer(layers.LayerTypeIPv6)
	if layer == nil {
		return
	}
	ip6, ok := layer.(*layers.IPv6)
	if !ok {
		return
	}
	info.SrcAddr = ip6.SrcIP.String()
	info.DstAddr = ip6.DstIP.String()
	info.Layers = append(info.Layers, LayerDetail{
		Name: "IPv6",
		Fields: []KeyValue{
			{"Source", ip6.SrcIP.String()},
			{"Destination", ip6.DstIP.String()},
			{"Version", "6"},
			{"Traffic Class", fmt.Sprintf("0x%02x", ip6.TrafficClass)},
			{"Flow Label", fmt.Sprintf("0x%05x", ip6.FlowLabel)},
			{"Payload Length", fmt.Sprintf("%d", ip6.Length)},
			{"Next Header", ip6.NextHeader.String()},
			{"Hop Limit", fmt.Sprintf("%d", ip6.HopLimit)},
		},
	})
}

func decodeTCP(pkt gopacket.Packet, info *PacketInfo) {
	layer := pkt.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return
	}
	tcp, ok := layer.(*layers.TCP)
	if !ok {
		return
	}
	info.Protocol = "TCP"
	info.SrcPort = fmt.Sprintf("%d", tcp.SrcPort)
	info.DstPort = fmt.Sprintf("%d", tcp.DstPort)

	flags := tcpFlagString(tcp)
	info.TCPFlags = flags
	info.Info = fmt.Sprintf("%d → %d [%s] Seq=%d Ack=%d Win=%d Len=%d",
		tcp.SrcPort, tcp.DstPort, flags,
		tcp.Seq, tcp.Ack, tcp.Window, len(tcp.Payload))

	info.Layers = append(info.Layers, LayerDetail{
		Name: "TCP",
		Fields: []KeyValue{
			{"Source Port", fmt.Sprintf("%d", tcp.SrcPort)},
			{"Destination Port", fmt.Sprintf("%d", tcp.DstPort)},
			{"Sequence Number", fmt.Sprintf("%d", tcp.Seq)},
			{"Acknowledgment Number", fmt.Sprintf("%d", tcp.Ack)},
			{"Data Offset", fmt.Sprintf("%d bytes", tcp.DataOffset*4)},
			{"Flags", flags},
			{"Window Size", fmt.Sprintf("%d", tcp.Window)},
			{"Checksum", fmt.Sprintf("0x%04x", tcp.Checksum)},
			{"Urgent Pointer", fmt.Sprintf("%d", tcp.Urgent)},
			{"Payload Length", fmt.Sprintf("%d bytes", len(tcp.Payload))},
		},
	})
}

func decodeUDP(pkt gopacket.Packet, info *PacketInfo) {
	layer := pkt.Layer(layers.LayerTypeUDP)
	if layer == nil {
		return
	}
	udp, ok := layer.(*layers.UDP)
	if !ok {
		return
	}
	if info.Protocol == "" {
		info.Protocol = "UDP"
	}
	info.SrcPort = fmt.Sprintf("%d", udp.SrcPort)
	info.DstPort = fmt.Sprintf("%d", udp.DstPort)
	if info.Info == "" {
		info.Info = fmt.Sprintf("%d → %d Len=%d", udp.SrcPort, udp.DstPort, udp.Length)
	}
	info.Layers = append(info.Layers, LayerDetail{
		Name: "UDP",
		Fields: []KeyValue{
			{"Source Port", fmt.Sprintf("%d", udp.SrcPort)},
			{"Destination Port", fmt.Sprintf("%d", udp.DstPort)},
			{"Length", fmt.Sprintf("%d", udp.Length)},
			{"Checksum", fmt.Sprintf("0x%04x", udp.Checksum)},
		},
	})
}

func decodeICMPv4(pkt gopacket.Packet, info *PacketInfo) {
	layer := pkt.Layer(layers.LayerTypeICMPv4)
	if layer == nil {
		return
	}
	icmp, ok := layer.(*layers.ICMPv4)
	if !ok {
		return
	}
	info.Protocol = "ICMP"
	typeName := icmpv4TypeName(icmp.TypeCode.Type())
	info.Info = fmt.Sprintf("%s (type=%d, code=%d) id=0x%04x seq=%d",
		typeName, icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Id, icmp.Seq)
	info.Layers = append(info.Layers, LayerDetail{
		Name: "ICMPv4",
		Fields: []KeyValue{
			{"Type", fmt.Sprintf("%d (%s)", icmp.TypeCode.Type(), typeName)},
			{"Code", fmt.Sprintf("%d", icmp.TypeCode.Code())},
			{"Checksum", fmt.Sprintf("0x%04x", icmp.Checksum)},
			{"Identifier", fmt.Sprintf("0x%04x (%d)", icmp.Id, icmp.Id)},
			{"Sequence", fmt.Sprintf("%d", icmp.Seq)},
		},
	})
}

func decodeICMPv6(pkt gopacket.Packet, info *PacketInfo) {
	layer := pkt.Layer(layers.LayerTypeICMPv6)
	if layer == nil {
		return
	}
	icmp6, ok := layer.(*layers.ICMPv6)
	if !ok {
		return
	}
	info.Protocol = "ICMPv6"
	info.Info = fmt.Sprintf("ICMPv6 type=%d code=%d", icmp6.TypeCode.Type(), icmp6.TypeCode.Code())
	info.Layers = append(info.Layers, LayerDetail{
		Name: "ICMPv6",
		Fields: []KeyValue{
			{"Type", fmt.Sprintf("%d", icmp6.TypeCode.Type())},
			{"Code", fmt.Sprintf("%d", icmp6.TypeCode.Code())},
			{"Checksum", fmt.Sprintf("0x%04x", icmp6.Checksum)},
		},
	})
}

func decodeDNS(pkt gopacket.Packet, info *PacketInfo) {
	layer := pkt.Layer(layers.LayerTypeDNS)
	if layer == nil {
		return
	}
	dns, ok := layer.(*layers.DNS)
	if !ok {
		return
	}
	info.Protocol = "DNS"

	if dns.QR {
		if len(dns.Answers) > 0 {
			info.Info = fmt.Sprintf("DNS Response: %d answer(s)", dns.ANCount)
		} else {
			info.Info = fmt.Sprintf("DNS Response (no answers), rcode=%d", dns.ResponseCode)
		}
	} else if len(dns.Questions) > 0 {
		info.Info = fmt.Sprintf("DNS Query: %s %s", string(dns.Questions[0].Name), dns.Questions[0].Type.String())
	} else {
		info.Info = "DNS"
	}

	fields := []KeyValue{
		{"Transaction ID", fmt.Sprintf("0x%04x", dns.ID)},
		{"Response", fmt.Sprintf("%v", dns.QR)},
		{"Opcode", fmt.Sprintf("%d", dns.OpCode)},
		{"Questions", fmt.Sprintf("%d", dns.QDCount)},
		{"Answers", fmt.Sprintf("%d", dns.ANCount)},
		{"Authority", fmt.Sprintf("%d", dns.NSCount)},
		{"Additional", fmt.Sprintf("%d", dns.ARCount)},
	}
	for i, q := range dns.Questions {
		fields = append(fields, KeyValue{
			fmt.Sprintf("Question %d", i+1),
			fmt.Sprintf("%s %s %s", string(q.Name), q.Type.String(), q.Class.String()),
		})
	}
	for i, a := range dns.Answers {
		val := dnsAnswerString(a)
		fields = append(fields, KeyValue{
			fmt.Sprintf("Answer %d (%s)", i+1, a.Type.String()),
			fmt.Sprintf("%s → %s (TTL %d)", string(a.Name), val, a.TTL),
		})
	}
	info.Layers = append(info.Layers, LayerDetail{Name: "DNS", Fields: fields})
}

// ---------- helpers ----------

func tcpFlagString(tcp *layers.TCP) string {
	var names []string
	if tcp.SYN {
		names = append(names, "SYN")
	}
	if tcp.ACK {
		names = append(names, "ACK")
	}
	if tcp.FIN {
		names = append(names, "FIN")
	}
	if tcp.RST {
		names = append(names, "RST")
	}
	if tcp.PSH {
		names = append(names, "PSH")
	}
	if tcp.URG {
		names = append(names, "URG")
	}
	if tcp.ECE {
		names = append(names, "ECE")
	}
	if tcp.CWR {
		names = append(names, "CWR")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

func icmpv4TypeName(t uint8) string {
	switch t {
	case 0:
		return "Echo Reply"
	case 3:
		return "Destination Unreachable"
	case 5:
		return "Redirect"
	case 8:
		return "Echo Request"
	case 11:
		return "Time Exceeded"
	default:
		return fmt.Sprintf("Type %d", t)
	}
}

func dnsAnswerString(a layers.DNSResourceRecord) string {
	switch {
	case a.IP != nil:
		return a.IP.String()
	case len(a.CNAME) > 0:
		return string(a.CNAME)
	case len(a.NS) > 0:
		return string(a.NS)
	case len(a.PTR) > 0:
		return string(a.PTR)
	case len(a.TXTs) > 0:
		var parts []string
		for _, t := range a.TXTs {
			parts = append(parts, string(t))
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprintf("(%d bytes)", a.DataLength)
	}
}

func formatIPBytes(b []byte) string {
	if len(b) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	return fmt.Sprintf("%x", b)
}

func formatMACBytes(b []byte) string {
	if len(b) == 6 {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
	}
	return fmt.Sprintf("%x", b)
}

func formatHexDump(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var buf strings.Builder
	for i := 0; i < len(data); i += 16 {
		fmt.Fprintf(&buf, "%04x  ", i)
		// Hex octets
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Fprintf(&buf, "%02x ", data[i+j])
			} else {
				buf.WriteString("   ")
			}
			if j == 7 {
				buf.WriteByte(' ')
			}
		}
		buf.WriteString(" ")
		// ASCII
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b < 127 {
				buf.WriteByte(b)
			} else {
				buf.WriteByte('.')
			}
		}
		buf.WriteByte('\n')
	}
	return buf.String()
}
