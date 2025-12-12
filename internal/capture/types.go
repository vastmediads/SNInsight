package capture

import (
	"fmt"
	"net"
	"time"
)

// Direction 流量方向
type Direction uint8

const (
	Ingress Direction = iota // 下载/入站
	Egress                   // 上传/出站
)

func (d Direction) String() string {
	switch d {
	case Ingress:
		return "ingress"
	case Egress:
		return "egress"
	default:
		return "unknown"
	}
}

// Protocol 协议类型
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// PacketEvent 数据包事件
type PacketEvent struct {
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Direction Direction
	ByteCount uint64
	Payload   []byte // TLS ClientHello 时填充 (≤256 bytes)
}

// FiveTuple 五元组，用作 map key
type FiveTuple struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Direction Direction
}

// String 返回五元组字符串表示
func (f FiveTuple) String() string {
	return fmt.Sprintf("%s:%d->%s:%d/%d/%s",
		f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol, f.Direction)
}

// ToFiveTuple 从 PacketEvent 生成 FiveTuple
func (p *PacketEvent) ToFiveTuple() FiveTuple {
	return FiveTuple{
		SrcIP:     p.SrcIP.String(),
		DstIP:     p.DstIP.String(),
		SrcPort:   p.SrcPort,
		DstPort:   p.DstPort,
		Protocol:  p.Protocol,
		Direction: p.Direction,
	}
}

// FlowStats 流量统计
type FlowStats struct {
	Key        FiveTuple
	Bytes      uint64
	Packets    uint64
	LastSeenNs uint64
}

// Capabilities 平台能力
type Capabilities struct {
	SupportsDirection bool // Linux=true, macOS=false
	SupportsBPFFilter bool // 是否支持 BPF 过滤
}
