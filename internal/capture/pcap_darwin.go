//go:build darwin

package capture

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/nickproject/sninsight/internal/logger"
	"github.com/nickproject/sninsight/internal/parser"
)

const (
	snapshotLen = 512 // 抓包长度，足够获取 TLS ClientHello
	promiscuous = false
	timeout     = pcap.BlockForever
)

type pcapCapturer struct {
	cfg      CaptureConfig
	handles  []*pcap.Handle
	events   chan PacketEvent
	stats    chan []FlowStats
	stopOnce sync.Once
	wg       sync.WaitGroup

	// 流量统计
	mu        sync.Mutex
	flowStats map[string]*flowEntry
}

type flowEntry struct {
	key      FiveTuple
	bytes    uint64
	packets  uint64
	lastSeen time.Time
}

func newPcapCapturer(cfg CaptureConfig) (*pcapCapturer, error) {
	return &pcapCapturer{
		cfg:       cfg,
		events:    make(chan PacketEvent, 1000),
		stats:     make(chan []FlowStats, 10),
		flowStats: make(map[string]*flowEntry),
	}, nil
}

func (c *pcapCapturer) Start(ctx context.Context) error {
	// 发现网卡
	ifaces, err := DiscoverInterfaces(c.cfg.Interfaces)
	if err != nil {
		return fmt.Errorf("发现网卡失败: %w", err)
	}

	if len(ifaces) == 0 {
		return fmt.Errorf("没有找到可用网卡")
	}

	logger.Info("发现网卡", "interfaces", ifaces)

	// 为每个网卡创建 pcap handle
	for _, iface := range ifaces {
		handle, err := pcap.OpenLive(iface, snapshotLen, promiscuous, timeout)
		if err != nil {
			logger.Warn("打开网卡失败", "interface", iface, "error", err)
			continue
		}

		// 设置 BPF 过滤器
		filter := "ip or ip6"
		if c.cfg.BPFFilter != "" {
			filter = c.cfg.BPFFilter
		}
		if err := handle.SetBPFFilter(filter); err != nil {
			logger.Warn("设置 BPF 过滤器失败", "interface", iface, "error", err)
			handle.Close()
			continue
		}

		c.handles = append(c.handles, handle)

		// 启动抓包协程
		c.wg.Add(1)
		go c.captureLoop(ctx, handle, iface)
	}

	if len(c.handles) == 0 {
		return fmt.Errorf("没有成功打开任何网卡")
	}

	// 启动统计发送协程
	c.wg.Add(1)
	go c.statsLoop(ctx)

	// 等待 context 取消
	<-ctx.Done()
	return nil
}

func (c *pcapCapturer) captureLoop(ctx context.Context, handle *pcap.Handle, iface string) {
	defer c.wg.Done()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			c.processPacket(packet)
		}
	}
}

func (c *pcapCapturer) processPacket(packet gopacket.Packet) {
	// 解析网络层
	var srcIP, dstIP net.IP
	var protocol uint8

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
		protocol = uint8(ip.Protocol)
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
		protocol = uint8(ip.NextHeader)
	} else {
		return
	}

	// 解析传输层
	var srcPort, dstPort uint16
	var payload []byte

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		payload = tcp.Payload
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		payload = udp.Payload
	} else {
		return
	}

	// 更新流量统计
	key := FiveTuple{
		SrcIP:     srcIP.String(),
		DstIP:     dstIP.String(),
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		Direction: Egress, // macOS 无法区分方向
	}

	packetLen := uint64(len(packet.Data()))
	c.updateFlowStats(key, packetLen)

	// 检查是否为 TLS ClientHello
	if parser.IsTLSClientHello(payload) {
		evt := PacketEvent{
			Timestamp: packet.Metadata().Timestamp,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  protocol,
			Direction: Egress,
			ByteCount: packetLen,
			Payload:   payload,
		}

		select {
		case c.events <- evt:
		default:
			logger.Debug("事件通道已满，丢弃事件")
		}
	}
}

func (c *pcapCapturer) updateFlowStats(key FiveTuple, bytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keyStr := key.String()
	entry, ok := c.flowStats[keyStr]
	if !ok {
		entry = &flowEntry{key: key}
		c.flowStats[keyStr] = entry
	}
	entry.bytes += bytes
	entry.packets++
	entry.lastSeen = time.Now()
}

func (c *pcapCapturer) statsLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := c.collectStats()
			select {
			case c.stats <- stats:
			default:
			}
		}
	}
}

func (c *pcapCapturer) collectStats() []FlowStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	stats := make([]FlowStats, 0, len(c.flowStats))
	for _, entry := range c.flowStats {
		stats = append(stats, FlowStats{
			Key:        entry.key,
			Bytes:      entry.bytes,
			Packets:    entry.packets,
			LastSeenNs: uint64(entry.lastSeen.UnixNano()),
		})
	}
	return stats
}

func (c *pcapCapturer) Stop() error {
	c.stopOnce.Do(func() {
		for _, handle := range c.handles {
			handle.Close()
		}
		c.wg.Wait()
		close(c.events)
		close(c.stats)
	})
	return nil
}

func (c *pcapCapturer) Events() <-chan PacketEvent {
	return c.events
}

func (c *pcapCapturer) Stats() <-chan []FlowStats {
	return c.stats
}

func (c *pcapCapturer) Capabilities() Capabilities {
	return Capabilities{
		SupportsDirection: false,
		SupportsBPFFilter: true,
	}
}
