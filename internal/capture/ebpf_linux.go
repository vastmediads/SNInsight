//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
)

// TLS 事件结构 (与 eBPF 中的结构对应)
type tlsEvent struct {
	TimestampNs uint64
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Proto       uint8
	Direction   uint8
	PayloadLen  uint16
	Payload     [256]byte
}

type ebpfCapturer struct {
	cfg        CaptureConfig
	events     chan PacketEvent
	stats      chan []FlowStats
	objs       *trafficObjects
	tcLinks    []link.Link
	qdiscs     []netlink.Qdisc
	ringReader *ringbuf.Reader
	stopCh     chan struct{}
	wg         sync.WaitGroup
	mu         sync.Mutex
	interfaces []string
}

func newEBPFCapturer(cfg CaptureConfig) (*ebpfCapturer, error) {
	// 获取要监控的网卡列表
	interfaces := cfg.Interfaces
	if len(interfaces) == 0 {
		var err error
		interfaces, err = DiscoverInterfaces(nil)
		if err != nil {
			return nil, fmt.Errorf("获取网卡列表失败: %w", err)
		}
	}

	if len(interfaces) == 0 {
		return nil, errors.New("没有可用的网卡")
	}

	return &ebpfCapturer{
		cfg:        cfg,
		events:     make(chan PacketEvent, 1000),
		stats:      make(chan []FlowStats, 10),
		stopCh:     make(chan struct{}),
		interfaces: interfaces,
	}, nil
}

func (c *ebpfCapturer) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 加载 eBPF 程序
	c.objs = &trafficObjects{}
	if err := loadTrafficObjects(c.objs, nil); err != nil {
		return fmt.Errorf("加载 eBPF 程序失败: %w", err)
	}

	// 为每个网卡附加 TC 程序
	for _, iface := range c.interfaces {
		if err := c.attachTC(iface); err != nil {
			c.cleanup()
			return fmt.Errorf("附加 TC 到 %s 失败: %w", iface, err)
		}
	}

	// 创建 ring buffer reader
	var err error
	c.ringReader, err = ringbuf.NewReader(c.objs.TlsEvents)
	if err != nil {
		c.cleanup()
		return fmt.Errorf("创建 ring buffer reader 失败: %w", err)
	}

	// 启动 TLS 事件读取协程
	c.wg.Add(1)
	go c.readTLSEvents(ctx)

	// 启动流量统计轮询协程
	c.wg.Add(1)
	go c.pollFlowStats(ctx)

	return nil
}

func (c *ebpfCapturer) attachTC(iface string) error {
	// 获取网卡
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("找不到网卡 %s: %w", iface, err)
	}

	// 添加 clsact qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		// 如果已存在，继续
		if !os.IsExist(err) {
			return fmt.Errorf("添加 qdisc 失败: %w", err)
		}
	}
	c.qdiscs = append(c.qdiscs, qdisc)

	// 附加 ingress 过滤器
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Priority:  1,
			Protocol:  0x0003, // ETH_P_ALL
		},
		Fd:           c.objs.TcIngress.FD(),
		Name:         "sninsight_ingress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		return fmt.Errorf("添加 ingress 过滤器失败: %w", err)
	}

	// 附加 egress 过滤器
	egressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Priority:  1,
			Protocol:  0x0003, // ETH_P_ALL
		},
		Fd:           c.objs.TcEgress.FD(),
		Name:         "sninsight_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(egressFilter); err != nil {
		return fmt.Errorf("添加 egress 过滤器失败: %w", err)
	}

	return nil
}

func (c *ebpfCapturer) readTLSEvents(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		record, err := c.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		// 解析 TLS 事件
		evt := c.parseTLSEvent(record.RawSample)
		if evt != nil {
			select {
			case c.events <- *evt:
			default:
				// channel 满了，丢弃
			}
		}
	}
}

func (c *ebpfCapturer) parseTLSEvent(data []byte) *PacketEvent {
	if len(data) < 24 {
		return nil
	}

	evt := &PacketEvent{
		Timestamp: time.Now(),
	}

	// 解析字段 (与 eBPF 结构对应)
	evt.SrcIP = uint32ToIP(binary.LittleEndian.Uint32(data[8:12]))
	evt.DstIP = uint32ToIP(binary.LittleEndian.Uint32(data[12:16]))
	evt.SrcPort = binary.LittleEndian.Uint16(data[16:18])
	evt.DstPort = binary.LittleEndian.Uint16(data[18:20])
	evt.Protocol = data[20]
	evt.Direction = Direction(data[21])

	payloadLen := binary.LittleEndian.Uint16(data[22:24])
	if payloadLen > 0 && len(data) >= 24+int(payloadLen) {
		evt.Payload = make([]byte, payloadLen)
		copy(evt.Payload, data[24:24+payloadLen])
	}

	return evt
}

func (c *ebpfCapturer) pollFlowStats(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			stats := c.collectFlowStats()
			if len(stats) > 0 {
				select {
				case c.stats <- stats:
				default:
				}
			}
		}
	}
}

func (c *ebpfCapturer) collectFlowStats() []FlowStats {
	if c.objs == nil || c.objs.FlowStats == nil {
		return nil
	}

	var stats []FlowStats
	var key trafficFlowKey
	var value trafficFlowValue

	iter := c.objs.FlowStats.Iterate()
	for iter.Next(&key, &value) {
		fs := FlowStats{
			Key: FiveTuple{
				SrcIP:     uint32ToIP(key.SrcIp).String(),
				DstIP:     uint32ToIP(key.DstIp).String(),
				SrcPort:   key.SrcPort,
				DstPort:   key.DstPort,
				Protocol:  key.Proto,
				Direction: Direction(key.Direction),
			},
			Bytes:      value.Bytes,
			Packets:    value.Packets,
			LastSeenNs: value.LastSeenNs,
		}
		stats = append(stats, fs)
	}

	return stats
}

func (c *ebpfCapturer) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 发送停止信号
	close(c.stopCh)

	// 关闭 ring buffer reader
	if c.ringReader != nil {
		c.ringReader.Close()
	}

	// 等待协程退出
	c.wg.Wait()

	// 清理资源
	c.cleanup()

	// 关闭 channels
	close(c.events)
	close(c.stats)

	return nil
}

func (c *ebpfCapturer) cleanup() {
	// 关闭 TC links
	for _, l := range c.tcLinks {
		l.Close()
	}
	c.tcLinks = nil

	// 删除 qdiscs
	for _, qdisc := range c.qdiscs {
		netlink.QdiscDel(qdisc)
	}
	c.qdiscs = nil

	// 关闭 eBPF 对象
	if c.objs != nil {
		c.objs.Close()
		c.objs = nil
	}
}

func (c *ebpfCapturer) Events() <-chan PacketEvent {
	return c.events
}

func (c *ebpfCapturer) Stats() <-chan []FlowStats {
	return c.stats
}

func (c *ebpfCapturer) Capabilities() Capabilities {
	return Capabilities{
		SupportsDirection: true,
		SupportsBPFFilter: true,
	}
}

// uint32ToIP 将 uint32 转换为 net.IP (网络字节序)
func uint32ToIP(ip uint32) net.IP {
	return net.IPv4(
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	)
}
