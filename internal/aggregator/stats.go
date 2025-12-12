package aggregator

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/nickproject/sninsight/internal/capture"
	"github.com/nickproject/sninsight/internal/filter"
	"github.com/nickproject/sninsight/internal/logger"
	"github.com/nickproject/sninsight/internal/parser"
)

// SortMode 排序模式
type SortMode int

const (
	SortByInRate SortMode = iota
	SortByOutRate
	SortByTotal
	SortByConns
)

// Aggregator 流量聚合器
type Aggregator struct {
	mu              sync.RWMutex
	sessions        *SessionMap
	currentStats    map[string]*flowAccumulator // 按域名/IP 聚合
	filter          *filter.Filter
	supportsDir     bool
	refreshInterval time.Duration
	cleanupInterval time.Duration
	sessionTTL      time.Duration
}

type flowAccumulator struct {
	displayName string
	protocol    string
	bytesIn     uint64
	bytesOut    uint64
	rateIn      uint64              // 最新的入站瞬时速率
	rateOut     uint64              // 最新的出站瞬时速率
	connKeys    map[string]struct{} // 去重连接
	lastSeen    time.Time
}

// NewAggregator 创建聚合器
func NewAggregator(f *filter.Filter, supportsDirection bool, refresh time.Duration) *Aggregator {
	return &Aggregator{
		sessions:        NewSessionMap(),
		currentStats:    make(map[string]*flowAccumulator),
		filter:          f,
		supportsDir:     supportsDirection,
		refreshInterval: refresh,
		cleanupInterval: 30 * time.Second,
		sessionTTL:      60 * time.Second,
	}
}

// Run 运行聚合器
func (a *Aggregator) Run(ctx context.Context, events <-chan capture.PacketEvent, stats <-chan []capture.FlowStats, output chan<- []TrafficEntry) {
	refreshTicker := time.NewTicker(a.refreshInterval)
	defer refreshTicker.Stop()

	cleanupTicker := time.NewTicker(a.cleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case evt, ok := <-events:
			if !ok {
				return
			}
			a.handleEvent(evt)

		case flowStats, ok := <-stats:
			if !ok {
				return
			}
			a.updateStats(flowStats)

		case <-refreshTicker.C:
			entries := a.computeRates()
			select {
			case output <- entries:
			default:
				// 如果 output 满了，跳过
			}

		case <-cleanupTicker.C:
			removed := a.sessions.Cleanup(a.sessionTTL)
			if removed > 0 {
				logger.Debug("清理过期会话", "count", removed)
			}
		}
	}
}

// handleEvent 处理 TLS 事件，提取 SNI
func (a *Aggregator) handleEvent(evt capture.PacketEvent) {
	if len(evt.Payload) == 0 {
		return
	}

	sni, err := parser.ExtractSNI(evt.Payload)
	if err != nil {
		logger.Debug("SNI 解析失败", "error", err)
		return
	}

	key := evt.ToFiveTuple().String()
	// 使用 SetWithDest 同时记录目标 IP:Port 索引
	a.sessions.SetWithDest(key, sni, evt.DstIP.String(), evt.DstPort)
	logger.Debug("记录 SNI 映射", "key", key, "sni", sni, "dstIP", evt.DstIP.String(), "dstPort", evt.DstPort)
}

// updateStats 更新流量统计
func (a *Aggregator) updateStats(flowStats []capture.FlowStats) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, fs := range flowStats {
		displayName := a.resolveDisplayName(fs.Key)

		// 应用过滤器
		if a.filter != nil && !a.filter.Match(displayName) {
			continue
		}

		acc, ok := a.currentStats[displayName]
		if !ok {
			acc = &flowAccumulator{
				displayName: displayName,
				protocol:    protoToString(fs.Key.Protocol),
				connKeys:    make(map[string]struct{}),
			}
			a.currentStats[displayName] = acc
		}

		// fs.Bytes 现在是增量数据（每秒新增字节数）
		// 同一域名的多个连接速率需要累加
		if fs.Key.Direction == capture.Ingress || !a.supportsDir {
			acc.bytesIn += fs.Bytes
			acc.rateIn += fs.Bytes // 累加速率而不是覆盖
		} else {
			acc.bytesOut += fs.Bytes
			acc.rateOut += fs.Bytes // 累加速率而不是覆盖
		}
		acc.connKeys[fs.Key.String()] = struct{}{}
		acc.lastSeen = time.Now()
	}
}

// resolveDisplayName 解析显示名称
func (a *Aggregator) resolveDisplayName(key capture.FiveTuple) string {
	// 确定远程服务器的 IP 和端口
	var remoteIP string
	var remotePort uint16

	if key.Direction == capture.Egress {
		// 出站流量：目标是远程服务器
		remoteIP = key.DstIP
		remotePort = key.DstPort
	} else {
		// 入站流量：源是远程服务器
		remoteIP = key.SrcIP
		remotePort = key.SrcPort
	}

	// 先尝试从 session map 获取 SNI (精确匹配)
	if sni, ok := a.sessions.Get(key.String()); ok {
		return sni
	}

	// 尝试反向查找 (ingress 流量对应的 egress SNI)
	// TLS ClientHello 只在 egress 方向发送，所以需要反转查找
	if key.Direction == capture.Ingress {
		reverseKey := capture.FiveTuple{
			SrcIP:     key.DstIP,
			DstIP:     key.SrcIP,
			SrcPort:   key.DstPort,
			DstPort:   key.SrcPort,
			Protocol:  key.Protocol,
			Direction: capture.Egress,
		}
		if sni, ok := a.sessions.Get(reverseKey.String()); ok {
			return sni
		}
	}

	// 尝试只匹配远程服务器 IP:Port (不考虑本地源)
	// 因为同一个服务器可能有多个连接
	if sni := a.sessions.FindByDestination(remoteIP, remotePort); sni != "" {
		return sni
	}

	// 降级显示远程 IP:Port
	if net.ParseIP(remoteIP) != nil {
		return fmt.Sprintf("%s:%d", remoteIP, remotePort)
	}
	return remoteIP
}

// computeRates 计算速率并返回条目列表
func (a *Aggregator) computeRates() []TrafficEntry {
	a.mu.Lock()
	defer a.mu.Unlock()

	entries := make([]TrafficEntry, 0, len(a.currentStats))

	for name, curr := range a.currentStats {
		entry := TrafficEntry{
			DisplayName: name,
			Protocol:    curr.protocol,
			TotalIn:     curr.bytesIn,
			TotalOut:    curr.bytesOut,
			InRate:      curr.rateIn,  // 直接使用实时速率
			OutRate:     curr.rateOut, // 直接使用实时速率
			ConnCount:   len(curr.connKeys),
			LastSeen:    curr.lastSeen,
		}

		entries = append(entries, entry)

		// 重置瞬时速率，等待下一次更新
		curr.rateIn = 0
		curr.rateOut = 0
	}

	return entries
}

// Sort 排序条目
func Sort(entries []TrafficEntry, mode SortMode) {
	sort.Slice(entries, func(i, j int) bool {
		switch mode {
		case SortByInRate:
			return entries[i].InRate > entries[j].InRate
		case SortByOutRate:
			return entries[i].OutRate > entries[j].OutRate
		case SortByTotal:
			return entries[i].Total() > entries[j].Total()
		case SortByConns:
			return entries[i].ConnCount > entries[j].ConnCount
		default:
			return entries[i].TotalRate() > entries[j].TotalRate()
		}
	})
}

func protoToString(proto uint8) string {
	switch proto {
	case capture.ProtoTCP:
		return "TCP"
	case capture.ProtoUDP:
		return "UDP"
	default:
		return fmt.Sprintf("%d", proto)
	}
}
