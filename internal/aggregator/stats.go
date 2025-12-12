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
	prevStats       map[string]*flowAccumulator
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
	connKeys    map[string]struct{} // 去重连接
	lastSeen    time.Time
}

// NewAggregator 创建聚合器
func NewAggregator(f *filter.Filter, supportsDirection bool, refresh time.Duration) *Aggregator {
	return &Aggregator{
		sessions:        NewSessionMap(),
		currentStats:    make(map[string]*flowAccumulator),
		prevStats:       make(map[string]*flowAccumulator),
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
	a.sessions.Set(key, sni)
	logger.Debug("记录 SNI 映射", "key", key, "sni", sni)
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

		if fs.Key.Direction == capture.Ingress || !a.supportsDir {
			acc.bytesIn += fs.Bytes
		} else {
			acc.bytesOut += fs.Bytes
		}
		acc.connKeys[fs.Key.String()] = struct{}{}
		acc.lastSeen = time.Now()
	}
}

// resolveDisplayName 解析显示名称
func (a *Aggregator) resolveDisplayName(key capture.FiveTuple) string {
	// 先尝试从 session map 获取 SNI
	if sni, ok := a.sessions.Get(key.String()); ok {
		return sni
	}

	// 降级显示 IP:Port
	var ip string
	if key.Direction == capture.Egress {
		ip = key.DstIP
	} else {
		ip = key.SrcIP
	}

	// 检查是否为有效 IP
	if net.ParseIP(ip) != nil {
		return fmt.Sprintf("%s:%d", ip, key.DstPort)
	}
	return ip
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
			ConnCount:   len(curr.connKeys),
			LastSeen:    curr.lastSeen,
		}

		// 计算速率 (与上一周期差值)
		if prev, ok := a.prevStats[name]; ok {
			intervalSec := uint64(a.refreshInterval.Seconds())
			if intervalSec == 0 {
				intervalSec = 1
			}
			if curr.bytesIn >= prev.bytesIn {
				entry.InRate = (curr.bytesIn - prev.bytesIn) / intervalSec
			}
			if curr.bytesOut >= prev.bytesOut {
				entry.OutRate = (curr.bytesOut - prev.bytesOut) / intervalSec
			}
		}

		entries = append(entries, entry)
	}

	// 保存当前状态用于下次计算
	a.prevStats = make(map[string]*flowAccumulator, len(a.currentStats))
	for k, v := range a.currentStats {
		a.prevStats[k] = &flowAccumulator{
			displayName: v.displayName,
			protocol:    v.protocol,
			bytesIn:     v.bytesIn,
			bytesOut:    v.bytesOut,
			connKeys:    v.connKeys,
			lastSeen:    v.lastSeen,
		}
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
