package aggregator

import (
	"fmt"
	"sync"
	"time"
)

// TrafficEntry 流量聚合条目
type TrafficEntry struct {
	DisplayName string  // 域名或 IP:Port
	Protocol    string  // TCP/UDP
	InRate      uint64  // 入站速率 bytes/s
	OutRate     uint64  // 出站速率 bytes/s
	TotalIn     uint64  // 累计入站字节
	TotalOut    uint64  // 累计出站字节
	ConnCount   int     // 连接数
	LastSeen    time.Time
}

// TotalRate 返回总速率
func (e *TrafficEntry) TotalRate() uint64 {
	return e.InRate + e.OutRate
}

// Total 返回总流量
func (e *TrafficEntry) Total() uint64 {
	return e.TotalIn + e.TotalOut
}

// SessionMap SNI 会话映射 (五元组 -> 域名)
type SessionMap struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry
	// 按目标 IP:Port 索引的域名映射 (用于快速查找)
	destIndex map[string]string
}

type sessionEntry struct {
	domain   string
	lastSeen time.Time
	dstIP    string
	dstPort  uint16
}

// NewSessionMap 创建会话映射
func NewSessionMap() *SessionMap {
	return &SessionMap{
		sessions:  make(map[string]sessionEntry),
		destIndex: make(map[string]string),
	}
}

// Set 设置映射
func (m *SessionMap) Set(key, domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[key] = sessionEntry{
		domain:   domain,
		lastSeen: time.Now(),
	}
}

// SetWithDest 设置映射并记录目标信息
func (m *SessionMap) SetWithDest(key, domain, dstIP string, dstPort uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[key] = sessionEntry{
		domain:   domain,
		lastSeen: time.Now(),
		dstIP:    dstIP,
		dstPort:  dstPort,
	}
	// 同时建立目标索引
	destKey := fmt.Sprintf("%s:%d", dstIP, dstPort)
	m.destIndex[destKey] = domain
}

// FindByDestination 根据目标 IP:Port 查找域名
func (m *SessionMap) FindByDestination(dstIP string, dstPort uint16) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	destKey := fmt.Sprintf("%s:%d", dstIP, dstPort)
	return m.destIndex[destKey]
}

// Get 获取域名
func (m *SessionMap) Get(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.sessions[key]
	if ok {
		return entry.domain, true
	}
	return "", false
}

// Cleanup 清理过期条目
func (m *SessionMap) Cleanup(maxAge time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0
	for key, entry := range m.sessions {
		if now.Sub(entry.lastSeen) > maxAge {
			delete(m.sessions, key)
			removed++
		}
	}
	return removed
}

// Len 返回条目数
func (m *SessionMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}
