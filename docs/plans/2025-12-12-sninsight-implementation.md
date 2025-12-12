# Sninsight 实现计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 实现一个基于 eBPF 的跨平台网络流量监控工具，支持 TLS SNI 解析和实时 TUI 展示。

**Architecture:** 分层架构，底层抓包通过接口抽象支持 Linux (eBPF) 和 macOS (libpcap)，中间层负责 SNI 解析和流量聚合，上层提供 TUI 展示和数据导出。

**Tech Stack:** Go 1.21+, cilium/ebpf, google/gopacket, charmbracelet/bubbletea, spf13/cobra

---

## Phase 1: 项目骨架与核心接口

### Task 1: 初始化 Go 模块和目录结构

**Files:**
- Create: `go.mod`
- Create: `cmd/sninsight/main.go`
- Create: `internal/capture/capture.go`
- Create: `internal/parser/sni.go`
- Create: `internal/aggregator/stats.go`
- Create: `internal/filter/filter.go`
- Create: `internal/tui/app.go`
- Create: `internal/export/export.go`
- Create: `internal/config/config.go`
- Create: `internal/logger/logger.go`

**Step 1: 创建 go.mod**

```bash
cd /Users/nick/Syncthing/Develop/Golang/nickproject/Sninsight
go mod init github.com/nickproject/sninsight
```

**Step 2: 创建目录结构**

```bash
mkdir -p cmd/sninsight internal/{capture,parser,aggregator,filter,tui,export,config,logger} bpf/headers configs dist
```

**Step 3: 创建占位 main.go**

创建 `cmd/sninsight/main.go`:

```go
package main

import (
	"fmt"
	"os"

	"github.com/nickproject/sninsight/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// TODO: 实现主逻辑
	_ = config.Default()
	fmt.Println("Sninsight - 网络流量监控工具")
	return nil
}
```

**Step 4: 提交**

```bash
git add -A && git commit -m "chore: 初始化项目结构和 go.mod"
```

---

### Task 2: 定义核心配置结构

**Files:**
- Create: `internal/config/config.go`

**Step 1: 实现配置结构**

创建 `internal/config/config.go`:

```go
package config

import (
	"time"
)

// Config 应用配置
type Config struct {
	Interfaces []string      `mapstructure:"interfaces"`
	Filter     FilterConfig  `mapstructure:"filter"`
	Display    DisplayConfig `mapstructure:"display"`
	Logging    LogConfig     `mapstructure:"logging"`
	Output     OutputConfig  `mapstructure:"output"`
}

// FilterConfig 过滤配置
type FilterConfig struct {
	BPF            string   `mapstructure:"bpf"`
	IncludeDomains []string `mapstructure:"include_domains"`
	ExcludeDomains []string `mapstructure:"exclude_domains"`
}

// DisplayConfig 显示配置
type DisplayConfig struct {
	Refresh time.Duration `mapstructure:"refresh"`
	MaxRows int           `mapstructure:"max_rows"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level     string `mapstructure:"level"`
	File      string `mapstructure:"file"`
	MaxSizeMB int    `mapstructure:"max_size_mb"`
	MaxFiles  int    `mapstructure:"max_files"`
}

// OutputConfig 输出配置
type OutputConfig struct {
	Duration time.Duration `mapstructure:"duration"`
	File     string        `mapstructure:"file"`
	Format   string        `mapstructure:"format"`
	NoTUI    bool          `mapstructure:"no_tui"`
}

// Default 返回默认配置
func Default() *Config {
	return &Config{
		Interfaces: nil, // nil 表示所有非回环网卡
		Filter: FilterConfig{
			BPF:            "",
			IncludeDomains: nil,
			ExcludeDomains: nil,
		},
		Display: DisplayConfig{
			Refresh: time.Second,
			MaxRows: 50,
		},
		Logging: LogConfig{
			Level:     "warn",
			File:      "/var/log/sninsight/sninsight.log",
			MaxSizeMB: 10,
			MaxFiles:  3,
		},
		Output: OutputConfig{
			Duration: 0, // 0 表示持续运行
			File:     "",
			Format:   "json",
			NoTUI:    false,
		},
	}
}
```

**Step 2: 提交**

```bash
git add -A && git commit -m "feat(config): 添加配置结构定义"
```

---

### Task 3: 定义抓包核心接口和数据类型

**Files:**
- Create: `internal/capture/capture.go`
- Create: `internal/capture/types.go`

**Step 1: 创建类型定义**

创建 `internal/capture/types.go`:

```go
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
```

**Step 2: 创建接口定义**

创建 `internal/capture/capture.go`:

```go
package capture

import (
	"context"
	"runtime"
)

// Capturer 抓包器接口
type Capturer interface {
	// Start 启动抓包，阻塞直到 ctx 取消或出错
	Start(ctx context.Context) error
	// Stop 停止抓包
	Stop() error
	// Events 返回数据包事件通道 (仅 TLS ClientHello)
	Events() <-chan PacketEvent
	// Stats 返回流量统计通道 (定时聚合)
	Stats() <-chan []FlowStats
	// Capabilities 返回平台能力
	Capabilities() Capabilities
}

// CaptureConfig 抓包配置
type CaptureConfig struct {
	Interfaces []string // 网卡列表，nil 表示所有
	BPFFilter  string   // BPF 过滤表达式
}

// New 根据平台创建 Capturer
func New(cfg CaptureConfig) (Capturer, error) {
	switch runtime.GOOS {
	case "linux":
		return newEBPFCapturer(cfg)
	case "darwin":
		return newPcapCapturer(cfg)
	default:
		return nil, &ErrUnsupportedPlatform{Platform: runtime.GOOS}
	}
}

// ErrUnsupportedPlatform 不支持的平台错误
type ErrUnsupportedPlatform struct {
	Platform string
}

func (e *ErrUnsupportedPlatform) Error() string {
	return "不支持的平台: " + e.Platform
}
```

**Step 3: 创建平台占位文件**

创建 `internal/capture/ebpf_linux.go`:

```go
//go:build linux

package capture

import (
	"context"
	"errors"
)

type ebpfCapturer struct {
	cfg    CaptureConfig
	events chan PacketEvent
	stats  chan []FlowStats
}

func newEBPFCapturer(cfg CaptureConfig) (*ebpfCapturer, error) {
	return &ebpfCapturer{
		cfg:    cfg,
		events: make(chan PacketEvent, 1000),
		stats:  make(chan []FlowStats, 10),
	}, nil
}

func (c *ebpfCapturer) Start(ctx context.Context) error {
	// TODO: 实现 eBPF 抓包
	return errors.New("eBPF 抓包尚未实现")
}

func (c *ebpfCapturer) Stop() error {
	close(c.events)
	close(c.stats)
	return nil
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
```

创建 `internal/capture/pcap_darwin.go`:

```go
//go:build darwin

package capture

import (
	"context"
	"errors"
)

type pcapCapturer struct {
	cfg    CaptureConfig
	events chan PacketEvent
	stats  chan []FlowStats
}

func newPcapCapturer(cfg CaptureConfig) (*pcapCapturer, error) {
	return &pcapCapturer{
		cfg:    cfg,
		events: make(chan PacketEvent, 1000),
		stats:  make(chan []FlowStats, 10),
	}, nil
}

func (c *pcapCapturer) Start(ctx context.Context) error {
	// TODO: 实现 libpcap 抓包
	return errors.New("libpcap 抓包尚未实现")
}

func (c *pcapCapturer) Stop() error {
	close(c.events)
	close(c.stats)
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
		SupportsDirection: false, // macOS 不支持方向区分
		SupportsBPFFilter: true,
	}
}
```

**Step 4: 验证编译**

```bash
go build ./...
```

**Step 5: 提交**

```bash
git add -A && git commit -m "feat(capture): 定义抓包核心接口和数据类型"
```

---

### Task 4: 实现日志模块

**Files:**
- Create: `internal/logger/logger.go`

**Step 1: 添加依赖**

```bash
go get gopkg.in/natefinch/lumberjack.v2
go get go.uber.org/zap
```

**Step 2: 实现日志模块**

创建 `internal/logger/logger.go`:

```go
package logger

import (
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var globalLogger *zap.SugaredLogger

// Config 日志配置
type Config struct {
	Level     string
	File      string
	MaxSizeMB int
	MaxFiles  int
	ToStderr  bool // 非 TUI 模式同时输出到 stderr
}

// Init 初始化全局日志
func Init(cfg Config) error {
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		level = zapcore.WarnLevel
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var cores []zapcore.Core

	// 文件输出
	if cfg.File != "" {
		// 确保目录存在
		dir := filepath.Dir(cfg.File)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}

		fileWriter := &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    cfg.MaxSizeMB,
			MaxBackups: cfg.MaxFiles,
			LocalTime:  true,
			Compress:   false,
		}
		fileCore := zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(fileWriter),
			level,
		)
		cores = append(cores, fileCore)
	}

	// stderr 输出 (非 TUI 模式)
	if cfg.ToStderr {
		consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)
		consoleCore := zapcore.NewCore(
			consoleEncoder,
			zapcore.AddSync(os.Stderr),
			level,
		)
		cores = append(cores, consoleCore)
	}

	// 如果没有任何输出，默认输出到 stderr
	if len(cores) == 0 {
		consoleCore := zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stderr),
			level,
		)
		cores = append(cores, consoleCore)
	}

	core := zapcore.NewTee(cores...)
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	globalLogger = logger.Sugar()

	return nil
}

// Debug 调试日志
func Debug(msg string, keysAndValues ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debugw(msg, keysAndValues...)
	}
}

// Info 信息日志
func Info(msg string, keysAndValues ...interface{}) {
	if globalLogger != nil {
		globalLogger.Infow(msg, keysAndValues...)
	}
}

// Warn 警告日志
func Warn(msg string, keysAndValues ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warnw(msg, keysAndValues...)
	}
}

// Error 错误日志
func Error(msg string, keysAndValues ...interface{}) {
	if globalLogger != nil {
		globalLogger.Errorw(msg, keysAndValues...)
	}
}

// Sync 刷新日志缓冲
func Sync() {
	if globalLogger != nil {
		_ = globalLogger.Sync()
	}
}
```

**Step 3: 提交**

```bash
git add -A && git commit -m "feat(logger): 实现日志模块，支持文件轮转"
```

---

### Task 5: 实现 SNI 解析器

**Files:**
- Create: `internal/parser/sni.go`

**Step 1: 实现 SNI 解析**

创建 `internal/parser/sni.go`:

```go
package parser

import (
	"encoding/binary"
	"errors"
)

var (
	ErrNotTLSHandshake   = errors.New("不是 TLS 握手消息")
	ErrNotClientHello    = errors.New("不是 ClientHello")
	ErrPayloadTooShort   = errors.New("payload 太短")
	ErrNoSNIExtension    = errors.New("没有 SNI 扩展")
	ErrInvalidSNIFormat  = errors.New("SNI 格式无效")
)

const (
	tlsHandshake       = 0x16
	tlsClientHello     = 0x01
	extensionSNI       = 0x0000
	sniHostNameType    = 0x00
	minClientHelloSize = 43 // 最小 ClientHello 大小
)

// ExtractSNI 从 TLS ClientHello payload 中提取 SNI
func ExtractSNI(payload []byte) (string, error) {
	if len(payload) < 6 {
		return "", ErrPayloadTooShort
	}

	// 检查是否为 TLS Handshake
	if payload[0] != tlsHandshake {
		return "", ErrNotTLSHandshake
	}

	// 检查 TLS 版本 (0x0301=TLS1.0, 0x0302=TLS1.1, 0x0303=TLS1.2/1.3)
	// payload[1:3] 是版本，我们不严格检查

	// payload[3:5] 是记录长度
	recordLen := binary.BigEndian.Uint16(payload[3:5])
	if int(recordLen)+5 > len(payload) {
		return "", ErrPayloadTooShort
	}

	// payload[5] 应该是 ClientHello (0x01)
	if payload[5] != tlsClientHello {
		return "", ErrNotClientHello
	}

	// ClientHello 长度在 payload[6:9] (3字节)
	if len(payload) < 9 {
		return "", ErrPayloadTooShort
	}

	// 跳过 ClientHello 头部，找到扩展部分
	// 结构: HandshakeType(1) + Length(3) + Version(2) + Random(32) + SessionID(1+var) + CipherSuites(2+var) + Compression(1+var) + Extensions(2+var)
	pos := 5 + 1 + 3 + 2 + 32 // 到达 SessionID 长度位置

	if pos >= len(payload) {
		return "", ErrPayloadTooShort
	}

	// SessionID
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(payload) {
		return "", ErrPayloadTooShort
	}

	// CipherSuites
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	if pos+1 > len(payload) {
		return "", ErrPayloadTooShort
	}

	// Compression Methods
	compressionLen := int(payload[pos])
	pos += 1 + compressionLen

	if pos+2 > len(payload) {
		return "", ErrPayloadTooShort
	}

	// Extensions 长度
	extensionsLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	if pos+extensionsLen > len(payload) {
		extensionsLen = len(payload) - pos // 截断情况，尽量解析
	}

	// 遍历扩展找 SNI
	extEnd := pos + extensionsLen
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > extEnd {
			break
		}

		if extType == extensionSNI {
			return parseSNIExtension(payload[pos : pos+extLen])
		}

		pos += extLen
	}

	return "", ErrNoSNIExtension
}

// parseSNIExtension 解析 SNI 扩展数据
func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 5 {
		return "", ErrInvalidSNIFormat
	}

	// SNI 列表长度
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen+2 > len(data) {
		listLen = len(data) - 2
	}

	pos := 2
	listEnd := pos + listLen

	for pos+3 <= listEnd {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3

		if pos+nameLen > listEnd {
			break
		}

		if nameType == sniHostNameType {
			return string(data[pos : pos+nameLen]), nil
		}

		pos += nameLen
	}

	return "", ErrNoSNIExtension
}

// IsTLSClientHello 快速判断是否为 TLS ClientHello
func IsTLSClientHello(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	return payload[0] == tlsHandshake && payload[5] == tlsClientHello
}
```

**Step 2: 提交**

```bash
git add -A && git commit -m "feat(parser): 实现 TLS ClientHello SNI 解析"
```

---

### Task 6: 实现域名过滤器

**Files:**
- Create: `internal/filter/filter.go`

**Step 1: 实现过滤器**

创建 `internal/filter/filter.go`:

```go
package filter

import (
	"path/filepath"
	"strings"
)

// Filter 域名过滤器
type Filter struct {
	includePatterns []string
	excludePatterns []string
}

// New 创建过滤器
func New(include, exclude []string) *Filter {
	return &Filter{
		includePatterns: normalizePatterns(include),
		excludePatterns: normalizePatterns(exclude),
	}
}

// normalizePatterns 规范化通配符模式
func normalizePatterns(patterns []string) []string {
	result := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// Match 判断域名是否应该显示
// 返回 true 表示应该显示，false 表示应该过滤掉
func (f *Filter) Match(domain string) bool {
	domain = strings.ToLower(domain)

	// 如果在排除列表中，直接过滤
	for _, pattern := range f.excludePatterns {
		if matchPattern(pattern, domain) {
			return false
		}
	}

	// 如果没有包含列表，默认显示
	if len(f.includePatterns) == 0 {
		return true
	}

	// 检查是否在包含列表中
	for _, pattern := range f.includePatterns {
		if matchPattern(pattern, domain) {
			return true
		}
	}

	return false
}

// matchPattern 使用通配符匹配域名
// 支持 * 和 ? 通配符
// 例如: *.google.com 匹配 www.google.com, mail.google.com
func matchPattern(pattern, domain string) bool {
	// 处理 *.example.com 格式
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return strings.HasSuffix(domain, suffix) || domain == pattern[2:]
	}

	// 使用 filepath.Match 进行通配符匹配
	matched, err := filepath.Match(pattern, domain)
	if err != nil {
		return false
	}
	return matched
}

// IsEmpty 检查过滤器是否为空（无任何规则）
func (f *Filter) IsEmpty() bool {
	return len(f.includePatterns) == 0 && len(f.excludePatterns) == 0
}
```

**Step 2: 提交**

```bash
git add -A && git commit -m "feat(filter): 实现域名通配符过滤器"
```

---

### Task 7: 实现流量聚合器

**Files:**
- Create: `internal/aggregator/stats.go`
- Create: `internal/aggregator/entry.go`

**Step 1: 创建聚合条目类型**

创建 `internal/aggregator/entry.go`:

```go
package aggregator

import (
	"sync"
	"time"
)

// TrafficEntry 流量聚合条目
type TrafficEntry struct {
	DisplayName  string  // 域名或 IP:Port
	Protocol     string  // TCP/UDP
	InRate       uint64  // 入站速率 bytes/s
	OutRate      uint64  // 出站速率 bytes/s
	TotalIn      uint64  // 累计入站字节
	TotalOut     uint64  // 累计出站字节
	ConnCount    int     // 连接数
	LastSeen     time.Time
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
}

type sessionEntry struct {
	domain   string
	lastSeen time.Time
}

// NewSessionMap 创建会话映射
func NewSessionMap() *SessionMap {
	return &SessionMap{
		sessions: make(map[string]sessionEntry),
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
```

**Step 2: 实现聚合器**

创建 `internal/aggregator/stats.go`:

```go
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
```

**Step 3: 提交**

```bash
git add -A && git commit -m "feat(aggregator): 实现流量聚合和速率计算"
```

---

## Phase 2: TUI 和导出功能

### Task 8: 实现导出功能

**Files:**
- Create: `internal/export/export.go`

**Step 1: 添加依赖**

```bash
go get encoding/json encoding/csv
```

**Step 2: 实现导出模块**

创建 `internal/export/export.go`:

```go
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nickproject/sninsight/internal/aggregator"
)

// ExportFormat 导出格式
type ExportFormat string

const (
	FormatJSON ExportFormat = "json"
	FormatCSV  ExportFormat = "csv"
)

// Report 导出报告
type Report struct {
	Timestamp   time.Time                `json:"timestamp"`
	Duration    time.Duration            `json:"duration"`
	TotalIn     uint64                   `json:"total_in_bytes"`
	TotalOut    uint64                   `json:"total_out_bytes"`
	Connections int                      `json:"connections"`
	Entries     []aggregator.TrafficEntry `json:"entries"`
}

// Export 导出数据到文件
func Export(report *Report, filename string, format ExportFormat) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer file.Close()

	switch format {
	case FormatJSON:
		return exportJSON(report, file)
	case FormatCSV:
		return exportCSV(report, file)
	default:
		return fmt.Errorf("不支持的格式: %s", format)
	}
}

func exportJSON(report *Report, file *os.File) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func exportCSV(report *Report, file *os.File) error {
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入头部
	headers := []string{
		"domain_ip",
		"protocol",
		"in_rate_bytes_s",
		"out_rate_bytes_s",
		"total_in_bytes",
		"total_out_bytes",
		"connections",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// 写入数据行
	for _, entry := range report.Entries {
		row := []string{
			entry.DisplayName,
			entry.Protocol,
			fmt.Sprintf("%d", entry.InRate),
			fmt.Sprintf("%d", entry.OutRate),
			fmt.Sprintf("%d", entry.TotalIn),
			fmt.Sprintf("%d", entry.TotalOut),
			fmt.Sprintf("%d", entry.ConnCount),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// ParseFormat 解析格式字符串
func ParseFormat(s string) (ExportFormat, error) {
	switch s {
	case "json", "JSON":
		return FormatJSON, nil
	case "csv", "CSV":
		return FormatCSV, nil
	default:
		return "", fmt.Errorf("不支持的格式: %s (支持: json, csv)", s)
	}
}
```

**Step 3: 提交**

```bash
git add -A && git commit -m "feat(export): 实现 JSON/CSV 导出功能"
```

---

### Task 9: 实现 TUI 界面

**Files:**
- Create: `internal/tui/app.go`
- Create: `internal/tui/styles.go`
- Create: `internal/tui/format.go`

**Step 1: 添加依赖**

```bash
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss
go get github.com/charmbracelet/bubbles/table
```

**Step 2: 创建样式定义**

创建 `internal/tui/styles.go`:

```go
package tui

import "github.com/charmbracelet/lipgloss"

var (
	// 颜色定义
	primaryColor   = lipgloss.Color("39")  // 青色
	secondaryColor = lipgloss.Color("243") // 灰色
	accentColor    = lipgloss.Color("205") // 粉色
	successColor   = lipgloss.Color("42")  // 绿色
	warningColor   = lipgloss.Color("214") // 橙色

	// 标题样式
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			MarginBottom(1)

	// Header 样式
	headerStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(secondaryColor)

	// 表格头样式
	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(primaryColor).
				Padding(0, 1)

	// 表格行样式
	tableRowStyle = lipgloss.NewStyle().
			Padding(0, 1)

	// 选中行样式
	selectedRowStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("236")).
				Foreground(lipgloss.Color("255")).
				Padding(0, 1)

	// Footer 样式
	footerStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			MarginTop(1)

	// 速率样式 (入站)
	inRateStyle = lipgloss.NewStyle().
			Foreground(successColor)

	// 速率样式 (出站)
	outRateStyle = lipgloss.NewStyle().
			Foreground(warningColor)

	// 帮助文本样式
	helpStyle = lipgloss.NewStyle().
			Foreground(secondaryColor)
)
```

**Step 3: 创建格式化工具**

创建 `internal/tui/format.go`:

```go
package tui

import "fmt"

// FormatBytes 格式化字节数为人类可读格式
func FormatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.1f TB", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// FormatRate 格式化速率为人类可读格式
func FormatRate(bytesPerSec uint64) string {
	return FormatBytes(bytesPerSec) + "/s"
}

// TruncateString 截断字符串
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
```

**Step 4: 实现主 TUI 应用**

创建 `internal/tui/app.go`:

```go
package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nickproject/sninsight/internal/aggregator"
)

// Config TUI 配置
type Config struct {
	SupportsDirection bool
	Hostname          string
	KernelVersion     string
	Interfaces        []string
}

// Model TUI 模型
type Model struct {
	config       Config
	entries      []aggregator.TrafficEntry
	sortMode     aggregator.SortMode
	paused       bool
	filterInput  textinput.Model
	filtering    bool
	filterText   string
	selected     int
	offset       int
	width        int
	height       int
	startTime    time.Time
	totalIn      uint64
	totalOut     uint64
	showHelp     bool
	entriesChan  <-chan []aggregator.TrafficEntry
}

// 消息类型
type tickMsg time.Time
type entriesMsg []aggregator.TrafficEntry

// New 创建 TUI 模型
func New(cfg Config, entriesChan <-chan []aggregator.TrafficEntry) Model {
	ti := textinput.New()
	ti.Placeholder = "输入过滤关键词..."
	ti.CharLimit = 50

	return Model{
		config:      cfg,
		sortMode:    aggregator.SortByInRate,
		filterInput: ti,
		startTime:   time.Now(),
		entriesChan: entriesChan,
		width:       80,
		height:      24,
	}
}

// Init 初始化
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		waitForEntries(m.entriesChan),
	)
}

func waitForEntries(ch <-chan []aggregator.TrafficEntry) tea.Cmd {
	return func() tea.Msg {
		entries, ok := <-ch
		if !ok {
			return nil
		}
		return entriesMsg(entries)
	}
}

// Update 更新状态
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.filtering {
			return m.handleFilterInput(msg)
		}
		return m.handleKeyPress(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case entriesMsg:
		if !m.paused {
			m.entries = []aggregator.TrafficEntry(msg)
			m.applyFilter()
			aggregator.Sort(m.entries, m.sortMode)
			m.updateTotals()
		}
		cmds = append(cmds, waitForEntries(m.entriesChan))
		return m, tea.Batch(cmds...)
	}

	return m, nil
}

func (m Model) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "s":
		m.sortMode = (m.sortMode + 1) % 4
		aggregator.Sort(m.entries, m.sortMode)
	case "p":
		m.paused = !m.paused
	case "/":
		m.filtering = true
		m.filterInput.Focus()
		return m, textinput.Blink
	case "?":
		m.showHelp = !m.showHelp
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
	case "down", "j":
		if m.selected < len(m.entries)-1 {
			m.selected++
		}
	case "home":
		m.selected = 0
	case "end":
		if len(m.entries) > 0 {
			m.selected = len(m.entries) - 1
		}
	}
	return m, nil
}

func (m Model) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.filterText = m.filterInput.Value()
		m.filtering = false
		m.filterInput.Blur()
		m.applyFilter()
	case "esc":
		m.filtering = false
		m.filterInput.Blur()
		m.filterInput.SetValue(m.filterText)
	default:
		var cmd tea.Cmd
		m.filterInput, cmd = m.filterInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) applyFilter() {
	if m.filterText == "" {
		return
	}
	filter := strings.ToLower(m.filterText)
	filtered := make([]aggregator.TrafficEntry, 0)
	for _, e := range m.entries {
		if strings.Contains(strings.ToLower(e.DisplayName), filter) {
			filtered = append(filtered, e)
		}
	}
	m.entries = filtered
}

func (m *Model) updateTotals() {
	m.totalIn = 0
	m.totalOut = 0
	for _, e := range m.entries {
		m.totalIn += e.InRate
		m.totalOut += e.OutRate
	}
}

// View 渲染视图
func (m Model) View() string {
	if m.showHelp {
		return m.renderHelp()
	}

	var b strings.Builder

	// Header
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	// Table
	b.WriteString(m.renderTable())

	// Footer
	b.WriteString(m.renderFooter())

	return b.String()
}

func (m Model) renderHeader() string {
	runtime := time.Since(m.startTime).Round(time.Second)

	line1 := fmt.Sprintf(" Sninsight │ Host: %s │ Kernel: %s │ NICs: %s",
		m.config.Hostname,
		m.config.KernelVersion,
		strings.Join(m.config.Interfaces, ", "))

	var line2 string
	if m.config.SupportsDirection {
		line2 = fmt.Sprintf(" Total: ↓ %s  ↑ %s │ Connections: %d │ Runtime: %s",
			inRateStyle.Render(FormatRate(m.totalIn)),
			outRateStyle.Render(FormatRate(m.totalOut)),
			len(m.entries),
			runtime)
	} else {
		line2 = fmt.Sprintf(" Total: %s │ Connections: %d │ Runtime: %s",
			FormatRate(m.totalIn+m.totalOut),
			len(m.entries),
			runtime)
	}

	if m.paused {
		line2 += " [PAUSED]"
	}

	return titleStyle.Render(line1) + "\n" + headerStyle.Render(line2)
}

func (m Model) renderTable() string {
	var b strings.Builder

	// 表头
	var header string
	if m.config.SupportsDirection {
		header = fmt.Sprintf(" %-30s %5s %12s %12s %10s %6s",
			"Domain/IP", "Proto", "↓ In Rate", "↑ Out Rate", "Total", "Conns")
	} else {
		header = fmt.Sprintf(" %-30s %5s %12s %10s %6s",
			"Domain/IP", "Proto", "Rate", "Total", "Conns")
	}
	b.WriteString(tableHeaderStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", m.width))
	b.WriteString("\n")

	// 计算可显示行数
	maxRows := m.height - 8
	if maxRows < 1 {
		maxRows = 10
	}

	// 显示条目
	for i, entry := range m.entries {
		if i >= maxRows {
			break
		}

		name := TruncateString(entry.DisplayName, 30)
		var row string
		if m.config.SupportsDirection {
			row = fmt.Sprintf(" %-30s %5s %12s %12s %10s %6d",
				name,
				entry.Protocol,
				inRateStyle.Render(FormatRate(entry.InRate)),
				outRateStyle.Render(FormatRate(entry.OutRate)),
				FormatBytes(entry.Total()),
				entry.ConnCount)
		} else {
			row = fmt.Sprintf(" %-30s %5s %12s %10s %6d",
				name,
				entry.Protocol,
				FormatRate(entry.InRate+entry.OutRate),
				FormatBytes(entry.Total()),
				entry.ConnCount)
		}

		if i == m.selected {
			b.WriteString(selectedRowStyle.Render(row))
		} else {
			b.WriteString(tableRowStyle.Render(row))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) renderFooter() string {
	sortNames := []string{"In Rate", "Out Rate", "Total", "Conns"}
	sortName := sortNames[m.sortMode]

	var footer string
	if m.filtering {
		footer = " Filter: " + m.filterInput.View()
	} else {
		footer = fmt.Sprintf(" [q]uit  [s]ort: %s  [p]ause  [/]filter  [?]help", sortName)
		if m.filterText != "" {
			footer += fmt.Sprintf("  Filter: %s", m.filterText)
		}
	}

	return footerStyle.Render(footer)
}

func (m Model) renderHelp() string {
	help := `
 Sninsight 快捷键帮助

 导航:
   ↑/k     向上移动
   ↓/j     向下移动
   Home    跳到顶部
   End     跳到底部

 操作:
   s       切换排序模式 (In Rate → Out Rate → Total → Conns)
   p       暂停/恢复刷新
   /       输入过滤关键词
   ?       显示/隐藏帮助

 退出:
   q       退出程序
   Ctrl+C  退出程序

 按任意键返回...
`
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Render(help)
}

// Run 运行 TUI
func Run(cfg Config, entriesChan <-chan []aggregator.TrafficEntry) error {
	p := tea.NewProgram(
		New(cfg, entriesChan),
		tea.WithAltScreen(),
	)

	_, err := p.Run()
	return err
}
```

**Step 5: 提交**

```bash
git add -A && git commit -m "feat(tui): 实现 Bubbletea TUI 界面"
```

---

## Phase 3: CLI 和主程序

### Task 10: 实现 CLI 命令行

**Files:**
- Modify: `cmd/sninsight/main.go`
- Create: `cmd/sninsight/root.go`

**Step 1: 添加依赖**

```bash
go get github.com/spf13/cobra
go get github.com/spf13/viper
```

**Step 2: 创建 root 命令**

创建 `cmd/sninsight/root.go`:

```go
package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nickproject/sninsight/internal/config"
)

var (
	cfgFile string
	cfg     *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "sninsight",
	Short: "基于 eBPF 的网络流量监控工具",
	Long: `Sninsight 是一个基于 eBPF 的网络流量监控工具。
支持实时监控网络流量，解析 TLS SNI 识别域名，
通过 TUI 界面实时展示流量统计。`,
	RunE: runMonitor,
}

func init() {
	cobra.OnInitialize(initConfig)

	// 基础选项
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "配置文件路径")
	rootCmd.Flags().StringSliceP("interface", "i", nil, "指定网卡 (可多次指定)")
	rootCmd.Flags().DurationP("refresh", "r", time.Second, "刷新间隔")

	// 过滤选项
	rootCmd.Flags().StringP("filter", "f", "", "BPF 过滤表达式")
	rootCmd.Flags().StringSlice("include-domains", nil, "域名白名单 (逗号分隔)")
	rootCmd.Flags().StringSlice("exclude-domains", nil, "域名黑名单 (逗号分隔)")

	// 输出选项
	rootCmd.Flags().DurationP("duration", "d", 0, "运行时长后退出")
	rootCmd.Flags().StringP("output", "o", "", "导出文件路径")
	rootCmd.Flags().String("format", "json", "导出格式 (json|csv)")
	rootCmd.Flags().Bool("no-tui", false, "禁用 TUI")

	// 日志选项
	rootCmd.Flags().String("log-file", "", "日志文件路径")
	rootCmd.Flags().String("log-level", "warn", "日志级别 (debug|info|warn|error)")

	// 绑定到 viper
	viper.BindPFlag("interfaces", rootCmd.Flags().Lookup("interface"))
	viper.BindPFlag("display.refresh", rootCmd.Flags().Lookup("refresh"))
	viper.BindPFlag("filter.bpf", rootCmd.Flags().Lookup("filter"))
	viper.BindPFlag("filter.include_domains", rootCmd.Flags().Lookup("include-domains"))
	viper.BindPFlag("filter.exclude_domains", rootCmd.Flags().Lookup("exclude-domains"))
	viper.BindPFlag("output.duration", rootCmd.Flags().Lookup("duration"))
	viper.BindPFlag("output.file", rootCmd.Flags().Lookup("output"))
	viper.BindPFlag("output.format", rootCmd.Flags().Lookup("format"))
	viper.BindPFlag("output.no_tui", rootCmd.Flags().Lookup("no-tui"))
	viper.BindPFlag("logging.file", rootCmd.Flags().Lookup("log-file"))
	viper.BindPFlag("logging.level", rootCmd.Flags().Lookup("log-level"))
}

func initConfig() {
	cfg = config.Default()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// 搜索配置文件
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home + "/.config/sninsight")
		}
		viper.AddConfigPath("/etc/sninsight")
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// 环境变量
	viper.SetEnvPrefix("SNINSIGHT")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "读取配置文件错误: %v\n", err)
			os.Exit(1)
		}
	}

	// 解析到结构体
	if err := viper.Unmarshal(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "解析配置错误: %v\n", err)
		os.Exit(1)
	}
}

func runMonitor(cmd *cobra.Command, args []string) error {
	// 权限检查
	if err := checkPermissions(); err != nil {
		return err
	}

	// TODO: 启动监控
	fmt.Printf("Sninsight v0.1.0 (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("配置: %+v\n", cfg)

	return fmt.Errorf("监控功能尚未完全实现")
}

func checkPermissions() error {
	if runtime.GOOS == "linux" {
		// Linux: 检查 root 或 CAP_NET_ADMIN
		if os.Geteuid() != 0 {
			return fmt.Errorf("需要 root 权限或 CAP_NET_ADMIN 能力")
		}
	} else if runtime.GOOS == "darwin" {
		// macOS: 检查 root 或 BPF 访问权限
		if os.Geteuid() != 0 {
			// 检查 /dev/bpf* 是否可访问
			if _, err := os.Stat("/dev/bpf0"); os.IsPermission(err) {
				return fmt.Errorf("需要 sudo 权限或加入 access_bpf 组")
			}
		}
	}
	return nil
}

func Execute() error {
	return rootCmd.Execute()
}
```

**Step 3: 更新 main.go**

更新 `cmd/sninsight/main.go`:

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}
```

**Step 4: 验证编译**

```bash
go build ./cmd/sninsight
```

**Step 5: 提交**

```bash
git add -A && git commit -m "feat(cli): 实现 Cobra CLI 命令行框架"
```

---

## Phase 4: macOS libpcap 实现

### Task 11: 实现 macOS libpcap 抓包

**Files:**
- Modify: `internal/capture/pcap_darwin.go`
- Create: `internal/capture/interfaces.go`

**Step 1: 添加 gopacket 依赖**

```bash
go get github.com/google/gopacket
go get github.com/google/gopacket/pcap
go get github.com/google/gopacket/layers
```

**Step 2: 创建网卡发现工具**

创建 `internal/capture/interfaces.go`:

```go
package capture

import (
	"net"
	"strings"
)

// DiscoverInterfaces 发现可用网卡
func DiscoverInterfaces(specified []string) ([]string, error) {
	if len(specified) > 0 {
		return specified, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []string
	for _, iface := range ifaces {
		// 跳过回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// 跳过未启用的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// 跳过常见的虚拟接口
		name := iface.Name
		if shouldSkipInterface(name) {
			continue
		}
		result = append(result, name)
	}

	return result, nil
}

func shouldSkipInterface(name string) bool {
	skipPrefixes := []string{
		"lo",      // loopback
		"docker",  // docker
		"br-",     // docker bridge
		"veth",    // docker veth
		"virbr",   // libvirt bridge
		"vmnet",   // vmware
		"vboxnet", // virtualbox
		"utun",    // macOS utun
		"awdl",    // macOS awdl
		"llw",     // macOS llw
		"bridge",  // macOS bridge
		"gif",     // macOS gif
		"stf",     // macOS stf
		"anpi",    // macOS anpi
	}

	nameLower := strings.ToLower(name)
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(nameLower, prefix) {
			return true
		}
	}
	return false
}
```

**Step 3: 实现 macOS pcap 抓包**

更新 `internal/capture/pcap_darwin.go`:

```go
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
	snapshotLen = 512  // 抓包长度，足够获取 TLS ClientHello
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
```

**Step 4: 验证编译 (macOS)**

```bash
go build ./cmd/sninsight
```

**Step 5: 提交**

```bash
git add -A && git commit -m "feat(capture): 实现 macOS libpcap 抓包"
```

---

## Phase 5: 完整主程序集成

### Task 12: 集成主程序逻辑

**Files:**
- Modify: `cmd/sninsight/root.go`

**Step 1: 更新主程序**

更新 `cmd/sninsight/root.go` 中的 `runMonitor` 函数:

```go
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nickproject/sninsight/internal/aggregator"
	"github.com/nickproject/sninsight/internal/capture"
	"github.com/nickproject/sninsight/internal/config"
	"github.com/nickproject/sninsight/internal/export"
	"github.com/nickproject/sninsight/internal/filter"
	"github.com/nickproject/sninsight/internal/logger"
	"github.com/nickproject/sninsight/internal/tui"
)

var (
	cfgFile string
	cfg     *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "sninsight",
	Short: "基于 eBPF 的网络流量监控工具",
	Long: `Sninsight 是一个基于 eBPF 的网络流量监控工具。
支持实时监控网络流量，解析 TLS SNI 识别域名，
通过 TUI 界面实时展示流量统计。`,
	RunE: runMonitor,
}

func init() {
	cobra.OnInitialize(initConfig)

	// 基础选项
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "配置文件路径")
	rootCmd.Flags().StringSliceP("interface", "i", nil, "指定网卡 (可多次指定)")
	rootCmd.Flags().DurationP("refresh", "r", time.Second, "刷新间隔")

	// 过滤选项
	rootCmd.Flags().StringP("filter", "f", "", "BPF 过滤表达式")
	rootCmd.Flags().StringSlice("include-domains", nil, "域名白名单 (逗号分隔)")
	rootCmd.Flags().StringSlice("exclude-domains", nil, "域名黑名单 (逗号分隔)")

	// 输出选项
	rootCmd.Flags().DurationP("duration", "d", 0, "运行时长后退出")
	rootCmd.Flags().StringP("output", "o", "", "导出文件路径")
	rootCmd.Flags().String("format", "json", "导出格式 (json|csv)")
	rootCmd.Flags().Bool("no-tui", false, "禁用 TUI")

	// 日志选项
	rootCmd.Flags().String("log-file", "", "日志文件路径")
	rootCmd.Flags().String("log-level", "warn", "日志级别 (debug|info|warn|error)")

	// 绑定到 viper
	viper.BindPFlag("interfaces", rootCmd.Flags().Lookup("interface"))
	viper.BindPFlag("display.refresh", rootCmd.Flags().Lookup("refresh"))
	viper.BindPFlag("filter.bpf", rootCmd.Flags().Lookup("filter"))
	viper.BindPFlag("filter.include_domains", rootCmd.Flags().Lookup("include-domains"))
	viper.BindPFlag("filter.exclude_domains", rootCmd.Flags().Lookup("exclude-domains"))
	viper.BindPFlag("output.duration", rootCmd.Flags().Lookup("duration"))
	viper.BindPFlag("output.file", rootCmd.Flags().Lookup("output"))
	viper.BindPFlag("output.format", rootCmd.Flags().Lookup("format"))
	viper.BindPFlag("output.no_tui", rootCmd.Flags().Lookup("no-tui"))
	viper.BindPFlag("logging.file", rootCmd.Flags().Lookup("log-file"))
	viper.BindPFlag("logging.level", rootCmd.Flags().Lookup("log-level"))
}

func initConfig() {
	cfg = config.Default()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home + "/.config/sninsight")
		}
		viper.AddConfigPath("/etc/sninsight")
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("SNINSIGHT")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "读取配置文件错误: %v\n", err)
			os.Exit(1)
		}
	}

	if err := viper.Unmarshal(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "解析配置错误: %v\n", err)
		os.Exit(1)
	}
}

func runMonitor(cmd *cobra.Command, args []string) error {
	// 初始化日志
	logCfg := logger.Config{
		Level:     cfg.Logging.Level,
		File:      cfg.Logging.File,
		MaxSizeMB: cfg.Logging.MaxSizeMB,
		MaxFiles:  cfg.Logging.MaxFiles,
		ToStderr:  cfg.Output.NoTUI,
	}
	if err := logger.Init(logCfg); err != nil {
		return fmt.Errorf("初始化日志失败: %w", err)
	}
	defer logger.Sync()

	// 权限检查
	if err := checkPermissions(); err != nil {
		return err
	}

	// 创建 context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 处理信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("收到退出信号")
		cancel()
	}()

	// 如果设置了 duration，添加超时
	if cfg.Output.Duration > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, cfg.Output.Duration)
		defer timeoutCancel()
	}

	// 创建抓包器
	captureCfg := capture.CaptureConfig{
		Interfaces: cfg.Interfaces,
		BPFFilter:  cfg.Filter.BPF,
	}
	capturer, err := capture.New(captureCfg)
	if err != nil {
		return fmt.Errorf("创建抓包器失败: %w", err)
	}

	// 创建过滤器
	domainFilter := filter.New(cfg.Filter.IncludeDomains, cfg.Filter.ExcludeDomains)

	// 创建聚合器
	caps := capturer.Capabilities()
	agg := aggregator.NewAggregator(domainFilter, caps.SupportsDirection, cfg.Display.Refresh)

	// 创建输出通道
	entriesChan := make(chan []aggregator.TrafficEntry, 10)

	// 启动抓包
	go func() {
		if err := capturer.Start(ctx); err != nil && ctx.Err() == nil {
			logger.Error("抓包错误", "error", err)
		}
	}()

	// 启动聚合器
	go agg.Run(ctx, capturer.Events(), capturer.Stats(), entriesChan)

	// 获取系统信息
	hostname, _ := os.Hostname()
	ifaces, _ := capture.DiscoverInterfaces(cfg.Interfaces)

	startTime := time.Now()
	var lastEntries []aggregator.TrafficEntry

	// 运行 TUI 或等待导出
	if cfg.Output.NoTUI {
		// 非 TUI 模式：收集数据直到超时或退出
		for {
			select {
			case <-ctx.Done():
				goto exportData
			case entries := <-entriesChan:
				lastEntries = entries
			}
		}
	} else {
		// TUI 模式
		tuiCfg := tui.Config{
			SupportsDirection: caps.SupportsDirection,
			Hostname:          hostname,
			KernelVersion:     getKernelVersion(),
			Interfaces:        ifaces,
		}

		// 收集最后的数据用于导出
		go func() {
			for entries := range entriesChan {
				lastEntries = entries
			}
		}()

		if err := tui.Run(tuiCfg, entriesChan); err != nil {
			return fmt.Errorf("TUI 错误: %w", err)
		}
	}

exportData:
	// 导出数据
	if cfg.Output.File != "" && len(lastEntries) > 0 {
		format, err := export.ParseFormat(cfg.Output.Format)
		if err != nil {
			return err
		}

		var totalIn, totalOut uint64
		for _, e := range lastEntries {
			totalIn += e.TotalIn
			totalOut += e.TotalOut
		}

		report := &export.Report{
			Timestamp:   time.Now(),
			Duration:    time.Since(startTime),
			TotalIn:     totalIn,
			TotalOut:    totalOut,
			Connections: len(lastEntries),
			Entries:     lastEntries,
		}

		if err := export.Export(report, cfg.Output.File, format); err != nil {
			return fmt.Errorf("导出失败: %w", err)
		}
		logger.Info("数据已导出", "file", cfg.Output.File)
	}

	return nil
}

func checkPermissions() error {
	if runtime.GOOS == "linux" {
		if os.Geteuid() != 0 {
			return fmt.Errorf("需要 root 权限或 CAP_NET_ADMIN 能力")
		}
	} else if runtime.GOOS == "darwin" {
		if os.Geteuid() != 0 {
			if _, err := os.Stat("/dev/bpf0"); os.IsPermission(err) {
				return fmt.Errorf("需要 sudo 权限或加入 access_bpf 组")
			}
		}
	}
	return nil
}

func getKernelVersion() string {
	if runtime.GOOS == "darwin" {
		return "macOS"
	}
	// Linux: 读取 /proc/version
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	parts := strings.Fields(string(data))
	if len(parts) >= 3 {
		return parts[2]
	}
	return "unknown"
}

func Execute() error {
	return rootCmd.Execute()
}
```

**Step 2: 验证编译**

```bash
go build ./cmd/sninsight
```

**Step 3: 提交**

```bash
git add -A && git commit -m "feat: 集成主程序逻辑，连接所有组件"
```

---

## Phase 6: Linux eBPF 实现 (后续)

### Task 13: 编写 eBPF C 程序

**Files:**
- Create: `bpf/traffic.c`
- Create: `bpf/headers/vmlinux.h` (需要从目标系统生成)

**注意:** 此任务需要在 Linux 环境下完成，需要安装 clang、llvm 和 bpftool。

**Step 1: 创建 eBPF 程序骨架**

创建 `bpf/traffic.c`:

```c
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// 流量统计 Key
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  direction;  // 0=ingress, 1=egress
    __u16 _pad;
};

// 流量统计 Value
struct flow_value {
    __u64 bytes;
    __u64 packets;
    __u64 last_seen_ns;
};

// TLS 事件数据
struct tls_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  direction;
    __u16 payload_len;
    __u8  payload[256];
};

// 流量统计 Map (LRU Hash)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_stats SEC(".maps");

// TLS 事件 RingBuffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tls_events SEC(".maps");

// 检查是否为 TLS ClientHello
static __always_inline int is_tls_client_hello(void *data, void *data_end, __u32 offset) {
    if (data + offset + 6 > data_end)
        return 0;

    __u8 *payload = data + offset;

    // Content Type: Handshake (0x16)
    if (payload[0] != 0x16)
        return 0;

    // Handshake Type: ClientHello (0x01)
    if (payload[5] != 0x01)
        return 0;

    return 1;
}

// TC Ingress 程序
SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // 仅处理 IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 解析 IP 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // 仅处理 TCP
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // 解析 TCP 头
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // 构建 flow key
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = bpf_ntohs(tcp->source),
        .dst_port = bpf_ntohs(tcp->dest),
        .proto = ip->protocol,
        .direction = 0, // ingress
    };

    // 更新流量统计
    struct flow_value *val = bpf_map_lookup_elem(&flow_stats, &key);
    if (val) {
        __sync_fetch_and_add(&val->bytes, skb->len);
        __sync_fetch_and_add(&val->packets, 1);
        val->last_seen_ns = bpf_ktime_get_ns();
    } else {
        struct flow_value new_val = {
            .bytes = skb->len,
            .packets = 1,
            .last_seen_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_stats, &key, &new_val, BPF_ANY);
    }

    // 检查 TLS ClientHello
    __u32 tcp_header_len = tcp->doff * 4;
    __u32 payload_offset = sizeof(*eth) + (ip->ihl * 4) + tcp_header_len;

    if (is_tls_client_hello(data, data_end, payload_offset)) {
        struct tls_event *evt = bpf_ringbuf_reserve(&tls_events, sizeof(*evt), 0);
        if (evt) {
            evt->src_ip = ip->saddr;
            evt->dst_ip = ip->daddr;
            evt->src_port = bpf_ntohs(tcp->source);
            evt->dst_port = bpf_ntohs(tcp->dest);
            evt->proto = ip->protocol;
            evt->direction = 0;

            // 复制 payload (最多 256 字节)
            __u32 payload_len = data_end - (data + payload_offset);
            if (payload_len > 256)
                payload_len = 256;
            evt->payload_len = payload_len;

            bpf_probe_read_kernel(evt->payload, payload_len, data + payload_offset);

            bpf_ringbuf_submit(evt, 0);
        }
    }

    return TC_ACT_OK;
}

// TC Egress 程序 (类似 ingress，direction = 1)
SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    // ... 类似 ingress，但 direction = 1
    return TC_ACT_OK;
}
```

**Step 2: 创建 Go generate 指令**

创建 `internal/capture/generate.go`:

```go
package capture

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang traffic ../../bpf/traffic.c -- -I../../bpf/headers
```

**Step 3: 提交**

```bash
git add -A && git commit -m "feat(ebpf): 添加 eBPF C 程序骨架"
```

---

### Task 14: 创建 Makefile 和示例配置

**Files:**
- Create: `Makefile`
- Create: `configs/config.example.yaml`

**Step 1: 创建 Makefile**

创建 `Makefile`:

```makefile
.PHONY: all build build-linux build-darwin bpf generate clean

VERSION := 0.1.0
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"

all: build

# 构建当前平台
build:
	go build $(LDFLAGS) -o dist/sninsight ./cmd/sninsight

# 构建 Linux (需要在 Linux 上或交叉编译)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/sninsight-linux-amd64 ./cmd/sninsight

# 构建 macOS ARM
build-darwin:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/sninsight-darwin-arm64 ./cmd/sninsight

# 编译 eBPF 程序 (需要 clang)
bpf:
	clang -O2 -g -target bpf \
		-D__TARGET_ARCH_x86 \
		-I/usr/include \
		-c bpf/traffic.c \
		-o bpf/traffic.o

# 生成 Go eBPF 绑定
generate:
	go generate ./internal/capture/...

# 清理
clean:
	rm -rf dist/
	rm -f bpf/*.o
	rm -f internal/capture/traffic_*.go

# 运行 (需要 sudo)
run: build
	sudo ./dist/sninsight

# 安装依赖
deps:
	go mod download
	go mod tidy
```

**Step 2: 创建示例配置**

创建 `configs/config.example.yaml`:

```yaml
# Sninsight 配置示例

# 网卡列表 (留空表示所有非回环网卡)
interfaces:
  # - eth0
  # - ens192

# 过滤配置
filter:
  # BPF 过滤表达式
  bpf: ""
  # 域名白名单 (支持通配符)
  include_domains:
    # - "*.google.com"
    # - "github.com"
  # 域名黑名单 (支持通配符)
  exclude_domains:
    # - "*.doubleclick.net"
    # - "*.ads.*"

# 显示配置
display:
  # 刷新间隔
  refresh: 1s
  # 最大显示行数
  max_rows: 50

# 日志配置
logging:
  # 日志级别: debug, info, warn, error
  level: warn
  # 日志文件路径
  file: /var/log/sninsight/sninsight.log
  # 单文件最大 MB
  max_size_mb: 10
  # 保留文件数
  max_files: 3

# 输出配置
output:
  # 运行时长 (0 表示持续运行)
  duration: 0
  # 导出文件路径
  file: ""
  # 导出格式: json, csv
  format: json
  # 禁用 TUI
  no_tui: false
```

**Step 3: 提交**

```bash
git add -A && git commit -m "chore: 添加 Makefile 和示例配置"
```

---

## 验收检查

### 最终验证步骤

**Step 1: 验证 macOS 编译**

```bash
make build-darwin
./dist/sninsight-darwin-arm64 --help
```

Expected: 显示帮助信息

**Step 2: 验证运行 (需要 sudo)**

```bash
sudo ./dist/sninsight-darwin-arm64 -d 5s --no-tui
```

Expected: 运行 5 秒后退出

**Step 3: 最终提交**

```bash
git add -A && git commit -m "chore: 完成 Phase 1-5 实现"
```

---

## 后续工作 (Phase 6+)

以下任务需要在 Linux 环境完成:

1. **Task 13 完整实现**: 在 Linux 上编译 eBPF 程序
2. **Task 15**: 实现 Linux eBPF 抓包 (`ebpf_linux.go`)
3. **Task 16**: 端到端测试
4. **Task 17**: 性能优化

---

**Plan complete and saved to `docs/plans/2025-12-12-sninsight-implementation.md`.**

**两种执行方式:**

1. **Subagent-Driven (当前会话)** - 我为每个任务派发独立 subagent，任务间进行代码审查，快速迭代

2. **Parallel Session (单独会话)** - 在新会话中使用 executing-plans 技能，批量执行并设置检查点

**你选择哪种方式?**
