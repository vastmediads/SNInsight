# Sninsight 设计文档

## 概述

基于 eBPF 的跨平台网络流量监控工具，支持 TLS SNI 解析和实时 TUI 展示。

## 目标平台

| 平台 | 技术方案 | 功能完整度 |
|------|----------|-----------|
| Linux (Debian 11+) | eBPF + TC | 完整功能 |
| macOS ARM | libpcap (gopacket) | 简化版 (无方向区分) |

## 项目结构

```
sninsight/
├── cmd/
│   └── sninsight/
│       └── main.go           # 入口：参数解析、权限检查、启动
├── internal/
│   ├── capture/              # 抓包抽象层
│   │   ├── capture.go        # 接口定义
│   │   ├── ebpf_linux.go     # Linux eBPF/TC 实现
│   │   └── pcap_darwin.go    # macOS libpcap 实现
│   ├── parser/
│   │   └── sni.go            # TLS ClientHello SNI 解析
│   ├── aggregator/
│   │   └── stats.go          # 流量聚合、速率计算、GC
│   ├── filter/
│   │   └── filter.go         # BPF 表达式 + 域名黑白名单
│   ├── tui/
│   │   └── app.go            # Bubbletea TUI 实现
│   └── export/
│       └── export.go         # JSON/CSV 导出
├── bpf/
│   ├── traffic.c             # eBPF C 源码
│   └── headers/              # vmlinux.h 等
├── configs/
│   └── config.example.yaml   # 示例配置
└── go.mod
```

## 核心接口

### 抓包接口 (capture/capture.go)

```go
type PacketEvent struct {
    Timestamp   time.Time
    SrcIP       net.IP
    DstIP       net.IP
    SrcPort     uint16
    DstPort     uint16
    Protocol    uint8      // TCP=6, UDP=17
    Direction   Direction  // Ingress/Egress
    ByteCount   uint64
    Payload     []byte     // 仅 TLS ClientHello 时填充 (≤256 bytes)
}

type Direction uint8
const (
    Ingress Direction = iota  // 下载/入站
    Egress                    // 上传/出站
)

type Capturer interface {
    Start(ctx context.Context) error
    Stop() error
    Events() <-chan PacketEvent
    Stats() <-chan FlowStats      // 定时聚合统计 (1s)
    Capabilities() Capabilities   // 报告平台能力差异
}

type Capabilities struct {
    SupportsDirection bool  // Linux=true, macOS=false
    SupportsBPFFilter bool  // 是否支持 BPF 过滤表达式
}
```

### 数据流

1. `Capturer` 产生 `PacketEvent` 流
2. `parser.ExtractSNI(payload)` 提取域名，存入 `map[FiveTuple]string`
3. `aggregator` 每秒聚合，关联 SNI 映射，计算速率
4. `tui` 或 `export` 消费聚合结果

## eBPF 设计 (Linux)

### 挂载策略

- 使用 TC (Traffic Control) 挂载点
- 每个网卡挂载两个 BPF 程序：`tc_ingress` 和 `tc_egress`

### BPF Maps

```c
// 1. 流量统计 Map
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  direction;  // 0=ingress, 1=egress
};

struct flow_value {
    __u64 bytes;
    __u64 packets;
    __u64 last_seen_ns;
};

// BPF_MAP_TYPE_LRU_HASH - 自动淘汰旧条目
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); } flow_stats;

// 2. TLS 事件 RingBuffer
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } tls_events;
```

### TLS ClientHello 检测

1. 检查 TCP 且 payload 长度 > 5
2. 检查字节特征：`payload[0] == 0x16` (Handshake) + `payload[5] == 0x01` (ClientHello)
3. 匹配则截取前 256 字节，通过 RingBuffer 上报

## macOS 实现 (libpcap)

### 技术选型

- `google/gopacket` + `gopacket/pcap`
- 需要 sudo 或 access_bpf 组权限

### 功能限制

| 功能 | Linux (eBPF) | macOS (libpcap) |
|------|-------------|-----------------|
| Ingress/Egress 区分 | ✓ 精确 | ✗ 统一显示 |
| SNI 解析 | ✓ | ✓ |
| BPF 过滤表达式 | ✓ | ✓ |
| 性能影响 | 极低 | 中等 |
| 权限要求 | CAP_NET_ADMIN | sudo / access_bpf |

## 配置系统

### 命令行参数

```bash
sninsight [flags]

# 基础选项
  -i, --interface string    指定网卡 (默认: 所有非回环网卡)
  -r, --refresh duration    刷新间隔 (默认: 1s)
  -c, --config string       配置文件路径

# 过滤选项
  -f, --filter string       BPF 过滤表达式 (如 "port 443")
      --include-domains     域名白名单 (逗号分隔, 支持通配符)
      --exclude-domains     域名黑名单

# 输出选项
  -d, --duration duration   运行时长后自动退出 (如 "60s", "5m")
  -o, --output string       导出文件路径
      --format string       导出格式: json|csv (默认: json)
      --no-tui              禁用 TUI，仅统计后导出

# 日志选项
      --log-file string     日志文件路径 (默认: /var/log/sninsight/sninsight.log)
      --log-level string    日志级别: debug|info|warn|error (默认: warn)
```

### 配置文件 (~/.config/sninsight/config.yaml)

```yaml
interfaces:
  - eth0
  - ens192

filter:
  bpf: "port 443 or port 80"
  include_domains:
    - "*.google.com"
    - "github.com"
  exclude_domains:
    - "*.doubleclick.net"

display:
  refresh: 1s
  max_rows: 50

logging:
  level: info
  file: /var/log/sninsight/sninsight.log
  max_size_mb: 10
  max_files: 3
```

优先级：命令行参数 > 配置文件 > 默认值

## TUI 界面

```
┌─ Sninsight ─────────────────────────────────────────────────────────┐
│ Host: debian-server │ Kernel: 5.10.0 │ NICs: eth0, ens192           │
│ Total: ↓ 125.6 MB/s  ↑ 12.3 MB/s │ Connections: 847 │ Runtime: 5m32s│
├─────────────────────────────────────────────────────────────────────┤
│ Domain/IP              Proto  ↓ In Rate  ↑ Out Rate   Total   Conns │
│─────────────────────────────────────────────────────────────────────│
│ *.googleapis.com       TCP    45.2 MB/s   1.2 MB/s   2.1 GB    23   │
│ github.com             TCP    12.8 MB/s   0.5 MB/s   856 MB    12   │
│ 142.250.189.14:443     TCP     8.1 MB/s   0.3 MB/s   512 MB     4   │
│ *.cloudflare.com       TCP     5.6 MB/s   0.2 MB/s   320 MB    18   │
├─────────────────────────────────────────────────────────────────────┤
│ [q]uit  [s]ort: In Rate  [p]ause  [/]filter  [?]help                │
└─────────────────────────────────────────────────────────────────────┘
```

### 快捷键

| 按键 | 功能 |
|------|------|
| `q` | 退出 |
| `s` | 循环切换排序 (In Rate → Out Rate → Total → Conns) |
| `p` | 暂停/恢复刷新 |
| `/` | 实时过滤搜索 |
| `↑↓` | 滚动列表 |
| `?` | 显示帮助 |

macOS 上隐藏方向列，合并显示为 `Rate`。

## 依赖

```go
// go.mod
require (
    github.com/cilium/ebpf v0.12.0
    github.com/google/gopacket v1.1.19
    github.com/charmbracelet/bubbletea v0.25.0
    github.com/charmbracelet/lipgloss v0.9.0
    github.com/spf13/cobra v1.8.0
    github.com/spf13/viper v1.18.0
    gopkg.in/yaml.v3 v3.0.1
    gopkg.in/natefinch/lumberjack.v2 v2.2.1
)
```

## 构建

```makefile
# 编译 eBPF 程序
bpf:
    clang -O2 -g -target bpf -c bpf/traffic.c -o bpf/traffic.o

# 生成 Go 绑定
generate:
    go generate ./...

# 构建 Linux 二进制
build-linux:
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/sninsight-linux ./cmd/sninsight

# 构建 macOS 二进制 (需要 CGO)
build-darwin:
    CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o dist/sninsight-darwin ./cmd/sninsight
```

## 错误处理

### 启动检查

- 权限不足：报错退出
- 内核版本 < 5.8：警告但继续

### 运行时降级

| 场景 | 行为 |
|------|------|
| SNI 解析失败 | 显示 IP:Port |
| 网卡挂载失败 | 跳过该网卡 |
| RingBuffer 满 | 丢弃 SNI 事件 |
| BPF Map 满 | LRU 自动淘汰 |
| 配置文件不存在 | 使用默认配置 |
| 配置解析错误 | 报错退出 |

## 日志系统

- TUI 模式：静默写入文件
- 非 TUI 模式：同时输出 stderr 和文件
- 自动轮转：单文件 10MB，保留 3 个文件
- 文件权限：0640
