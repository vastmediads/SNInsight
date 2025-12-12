# SNInsight

基于 eBPF 的实时网络流量监控工具，支持 TLS SNI 域名识别。

![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## 功能特性

- **实时流量监控** - 基于 eBPF (Linux) 或 libpcap (macOS) 内核态捕获
- **SNI 域名识别** - 自动解析 TLS ClientHello 提取目标域名
- **交互式 TUI** - 类似 `top` 的实时刷新界面
- **多维度统计** - 支持按速率、流量、连接数排序
- **灵活过滤** - BPF 表达式 + 域名黑白名单
- **数据导出** - 支持 JSON/CSV 格式导出
- **跨平台** - 支持 Linux x86_64/ARM64 和 macOS

## 快速开始

### 安装

从 [Releases](https://github.com/vastmediads/SNInsight/releases) 下载预编译二进制，或从源码构建：

```bash
git clone https://github.com/vastmediads/SNInsight.git
cd SNInsight
make build
```

### 运行

```bash
# Linux 需要 root 权限
sudo ./dist/sninsight

# 指定网卡
sudo ./dist/sninsight -i eth0

# 仅监控 HTTPS 流量
sudo ./dist/sninsight -f "tcp port 443"

# 仅显示能解析 SNI 的流量
sudo ./dist/sninsight --sni-only
```

## 界面预览

```
SNInsight v0.1.0 | 运行: 00:05:23 | 网卡: eth0
入站: 12.5 MB/s | 出站: 3.2 MB/s | 连接: 156

排序: [1]入站 [2]出站 [3]总量 | 过滤: /搜索 | 退出: q

域名/IP                          入站速率    出站速率    总流量      连接
───────────────────────────────────────────────────────────────────────
*.googleapis.com                 5.2 MB/s    120 KB/s    28.5 MB     23
github.com                       2.1 MB/s    89 KB/s     12.3 MB     8
*.cloudflare.com                 1.8 MB/s    45 KB/s     9.8 MB      15
192.168.1.100:8080              1.2 MB/s    890 KB/s    6.2 MB      3
```

## 命令行参数

### 基础选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c, --config` | 配置文件路径 | 自动查找 |
| `-i, --interface` | 网卡名称（可多次指定） | 所有网卡 |
| `-r, --refresh` | TUI 刷新间隔 | 1s |

### 过滤选项

| 参数 | 说明 | 示例 |
|------|------|------|
| `-f, --filter` | BPF 过滤表达式 | `tcp port 443` |
| `--include-domains` | 域名白名单 | `*.google.com` |
| `--exclude-domains` | 域名黑名单 | `*.ads.com` |
| `--sni-only` | 仅统计 SNI 流量 | - |

### 输出选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-d, --duration` | 运行时长 | 持续运行 |
| `-o, --output` | 导出文件路径 | - |
| `--format` | 导出格式 (json/csv) | json |
| `--no-tui` | 禁用 TUI 后台运行 | false |

### 诊断选项

| 参数 | 说明 |
|------|------|
| `--diagnose-ebpf` | eBPF 环境诊断 (仅 Linux) |
| `--diagnose-sni` | SNI 捕获诊断 (仅 Linux) |

## 配置文件

配置文件查找顺序：

1. `-c` 命令行指定
2. `~/.config/sninsight/config.yaml`
3. `/etc/sninsight/config.yaml`
4. `./config.yaml`

示例配置：

```yaml
interfaces: []              # 空表示所有网卡

filter:
  bpf: "tcp port 443"       # BPF 过滤
  include_domains:          # 白名单
    - "*.google.com"
  exclude_domains:          # 黑名单
    - "*.ads.*"
  sni_only: false

display:
  refresh: 1s
  max_rows: 50

logging:
  level: warn               # debug|info|warn|error
  file: /var/log/sninsight/sninsight.log

output:
  format: json
```

## 构建

### 依赖

- Go 1.24+
- Linux: clang, llvm (用于编译 eBPF)
- macOS: libpcap

### 构建命令

```bash
make build          # 当前平台
make build-linux    # Linux amd64
make build-darwin   # macOS ARM64
make build-all      # 所有平台
make install        # 安装到 /usr/local/bin
```

## 工作原理

```
┌─────────────────────────────────────────────────────────┐
│                      用户空间                            │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────┐  │
│  │ TUI显示 │◄───│ 聚合器  │◄───│SNI解析器│◄───│Event│  │
│  └─────────┘    └─────────┘    └─────────┘    └──▲──┘  │
│                       ▲                          │      │
│                       │ 流量统计                 │      │
│                  ┌────┴────┐                     │      │
│                  │ BPF Map │                     │      │
├──────────────────┴────┬────┴────────────────────┼──────┤
│                       │                          │      │
│  ┌────────────────────▼──────────────────────────┴───┐  │
│  │              eBPF 程序 (TC Hook)                   │  │
│  │  • Ingress: 入站流量统计 + TLS ClientHello 捕获   │  │
│  │  • Egress:  出站流量统计 + TLS ClientHello 捕获   │  │
│  └───────────────────────────────────────────────────┘  │
│                      内核空间                            │
└─────────────────────────────────────────────────────────┘
```

## 权限要求

| 平台 | 要求 |
|------|------|
| Linux | root 权限或 `CAP_NET_ADMIN` 能力 |
| macOS | sudo 权限或加入 `access_bpf` 组 |

## License

MIT License
