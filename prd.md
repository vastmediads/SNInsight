# 🛠️ 产品技术规格说明书 (Technical Product Specification)

## 1. 系统综述 (System Overview)
### 1.1 核心目标
构建一个基于 eBPF 的 Linux 命令行网络流量监控工具。该工具需在内核层实时捕获所有网卡的 TCP/UDP 流量，自动解析 TLS 握手包中的 SNI (Server Name Indication) 以识别域名，并通过 TUI (文本用户界面) 实时展示按域名/IP 聚合的入站与出站流量速率。

### 1.2 范围定义 (Scope Definition)
*   **包含 (In Scope)**:
    *   **多网卡支持**: 自动发现并挂载所有非回环 (Loopback) 物理/虚拟网卡。
    *   **双向监控**: 基于 TC (Traffic Control) 区分 Ingress (下载/输入) 和 Egress (上传/输出) 流量。
    *   **SNI 识别**: 解析 HTTPS 流量的域名；非 HTTPS 流量降级显示 IP:Port。
    *   **TUI 交互**: 类似 `top` 的实时刷新列表，支持按流量排序。
    *   **资源管理**: 自动清理过期连接，防止内存泄漏。
*   **排除 (Out of Scope)**:
    *   HTTP/1.1 Host 头解析 (仅关注 TLS SNI，不处理明文 HTTP 深度包检测)。
    *   应用层内容解密 (不进行 SSL Termination/Decryption)。
    *   历史数据持久化存储 (仅内存态实时展示)。
    *   Windows/macOS 支持 (仅限 Linux)。

---

## 2. 业务流程与状态 (Workflows & States)

### 2.1 数据流处理管道 (Data Pipeline)

```mermaid
flowchart TD
    subgraph Kernel_Space [内核态 (eBPF/TC)]
        A[网络数据包 skb] --> B{挂载点 TC-Ingress/Egress}
        B --> C[eBPF Program]
        C --> D{是 TLS ClientHello?}
        
        D -- Yes (首包) --> E[截取 Payload 前 256 字节]
        E --> F[写入 RingBuffer/PerfEvents]
        
        D -- No (后续包/非TLS) --> G[更新 BPF Hash Map]
        G --> H[Key: 5元组, Val: 字节数/时间戳]
    end

    subgraph User_Space [用户态 (Go)]
        F -.-> I[Go接收: 解析 SNI 字符串]
        I --> J[更新本地 SessionMap]
        J --> K[映射: 5元组 -> 域名]
        
        L[定时器 Ticker 1s] --> M[读取 BPF Hash Map 统计]
        M --> N[关联 SessionMap 获取域名]
        N --> O[聚合计算速率]
        O --> P[TUI 渲染层]
    end
```

### 2.2 连接生命周期状态 (Connection Lifecycle)
*   **New**: eBPF 捕获到 SYN 包或 TLS ClientHello，用户态建立映射。
*   **Active**: 持续有数据包更新 BPF Map 中的计数器和时间戳。
*   **Closed**: 捕获到 FIN/RST 包，或超过 `TTL_THRESHOLD` (如 60秒) 无数据。
*   **Cleanup**: 用户态定时任务从 BPF Map 和本地 SessionMap 中移除过期条目。

---

## 3. 功能逻辑详述 (Functional Specifications)

### 3.1 模块：eBPF 内核探针 (Kernel Probe)
*   **触发条件**: 网卡接收或发送数据包时触发 TC 挂载的 BPF 程序。
*   **前置校验**:
    1.  协议校验：仅处理 IPv4/IPv6 下的 TCP 与 UDP 包。
    2.  排除逻辑：忽略 SSH (端口22) 自身流量（可选，避免监控工具本身流量造成回环干扰）。
*   **处理逻辑 (Processing Logic)**:
    1.  **解析包头**: 从 `__sk_buff` 提取 SrcIP, DstIP, SrcPort, DstPort, Protocol。
    2.  **TLS 判定**:
        *   检查是否为 TCP 且 Payload 长度 > 0。
        *   检查 Payload 前几个字节特征：`0x16` (Handshake) + `0x03 0x01/02/03` (SSL/TLS Version) + `0x01` (ClientHello)。
    3.  **SNI 上报**:
        *   如果判定为 TLS ClientHello，将包头+Payload (截断至 256字节) 写入 RingBuffer 发送给用户态。
    4.  **流量统计**:
        *   以 5元组 (SrcIP, DstIP, SrcPort, DstPort, Proto) 为 Key。
        *   原子累加 (Atomic Add) `bytes_sent` 或 `bytes_received` 到 BPF Map。
        *   更新 `last_seen_timestamp`。
*   **异常处理**:
    *   RingBuffer 满：丢弃 SNI 解析事件，仅做纯流量统计（降级为显示 IP）。

### 3.2 模块：用户态数据聚合 (Go Data Aggregator)
*   **触发条件**: RingBuffer 推送事件 或 1秒定时器。
*   **处理逻辑**:
    1.  **SNI 解析协程**:
        *   从 RingBuffer 读取二进制数据。
        *   解析 TLS 扩展字段提取 Server Name 字符串。
        *   存储映射：`Map<FiveTupleStr, DomainStr>`。
    2.  **统计同步协程 (1s 间隔)**:
        *   `bpfMapIterator` 遍历内核 BPF Map。
        *   读取累计字节数 `TotalBytes`。
        *   计算速率：`Rate = (TotalBytes - LastTotalBytes) / 1s`。
        *   **归因逻辑**: 使用 5元组在 `Map<FiveTupleStr, DomainStr>` 中查找域名。
            *   命中: 归入该域名统计。
            *   未命中: 归入 `DstIP` (Outbound) 或 `SrcIP` (Inbound) 统计。
    3.  **清理逻辑 (GC)**:
        *   遍历本地 Cache，若 `Now - LastSeen > 60s`，删除本地映射并调用 `bpf_map_delete_elem` 清理内核 Map。

### 3.3 模块：TUI 交互界面 (Bubbletea View)
*   **技术栈**: `charmbracelet/bubbletea` + `lipgloss` (样式)。
*   **界面布局**:
    *   **Header**: 系统信息 (Hostname, Kernel Ver)，总流量 (Total Up/Down)。
    *   **Body (Table)**:
        *   列定义: `[Domain/IP]`, `[Proto]`, `[In Rate]`, `[Out Rate]`, `[Total In]`, `[Total Out]`, `[Active Conns]`。
        *   默认按 `Total Rate (In+Out)` 降序排列。
    *   **Footer**: 操作提示 (q: Quit, s: Sort Mode, p: Pause)。
*   **交互逻辑**:
    *   按 `s`: 循环切换排序列 (按上传速率/下载速率/总流量)。
    *   按 `p`: 暂停/恢复 屏幕刷新 (数据采集后台继续)。
    *   按 `Resize`: 响应终端大小变化，动态调整显示的行数。

---

## 4. 数据模型需求 (Data Models)

### 4.1 内核态 BPF Map 定义
1.  **Map Name**: `traffic_stats_map`
    *   **Type**: `BPF_MAP_TYPE_HASH`
    *   **Key (struct five_tuple)**:
        ```c
        struct key_t {
            u32 src_ip;
            u32 dst_ip;
            u16 src_port;
            u16 dst_port;
            u8  proto;
        };
        ```
    *   **Value (struct flow_metrics)**:
        ```c
        struct value_t {
            u64 bytes_in;  // 入站累积字节
            u64 bytes_out; // 出站累积字节
            u64 ts_us;     // 最后更新时间戳(微秒)
        };
        ```

2.  **Map Name**: `tls_events`
    *   **Type**: `BPF_MAP_TYPE_RINGBUF`
    *   **Data**: Raw packet payload (Header + partial body).

### 4.2 用户态 Go 聚合结构
*   **TrafficEntry**:
    | 字段 | 类型 | 说明 |
    | :--- | :--- | :--- |
    | DisplayName | string | 域名 或 IP:Port |
    | UploadRate | uint64 | bps (bits per second) |
    | DownloadRate| uint64 | bps |
    | TotalTx | uint64 | Bytes |
    | TotalRx | uint64 | Bytes |
    | ConnCount | int | 聚合的连接(5元组)数量 |

---

## 5. 业务规则字典 (Business Rules)
| 规则ID | 规则名称 | 逻辑详述 |
| :--- | :--- | :--- |
| BR-001 | SNI 提取原则 | 仅提取 TLS ClientHello 中的 Server Name 扩展。若存在多个 SNI (极少见)，取第一个。若解析失败，回退显示目标 IP。 |
| BR-002 | 流量方向定义 | 基于 TC 挂载点判定。`TC_INGRESS` 判定为 Download，`TC_EGRESS` 判定为 Upload。 |
| BR-003 | 速率计算窗口 | 采用差值法：`(当前时刻累计值 - 上一秒累计值) / 时间间隔`。显示时转换为人类可读格式 (Kbps, Mbps)。 |
| BR-004 | 权限检查 | 程序启动时必须检查 `CAP_NET_ADMIN` 和 `CAP_SYS_RESOURCE` 权限，否则报错退出。 |

---

## 6. 非功能性约束 (Non-Functional Constraints)
*   **兼容性**: 
    *   Linux Kernel >= 4.18 (支持 eBPF TC BPF)。
    *   推荐 Kernel >= 5.8 (支持 CO-RE，一次编译到处运行)。
*   **性能消耗**: 
    *   eBPF 指令数限制 < 4096 (老内核兼容) 或 < 100万 (新内核)。
    *   用户态 CPU 占用率在 1Gbps 流量下不超过 5% 单核。
*   **依赖**:
    *   外部库: `cilium/ebpf` (Go bindings), `bubbletea` (TUI)。
    *   运行时: 无需安装 LLVM/Clang (如果使用 CO-RE 预编译对象)。
