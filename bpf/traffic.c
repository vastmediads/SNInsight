//go:build ignore

// eBPF 流量监控程序
// 用于 Linux 平台的 TC (Traffic Control) 钩子

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

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
    __u64 timestamp_ns;
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

// 更新流量统计
static __always_inline void update_flow_stats(struct flow_key *key, __u32 pkt_len) {
    struct flow_value *val = bpf_map_lookup_elem(&flow_stats, key);
    if (val) {
        __sync_fetch_and_add(&val->bytes, pkt_len);
        __sync_fetch_and_add(&val->packets, 1);
        val->last_seen_ns = bpf_ktime_get_ns();
    } else {
        struct flow_value new_val = {
            .bytes = pkt_len,
            .packets = 1,
            .last_seen_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_stats, key, &new_val, BPF_ANY);
    }
}

// 处理 IPv4 数据包
static __always_inline int process_ipv4(struct __sk_buff *skb, __u8 direction) {
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

    // 仅处理 TCP/UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return TC_ACT_OK;

    // 构建 flow key
    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .proto = ip->protocol,
        .direction = direction,
    };

    __u32 payload_offset = sizeof(*eth) + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        // 解析 TCP 头
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        key.src_port = bpf_ntohs(tcp->source);
        key.dst_port = bpf_ntohs(tcp->dest);

        __u32 tcp_hdr_len = tcp->doff * 4;
        payload_offset += tcp_hdr_len;

        // 更新统计
        update_flow_stats(&key, skb->len);

        // 检查 TLS ClientHello
        if (is_tls_client_hello(data, data_end, payload_offset)) {
            struct tls_event *evt = bpf_ringbuf_reserve(&tls_events, sizeof(*evt), 0);
            if (evt) {
                evt->timestamp_ns = bpf_ktime_get_ns();
                evt->src_ip = ip->saddr;
                evt->dst_ip = ip->daddr;
                evt->src_port = key.src_port;
                evt->dst_port = key.dst_port;
                evt->proto = ip->protocol;
                evt->direction = direction;

                // 计算 payload 长度
                __u32 payload_len = data_end - (data + payload_offset);
                if (payload_len > 256)
                    payload_len = 256;
                evt->payload_len = payload_len;

                // 复制 payload
                if (payload_len > 0) {
                    bpf_probe_read_kernel(evt->payload, payload_len, data + payload_offset);
                }

                bpf_ringbuf_submit(evt, 0);
            }
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        // 解析 UDP 头
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        key.src_port = bpf_ntohs(udp->source);
        key.dst_port = bpf_ntohs(udp->dest);

        // 更新统计
        update_flow_stats(&key, skb->len);
    }

    return TC_ACT_OK;
}

// TC Ingress 程序
SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    return process_ipv4(skb, 0); // direction = 0 (ingress)
}

// TC Egress 程序
SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    return process_ipv4(skb, 1); // direction = 1 (egress)
}
