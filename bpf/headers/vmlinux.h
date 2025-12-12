// 最小化 vmlinux.h - 用于 eBPF 程序编译
// 在实际 Linux 系统上，应使用 bpftool btf dump 生成

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;

enum {
    BPF_ANY = 0,
    BPF_NOEXIST = 1,
    BPF_EXIST = 2,
};

// TC action codes
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2

// Ethernet header
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 ihl:4,
         version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version:4,
         ihl:4;
#else
    __u8 ihl:4,
         version:4;
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

// IPv6 header
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 priority:4,
         version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version:4,
         priority:4;
#else
    __u8 priority:4,
         version:4;
#endif
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    struct in6_addr {
        union {
            __u8 u6_addr8[16];
            __be16 u6_addr16[8];
            __be32 u6_addr32[4];
        } in6_u;
    } saddr;
    struct in6_addr daddr;
} __attribute__((packed));

// TCP header
struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16 res1:4,
          doff:4,
          fin:1,
          syn:1,
          rst:1,
          psh:1,
          ack:1,
          urg:1,
          ece:1,
          cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16 doff:4,
          res1:4,
          cwr:1,
          ece:1,
          urg:1,
          ack:1,
          psh:1,
          rst:1,
          syn:1,
          fin:1;
#else
    __u16 res1:4,
          doff:4,
          fin:1,
          syn:1,
          rst:1,
          psh:1,
          ack:1,
          urg:1,
          ece:1,
          cwr:1;
#endif
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
} __attribute__((packed));

// UDP header
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
} __attribute__((packed));

// sk_buff (简化版本)
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
    __u64 tstamp;
    __u32 wire_len;
    __u32 gso_segs;
    __u64 hwtstamp;
};

#endif /* __VMLINUX_H__ */
