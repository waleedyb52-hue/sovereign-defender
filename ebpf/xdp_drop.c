/*
 * Sovereign Defender - Autonomous High-Performance In-Kernel XDP Filter
 * File: xdp_drop.c
 * Target: Linux Kernel 5.4+ (XDP Native / Generic / Offload)
 * License: Dual BSD/GPL
 *
 * Description:
 *   High-throughput eBPF XDP program that intercepts incoming ingress packets
 *   at the earliest possible point in the Linux network stack (NIC driver/XDP).
 *   Checks packet IPv4 source against an in-kernel BPF_MAP_TYPE_HASH blacklist.
 *   If matched, packet is dropped instantaneously (XDP_DROP) with zero CPU
 *   sk_buff allocation. Also tracks real-time dropped and passed packet/byte counters.
 *
 * Compile:
 *   clang -O2 -g -Wall -target bpf -c xdp_drop.c -o xdp_drop.o
 *
 * Load & Attach:
 *   ip link set dev eth0 xdpgeneric obj xdp_drop.o sec xdp
 *   bpftool prog load xdp_drop.o /sys/fs/bpf/xdp_drop type xdp pinmaps /sys/fs/bpf/
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

/* Alignment & Compatibility Definitions */
#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

/*
 * Data structure stored in the blacklist eBPF Hash Map
 */
struct ip_blacklist_entry {
    __u64 hits;           /* Monotonic match counter */
    __u64 added_at_ns;    /* Kernel monotonic timestamp (nanoseconds) */
    __u32 action;         /* 1 = XDP_DROP, 2 = XDP_PASS, 3 = XDP_REDIRECT */
    char reason[32];      /* Threat classification reason tag */
};

/*
 * Data structure for real-time datapath throughput & telemetry metrics
 */
struct datapath_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 dropped_packets;
    __u64 dropped_bytes;
    __u64 passed_packets;
    __u64 passed_bytes;
};

/*
 * Map 1: Blacklisted Source IPs (BPF_MAP_TYPE_HASH)
 * Key: __u32 (IPv4 in network byte order)
 * Value: struct ip_blacklist_entry
 * Capacity: 65,536 active quarantine entries
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct ip_blacklist_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blacklist_map SEC(".maps");

/*
 * Map 2: Real-time Datapath Statistics Array (BPF_MAP_TYPE_PERCPU_ARRAY)
 * Key: __u32 (Index 0 = global telemetry)
 * Value: struct datapath_stats
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datapath_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");

/*
 * XDP Ingress Hook Handler
 */
SEC("xdp")
int xdp_drop_prog(struct xdp_md *ctx)
{
    /* Packet boundary pointers provided by XDP driver */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = (__u64)(data_end - data);

    /* Retrieve per-CPU telemetry stats slot */
    __u32 stats_key = 0;
    struct datapath_stats *stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (stats) {
        stats->rx_packets++;
        stats->rx_bytes += pkt_len;
    }

    /* 1. Parse and verify Ethernet Header boundaries */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        /* Malformed frame: pass to kernel stack */
        return XDP_PASS;
    }

    /* 2. Filter only IPv4 traffic; allow IPv6 / ARP / other protocols through */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        if (stats) {
            stats->passed_packets++;
            stats->passed_bytes += pkt_len;
        }
        return XDP_PASS;
    }

    /* 3. Parse and verify IPv4 Header boundaries */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        /* Truncated IP packet */
        return XDP_PASS;
    }

    /* Strict header length check */
    if (iph->ihl < 5) {
        return XDP_PASS;
    }

    /* Bounds check variable IP options header */
    if ((void *)iph + (iph->ihl * 4) > data_end) {
        return XDP_PASS;
    }

    /* 4. Query BPF_MAP_TYPE_HASH blacklist map using IPv4 source */
    __u32 src_ip = iph->saddr;
    struct ip_blacklist_entry *entry = bpf_map_lookup_elem(&blacklist_map, &src_ip);

    if (entry) {
        /* Atomic counter increment for threat forensic tracking */
        __sync_fetch_and_add(&entry->hits, 1);

        if (stats) {
            stats->dropped_packets++;
            stats->dropped_bytes += pkt_len;
        }

        /* 
         * FAST-PATH ZERO-COPY DROP:
         * Instantly drops the packet at NIC driver layer before sk_buff allocation.
         */
        return XDP_DROP;
    }

    /* 5. Packet passed all Zero-Trust checks: forward to Linux network stack */
    if (stats) {
        stats->passed_packets++;
        stats->passed_bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
