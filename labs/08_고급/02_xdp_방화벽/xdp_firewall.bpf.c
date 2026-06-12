// xdp_firewall.bpf.c — XDP 로 패킷을 '커널 최전선(드라이버)'에서 처리한다.
//
// [무엇을] 들어오는 IPv4 패킷을 프로토콜(TCP/UDP/ICMP)별로 세고, ICMP 는 드롭(XDP_DROP)한다.
//   = eBPF 의 '관측'을 넘어 '강제(enforcement)'를 보여주는 예제. (DDoS 방어·로드밸런싱의 기초)
// [어디서] XDP 는 네트워크 스택보다 앞, 드라이버 수신 직후에 실행돼 가장 빠르다.
//
// 안전: 이 예제는 loopback(lo)에만 붙이므로 SSH(외부 인터페이스)에는 영향이 없다.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

char LICENSE[] SEC("license") = "GPL";

// 인덱스: 0=기타, 1=TCP, 2=UDP, 3=ICMP
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} pktcnt SEC(".maps");

static __always_inline void count(__u32 idx) {
    __u64 *c = bpf_map_lookup_elem(&pktcnt, &idx);
    if (c) {
        __sync_fetch_and_add(c, 1);
    }
}

SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_TCP) {
        count(1);
    } else if (ip->protocol == IPPROTO_UDP) {
        count(2);
    } else if (ip->protocol == IPPROTO_ICMP) {
        count(3);
        return XDP_DROP;   // ICMP(ping)는 커널에 닿기 전에 차단 = 강제
    } else {
        count(0);
    }
    return XDP_PASS;
}
