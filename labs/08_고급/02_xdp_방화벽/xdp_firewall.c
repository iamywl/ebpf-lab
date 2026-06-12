// xdp_firewall.c — XDP 프로그램을 인터페이스에 붙이고, 프로토콜별 패킷 수를 보여준다.
// 기본 대상은 loopback(lo). 종료 시 자동으로 떼어낸다(detach).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>   // XDP_FLAGS_SKB_MODE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_firewall.skel.h"

static volatile sig_atomic_t exiting = 0;
static void on_signal(int sig) { exiting = 1; }

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
    const char *ifname = (argc > 1) ? argv[1] : "lo";   // 기본: loopback (안전)
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "인터페이스 '%s' 를 찾을 수 없습니다\n", ifname);
        return 1;
    }

    libbpf_set_print(libbpf_print);
    struct xdp_firewall_bpf *skel = xdp_firewall_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "BPF 로드 실패\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_fw);
    // generic(SKB) 모드로 부착 — 가상 NIC·loopback 에서도 동작
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL)) {
        fprintf(stderr, "XDP 부착 실패 (sudo 필요)\n");
        xdp_firewall_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    printf("XDP 부착됨: %s (ICMP 차단 + 프로토콜 카운트). Ctrl-C 종료.\n", ifname);
    printf("테스트: 다른 창에서  ping -c3 127.0.0.1  (드롭됨) /  curl 127.0.0.1:22  (통과·카운트)\n\n");

    int map_fd = bpf_map__fd(skel->maps.pktcnt);
    const char *names[4] = {"기타", "TCP", "UDP", "ICMP(차단)"};
    while (!exiting) {
        sleep(1);
        printf("\r패킷 수  ");
        for (__u32 i = 0; i < 4; i++) {
            __u64 v = 0;
            bpf_map_lookup_elem(map_fd, &i, &v);
            printf("%s=%-6llu ", names[i], (unsigned long long)v);
        }
        fflush(stdout);
    }

    // 떼어내기 (안 하면 lo 가 계속 ICMP 드롭)
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    xdp_firewall_bpf__destroy(skel);
    printf("\nXDP 분리 완료.\n");
    return 0;
}
