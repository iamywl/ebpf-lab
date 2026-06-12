#!/usr/bin/env python3
"""conn_summary.py — 프로세스별·목적지별 아웃바운드 TCP 연결 집계기.

[배우는 OS 개념] 소켓, TCP 연결(connect), 클라이언트가 서버로 나가는 연결, 목적지 IP:포트(OSTEP 네트워킹).
[eBPF로 무엇을] 커널 tcp_v4_connect 를 가로채 (프로세스, 목적지 IP:포트)별 연결 횟수를 집계한다.
   10주차 실습(netflow-tracer)이 '실시간 스트림'이라면, 이건 '요약 집계' 버전.

부착 지점 : kprobe:tcp_v4_connect
관련 강의 : 10·12주차, OS 모듈 P? (네트워킹)

실행:
    sudo python3 conn_summary.py --duration 8
    # 다른 창에서 curl 여러 번
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/in.h>

#ifndef AF_INET
#define AF_INET 2
#endif

struct key_t { u32 pid; u32 daddr; u16 dport; char comm[16]; };
BPF_HASH(counts, struct key_t, u64);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, void *sk,
                           struct sockaddr *uaddr, int addr_len) {
    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sin->sin_family);
    if (family != AF_INET) {
        return 0;
    }
    struct key_t k = {};
    k.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel(&k.daddr, sizeof(k.daddr), &sin->sin_addr.s_addr);
    bpf_probe_read_kernel(&k.dport, sizeof(k.dport), &sin->sin_port);
    bpf_get_current_comm(&k.comm, sizeof(k.comm));
    u64 init = 0, *v = counts.lookup_or_try_init(&k, &init);
    if (v) {
        (*v)++;
    }
    return 0;
}
"""


def ip_str(daddr: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", daddr))


def main() -> int:
    p = argparse.ArgumentParser(description="프로세스별 TCP 연결 집계 (eBPF)")
    p.add_argument("--duration", type=float, default=8.0, help="추적 시간(초)")
    args = p.parse_args()

    bpf = BPF(text=BPF_TEXT)
    print(f"TCP 연결 집계 {args.duration}초... (다른 창에서 curl 등)", file=sys.stderr)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    rows = []
    for k, v in bpf["counts"].items():
        comm = k.comm.decode("utf-8", "replace")
        dst = f"{ip_str(k.daddr)}:{socket.ntohs(k.dport)}"
        rows.append((k.pid, comm, dst, v.value))
    rows.sort(key=lambda r: -r[3])

    print(f"\n=== 프로세스별·목적지별 TCP 연결 (최근 {args.duration}초) ===")
    print(f"  {'PID':>7} {'프로세스':<16} {'목적지':<24} {'횟수':>6}")
    print(f"  {'-' * 7} {'-' * 16} {'-' * 24} {'-' * 6}")
    for pid, comm, dst, n in rows:
        print(f"  {pid:>7} {comm:<16} {dst:<24} {n:>6}")
    if not rows:
        print("  (관측된 연결 없음 — 추적 중 curl/ssh 등을 실행해 보세요)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
