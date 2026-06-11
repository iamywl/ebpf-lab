#!/usr/bin/env python3
"""프로세스(PID)별 TCP 연결(아웃바운드) 추적기.

커널의 tcp_v4_connect() 에 kprobe 를 걸어, 어떤 프로세스가 어느 목적지로
TCP 연결을 시도하는지 실시간으로 출력하고 PID별로 집계한다.

사용 예::

    sudo python3 netflow.py                 # Ctrl-C 까지 실시간 추적
    sudo python3 netflow.py --duration 10   # 10초간 추적 후 PID별 요약
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from collections import defaultdict

from bcc import BPF

BPF_SOURCE = "bpf/tcpconnect.c"


def ip_str(daddr: int) -> str:
    # daddr 는 네트워크 바이트 오더 값이 호스트(리틀엔디언) 정수로 담겨 있다.
    return socket.inet_ntoa(struct.pack("<I", daddr))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PID별 TCP 연결 추적기 (eBPF)")
    p.add_argument("--duration", type=float, default=0.0,
                   help="추적 시간(초). 0 이면 Ctrl-C 까지 (기본: 0)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    print("eBPF TCP 연결 추적기를 로드하는 중...", file=sys.stderr)
    bpf = BPF(src_file=BPF_SOURCE)

    print(f"{'시각':<12} {'PID':>7}  {'프로세스':<16} {'목적지'}")
    print("-" * 60)

    per_pid: dict[int, int] = defaultdict(int)
    lost = {"count": 0}

    def handle(_cpu, data, _size):
        e = bpf["events"].event(data)
        comm = e.comm.decode("utf-8", "replace")
        dport = socket.ntohs(e.dport)
        dst = f"{ip_str(e.daddr)}:{dport}"
        per_pid[e.pid] += 1
        ts = time.strftime("%H:%M:%S")
        print(f"{ts:<12} {e.pid:>7}  {comm:<16} {dst}")

    def on_lost(n):
        # perf 버퍼가 가득 차 커널이 이벤트를 버린 경우 — 조용히 누락되지 않도록 알린다.
        lost["count"] += n

    bpf["events"].open_perf_buffer(handle, lost_cb=on_lost)

    start = time.time()
    try:
        while True:
            bpf.perf_buffer_poll(timeout=200)
            if args.duration and (time.time() - start) >= args.duration:
                break
    except KeyboardInterrupt:
        pass

    print("\n=== PID별 TCP 연결 시도 횟수 ===")
    if not per_pid:
        print("  (관측된 연결 없음)")
    for pid in sorted(per_pid, key=lambda p: -per_pid[p]):
        print(f"  PID {pid:>7} : {per_pid[pid]:>6} 회")
    if lost["count"]:
        print(f"\n  ⚠️ perf 버퍼 과부하로 누락된 이벤트: {lost['count']}개")
    return 0


if __name__ == "__main__":
    sys.exit(main())
