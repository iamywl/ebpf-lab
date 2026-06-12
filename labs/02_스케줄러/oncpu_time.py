#!/usr/bin/env python3
"""oncpu_time.py — 프로세스별 CPU 점유 시간 집계기.

[배우는 OS 개념] 컨텍스트 스위치, 타임슬라이스, "어떤 프로세스가 CPU를 실제로 얼마나 썼나".
[eBPF로 무엇을] sched_switch 에서 직전 태스크가 CPU를 잡고 있던 시간을 누적해, 프로세스별 on-CPU 시간을 보여준다.
   top 이 보여주는 CPU% 의 밑바탕을 직접 계산해 본다.

부착 지점 : tracepoint:sched:sched_switch
관련 강의 : 14주차(성능), OS 모듈 V3(스케줄링)

실행:
    sudo python3 oncpu_time.py --duration 5
"""

from __future__ import annotations

import argparse
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

struct comm_t { char name[16]; };
BPF_HASH(oncpu_start, u32, u64);      // pid -> CPU 잡은 시각(ns)
BPF_HASH(oncpu_ns, u32, u64);         // pid -> 누적 on-CPU 시간(ns)
BPF_HASH(names, u32, struct comm_t);  // pid -> comm

TRACEPOINT_PROBE(sched, sched_switch) {
    u64 now = bpf_ktime_get_ns();

    // 1) 나가는(prev) 태스크: 잡고 있던 시간을 누적
    u32 prev = args->prev_pid;
    if (prev != 0) {
        u64 *st = oncpu_start.lookup(&prev);
        if (st) {
            u64 init = 0, *acc = oncpu_ns.lookup_or_try_init(&prev, &init);
            if (acc) {
                *acc += now - *st;
            }
            struct comm_t c = {};
            bpf_probe_read_kernel(&c.name, sizeof(c.name), args->prev_comm);
            names.update(&prev, &c);
        }
    }

    // 2) 들어오는(next) 태스크: 지금부터 시간 측정 시작
    u32 next = args->next_pid;
    if (next != 0) {
        oncpu_start.update(&next, &now);
    }
    return 0;
}
"""


def main() -> int:
    p = argparse.ArgumentParser(description="프로세스별 CPU 점유 시간 (eBPF)")
    p.add_argument("--duration", type=float, default=5.0, help="추적 시간(초)")
    p.add_argument("--top", type=int, default=15, help="상위 N개")
    args = p.parse_args()

    bpf = BPF(text=BPF_TEXT)
    print(f"CPU 점유 시간 측정 {args.duration}초...", file=sys.stderr)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    names = bpf["names"]
    rows = []
    for k, v in bpf["oncpu_ns"].items():
        pid = k.value
        comm = names[k].name.decode("utf-8", "replace").rstrip("\x00") if k in names else "?"
        rows.append((pid, comm, v.value / 1e6))
    rows.sort(key=lambda r: -r[2])

    print(f"\n=== 프로세스별 CPU 점유 시간 (최근 {args.duration}초) ===")
    print(f"  {'PID':>7} {'프로세스':<16} {'on-CPU(ms)':>12}")
    print(f"  {'-' * 7} {'-' * 16} {'-' * 12}")
    for pid, comm, ms in rows[: args.top]:
        print(f"  {pid:>7} {comm:<16} {ms:>12.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
