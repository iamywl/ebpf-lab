#!/usr/bin/env python3
"""runq_latency.py — CPU 실행 대기시간(스케줄러 지연) 히스토그램.

[배우는 OS 개념] 런큐(run queue), 컨텍스트 스위치, 선점, "실행 준비됐는데 CPU를 못 받고 기다린 시간".
   이 값이 크면 CPU 경쟁이 심하다는 뜻 — 시스템이 바쁜지 진단하는 핵심 지표(OSTEP 7~10장).
[eBPF로 무엇을] 태스크가 깨어난(wakeup) 시각과 실제 CPU를 잡은(switch) 시각의 차이를 분포로 집계.

부착 지점 : tracepoint:sched:sched_wakeup(+new), tracepoint:sched:sched_switch
관련 강의 : 14주차(성능), OS 모듈 V3(스케줄링)

실행:
    sudo python3 runq_latency.py --duration 5
    # 부하를 주려면 다른 창에서:  yes > /dev/null
"""

from __future__ import annotations

import argparse
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

BPF_HASH(wake_ts, u32, u64);    // pid -> 깨어난 시각(ns)
BPF_HISTOGRAM(dist);            // 대기시간(us) 로그2 분포

static inline void mark_wakeup(u32 pid) {
    u64 ts = bpf_ktime_get_ns();
    wake_ts.update(&pid, &ts);
}

TRACEPOINT_PROBE(sched, sched_wakeup) {
    mark_wakeup(args->pid);
    return 0;
}
TRACEPOINT_PROBE(sched, sched_wakeup_new) {
    mark_wakeup(args->pid);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 next = args->next_pid;
    u64 *tsp = wake_ts.lookup(&next);
    if (tsp) {
        u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
        dist.increment(bpf_log2l(delta_us));
        wake_ts.delete(&next);
    }
    return 0;
}
"""


def main() -> int:
    p = argparse.ArgumentParser(description="스케줄러 대기시간 히스토그램 (eBPF)")
    p.add_argument("--duration", type=float, default=5.0, help="추적 시간(초)")
    args = p.parse_args()

    bpf = BPF(text=BPF_TEXT)
    print(f"스케줄러 대기시간 측정 {args.duration}초... (다른 창에서 'yes > /dev/null' 로 부하)",
          file=sys.stderr)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    print("\n=== CPU 실행 대기시간 분포 (단위: 마이크로초) ===")
    bpf["dist"].print_log2_hist("usecs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
