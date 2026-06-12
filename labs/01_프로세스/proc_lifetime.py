#!/usr/bin/env python3
"""proc_lifetime.py — 프로세스 수명(생성→종료) 측정기.

[배우는 OS 개념] 프로세스 생명주기(fork/exec → exit), 종료 코드, 짧은 수명 프로세스(short-lived)의 발견.
[eBPF로 무엇을] 프로세스가 exec 된 시각을 기록해 두었다가, 종료(exit)될 때 (수명, 종료코드)를 출력한다.
   "수천 개의 짧은 프로세스가 시스템을 좀먹는" 문제를 찾는 고전 기법.

부착 지점 : tracepoint:sched:sched_process_exec, tracepoint:sched:sched_process_exit
관련 강의 : OS 모듈 V1(프로세스), 13주차(보안)

실행:
    sudo python3 proc_lifetime.py --duration 10
"""

from __future__ import annotations

import argparse
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

BPF_HASH(start_ts, u32, u64);   // pid -> exec 시각(ns)

struct event_t {
    u32 pid;
    u64 lifetime_ns;
    int exit_code;
    char comm[16];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    start_ts.update(&pid, &ts);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *tsp = start_ts.lookup(&pid);
    if (!tsp) {
        return 0;  // exec 을 못 본 프로세스(추적 시작 전 존재)는 무시
    }
    struct event_t e = {};
    e.pid = pid;
    e.lifetime_ns = bpf_ktime_get_ns() - *tsp;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    events.perf_submit(args, &e, sizeof(e));
    start_ts.delete(&pid);
    return 0;
}
"""


def main() -> int:
    p = argparse.ArgumentParser(description="프로세스 수명 측정기 (eBPF)")
    p.add_argument("--duration", type=float, default=0.0, help="추적 시간(초), 0=Ctrl-C 까지")
    args = p.parse_args()

    bpf = BPF(text=BPF_TEXT)
    print(f"{'시각':<10} {'PID':>7} {'프로세스':<16} {'수명':>12}", file=sys.stderr)
    print("-" * 50, file=sys.stderr)

    def handle(_cpu, data, _size):
        e = bpf["events"].event(data)
        comm = e.comm.decode("utf-8", "replace")
        ms = e.lifetime_ns / 1e6
        dur = f"{ms:.1f} ms" if ms < 1000 else f"{ms / 1000:.2f} s"
        print(f"{time.strftime('%H:%M:%S'):<10} {e.pid:>7} {comm:<16} {dur:>12}")

    bpf["events"].open_perf_buffer(handle)
    start = time.time()
    try:
        while True:
            bpf.perf_buffer_poll(timeout=200)
            if args.duration and (time.time() - start) >= args.duration:
                break
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
