#!/usr/bin/env python3
"""syscall_latency.py — 시스템콜 소요시간 분포(히스토그램).

[배우는 OS 개념] 시스템콜 비용, 모드 전환 오버헤드, 빠른 콜과 느린(블로킹) 콜의 차이.
[eBPF로 무엇을] 모든 시스템콜의 진입~반환 시간을 재서 분포를 그린다. 느린 꼬리(tail)가 곧 병목 후보.

부착 지점 : tracepoint:raw_syscalls:sys_enter, sys_exit
관련 강의 : 2주차(시스템콜), 14주차(성능)

실행:
    sudo python3 syscall_latency.py --duration 5
    sudo python3 syscall_latency.py --duration 5 --pid 1234
"""
from __future__ import annotations
import argparse, sys, time
from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
BPF_HASH(start, u64, u64);     // pid_tgid -> 진입 시각
BPF_HISTOGRAM(dist);           // 소요시간(us) 로그2 분포
BPF_ARRAY(target, u32, 1);     // 0=전체, 그 외=해당 PID

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 id = bpf_get_current_pid_tgid();
    int zero = 0; u32 *t = target.lookup(&zero);
    if (t && *t != 0 && *t != (id >> 32)) { return 0; }
    u64 ts = bpf_ktime_get_ns();
    start.update(&id, &ts);
    return 0;
}
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 id = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&id);
    if (tsp) {
        dist.increment(bpf_log2l((bpf_ktime_get_ns() - *tsp) / 1000));
        start.delete(&id);
    }
    return 0;
}
"""

def main() -> int:
    p = argparse.ArgumentParser(description="시스템콜 지연 히스토그램 (eBPF)")
    p.add_argument("--duration", type=float, default=5.0, help="추적 시간(초)")
    p.add_argument("--pid", type=int, default=0, help="이 PID 만")
    args = p.parse_args()
    bpf = BPF(text=BPF_TEXT)
    import ctypes
    bpf["target"][ctypes.c_int(0)] = ctypes.c_uint(args.pid)
    scope = f"PID={args.pid}" if args.pid else "전체"
    print(f"시스템콜 지연 측정 {args.duration}초 ({scope})...", file=sys.stderr)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    print("\n=== 시스템콜 소요시간 분포 (단위: 마이크로초) ===")
    bpf["dist"].print_log2_hist("usecs")
    return 0

if __name__ == "__main__":
    sys.exit(main())
