#!/usr/bin/env python3
"""futex_contention.py — 락 경합(futex 대기) 측정기.

[배우는 OS 개념] 락, 임계구역, 블로킹, 경합(contention). 사용자 공간 뮤텍스는 경합이 없으면
   원자연산만으로 끝나지만, 경합하면 커널 `futex` 로 잠들었다 깨어난다(OSTEP 28~33장).
[eBPF로 무엇을] futex 시스템콜의 진입~반환 시간을 재서, 프로세스별로 "락 때문에 기다린 시간"을 합산한다.
   값이 크면 그 프로세스가 락 경합으로 시간을 버리고 있다는 뜻.

부착 지점 : tracepoint:syscalls:sys_enter_futex, sys_exit_futex
관련 강의 : OS 모듈 C2(락·동기화)

실행:
    sudo python3 futex_contention.py --duration 5
    # 경합을 만들려면: ostep threads_lock 같은 멀티스레드+뮤텍스 프로그램 실행
"""

from __future__ import annotations

import argparse
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

struct comm_t { char name[16]; };
struct stat_t { u64 calls; u64 wait_ns; };
BPF_HASH(enter_ts, u64, u64);        // pid_tgid -> futex 진입 시각
BPF_HASH(stats, u32, struct stat_t); // tgid -> {호출수, 대기시간 합}
BPF_HASH(names, u32, struct comm_t);

TRACEPOINT_PROBE(syscalls, sys_enter_futex) {
    u64 id = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    enter_ts.update(&id, &ts);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_futex) {
    u64 id = bpf_get_current_pid_tgid();
    u64 *tsp = enter_ts.lookup(&id);
    if (!tsp) {
        return 0;
    }
    u32 tgid = id >> 32;
    struct stat_t init = {}, *s = stats.lookup_or_try_init(&tgid, &init);
    if (s) {
        s->calls += 1;
        s->wait_ns += bpf_ktime_get_ns() - *tsp;
    }
    struct comm_t c = {};
    bpf_get_current_comm(&c.name, sizeof(c.name));
    names.update(&tgid, &c);
    enter_ts.delete(&id);
    return 0;
}
"""


def main() -> int:
    p = argparse.ArgumentParser(description="락 경합(futex 대기) 측정 (eBPF)")
    p.add_argument("--duration", type=float, default=5.0, help="추적 시간(초)")
    p.add_argument("--top", type=int, default=15, help="상위 N개")
    args = p.parse_args()

    bpf = BPF(text=BPF_TEXT)
    print(f"futex 대기 측정 {args.duration}초...", file=sys.stderr)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    names = bpf["names"]
    rows = []
    for k, v in bpf["stats"].items():
        comm = names[k].name.decode("utf-8", "replace").rstrip("\x00") if k in names else "?"
        rows.append((k.value, comm, v.calls, v.wait_ns / 1e6))
    rows.sort(key=lambda r: -r[3])

    print(f"\n=== 프로세스별 futex(락) 대기 시간 (최근 {args.duration}초) ===")
    print(f"  {'PID':>7} {'프로세스':<16} {'futex호출':>10} {'대기합(ms)':>12}")
    print(f"  {'-' * 7} {'-' * 16} {'-' * 10} {'-' * 12}")
    for pid, comm, calls, ms in rows[: args.top]:
        print(f"  {pid:>7} {comm:<16} {calls:>10,} {ms:>12.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
