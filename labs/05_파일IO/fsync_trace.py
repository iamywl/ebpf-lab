#!/usr/bin/env python3
"""fsync_trace.py — fsync(디스크 동기화) 추적기.

[배우는 OS 개념] 영속성·내구성(durability), 페이지 캐시와 디스크의 간극, fsync 가 데이터를
   실제로 디스크에 박아 넣는 비용. 크래시 일관성·저널링의 핵심 연산(OSTEP 42장).
[eBPF로 무엇을] fsync/fdatasync 시스템콜의 횟수와 소요시간을 프로세스별로 집계한다.
   DB·로그·에디터가 얼마나 자주, 얼마나 오래 디스크 동기화에 시간을 쓰는지 보인다.

부착 지점 : tracepoint:syscalls:sys_enter_fsync, sys_exit_fsync
관련 강의 : OS 모듈 P3(저널링·캐시), 14주차(성능)

실행:
    sudo python3 fsync_trace.py --duration 8
    # 테스트: 다른 창에서  for i in 1 2 3; do dd if=/dev/zero of=/tmp/x bs=1M count=16; sync; done
"""
from __future__ import annotations
import argparse, sys, time
from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
struct comm_t { char name[16]; };
struct stat_t { u64 count; u64 total_ns; u64 max_ns; };
BPF_HASH(start, u64, u64);
BPF_HASH(stats, u32, struct stat_t);
BPF_HASH(names, u32, struct comm_t);

TRACEPOINT_PROBE(syscalls, sys_enter_fsync) {
    u64 id = bpf_get_current_pid_tgid(); u64 ts = bpf_ktime_get_ns();
    start.update(&id, &ts);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_fsync) {
    u64 id = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&id);
    if (!tsp) { return 0; }
    u64 d = bpf_ktime_get_ns() - *tsp;
    u32 tgid = id >> 32;
    struct stat_t init = {}, *s = stats.lookup_or_try_init(&tgid, &init);
    if (s) { s->count += 1; s->total_ns += d; if (d > s->max_ns) s->max_ns = d; }
    struct comm_t c = {}; bpf_get_current_comm(&c.name, sizeof(c.name));
    names.update(&tgid, &c);
    start.delete(&id);
    return 0;
}
"""

def main() -> int:
    p = argparse.ArgumentParser(description="fsync 추적기 (eBPF)")
    p.add_argument("--duration", type=float, default=8.0, help="추적 시간(초)")
    args = p.parse_args()
    bpf = BPF(text=BPF_TEXT)
    print(f"fsync 측정 {args.duration}초... (다른 창서 dd+sync 로 유발)", file=sys.stderr)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    names = bpf["names"]; rows = []
    for k, v in bpf["stats"].items():
        comm = names[k].name.decode("utf-8","replace").rstrip("\x00") if k in names else "?"
        rows.append((k.value, comm, v.count, v.total_ns/1e6, v.max_ns/1e6))
    rows.sort(key=lambda r: -r[3])
    print(f"\n=== 프로세스별 fsync (최근 {args.duration}초) ===")
    print(f"  {'PID':>7} {'프로세스':<16} {'횟수':>6} {'총시간(ms)':>11} {'최대(ms)':>9}")
    print(f"  {'-'*7} {'-'*16} {'-'*6} {'-'*11} {'-'*9}")
    for pid, comm, n, tot, mx in rows[:15]:
        print(f"  {pid:>7} {comm:<16} {n:>6} {tot:>11.1f} {mx:>9.2f}")
    if not rows:
        print("  (fsync 없음 — 추적 중 dd+sync 등을 실행해 보세요)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
