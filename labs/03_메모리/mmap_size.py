#!/usr/bin/env python3
"""mmap_size.py — 프로세스별 메모리 매핑(mmap) 요청량 집계기.

[배우는 OS 개념] 메모리 할당 경로(mmap/brk), 주소공간 확장, malloc 의 밑바닥(OSTEP 13~17장).
   큰 메모리 할당은 보통 mmap 으로, 힙 확장은 brk 로 일어난다.
[eBPF로 무엇을] mmap 시스템콜의 요청 크기를 프로세스별로 합산하고 호출 횟수를 센다.

부착 지점 : tracepoint:syscalls:sys_enter_mmap
관련 강의 : OS 모듈 V4(가상메모리)

실행:
    sudo python3 mmap_size.py --duration 5
"""

from __future__ import annotations

import argparse
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

struct comm_t { char name[16]; };
struct stat_t { u64 calls; u64 bytes; };
BPF_HASH(stats, u32, struct stat_t);
BPF_HASH(names, u32, struct comm_t);

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct stat_t init = {}, *s = stats.lookup_or_try_init(&pid, &init);
    if (s) {
        s->calls += 1;
        s->bytes += args->len;   // mmap 의 length 인자 = 요청 바이트
    }
    struct comm_t c = {};
    bpf_get_current_comm(&c.name, sizeof(c.name));
    names.update(&pid, &c);
    return 0;
}
"""


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def main() -> int:
    p = argparse.ArgumentParser(description="프로세스별 mmap 요청량 (eBPF)")
    p.add_argument("--duration", type=float, default=5.0, help="추적 시간(초)")
    p.add_argument("--top", type=int, default=15, help="상위 N개")
    args = p.parse_args()

    bpf = BPF(text=BPF_TEXT)
    print(f"mmap 요청량 측정 {args.duration}초...", file=sys.stderr)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    names = bpf["names"]
    rows = []
    for k, v in bpf["stats"].items():
        comm = names[k].name.decode("utf-8", "replace").rstrip("\x00") if k in names else "?"
        rows.append((k.value, comm, v.calls, v.bytes))
    rows.sort(key=lambda r: -r[3])

    print(f"\n=== 프로세스별 mmap 요청량 (최근 {args.duration}초) ===")
    print(f"  {'PID':>7} {'프로세스':<16} {'호출수':>8} {'요청합계':>10}")
    print(f"  {'-' * 7} {'-' * 16} {'-' * 8} {'-' * 10}")
    for pid, comm, calls, byts in rows[: args.top]:
        print(f"  {pid:>7} {comm:<16} {calls:>8,} {human(byts):>10}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
