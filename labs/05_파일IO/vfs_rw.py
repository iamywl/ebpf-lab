#!/usr/bin/env python3
"""vfs_rw.py — 프로세스별 파일 읽기/쓰기 바이트 집계기.

[배우는 OS 개념] VFS(가상 파일시스템) — 모든 파일 입출력이 거쳐가는 커널의 공통 길목.
   read()/write() 시스템콜은 결국 커널의 vfs_read()/vfs_write() 로 모인다(OSTEP 39~40장).
[eBPF로 무엇을] vfs_read/vfs_write 커널 함수를 가로채 프로세스별로 읽고 쓴 바이트를 합산한다.
   "디스크/파일 I/O 를 많이 하는 프로세스"를 한눈에.

부착 지점 : kprobe:vfs_read, kprobe:vfs_write
관련 강의 : 5주차(kprobe), 14주차(성능), OS 모듈 P2(파일시스템)

실행:
    sudo python3 vfs_rw.py --duration 5
"""

from __future__ import annotations

import argparse
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

struct comm_t { char name[16]; };
struct io_t { u64 rbytes; u64 wbytes; };
BPF_HASH(io, u32, struct io_t);
BPF_HASH(names, u32, struct comm_t);

static inline void record(u32 pid, int is_write, u64 n) {
    struct io_t init = {}, *p = io.lookup_or_try_init(&pid, &init);
    if (p) {
        if (is_write) { p->wbytes += n; } else { p->rbytes += n; }
    }
    struct comm_t c = {};
    bpf_get_current_comm(&c.name, sizeof(c.name));
    names.update(&pid, &c);
}

// vfs_read(struct file*, char __user*, size_t count, loff_t*)  → 3번째 인자 = count
int kprobe__vfs_read(struct pt_regs *ctx, void *file, void *buf, size_t count) {
    record(bpf_get_current_pid_tgid() >> 32, 0, count);
    return 0;
}
int kprobe__vfs_write(struct pt_regs *ctx, void *file, void *buf, size_t count) {
    record(bpf_get_current_pid_tgid() >> 32, 1, count);
    return 0;
}
"""


def human(n: int) -> str:
    x = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if x < 1024 or unit == "GB":
            return f"{x:.0f}{unit}" if unit == "B" else f"{x:.1f}{unit}"
        x /= 1024
    return f"{x:.1f}GB"


def main() -> int:
    p = argparse.ArgumentParser(description="프로세스별 파일 읽기/쓰기 바이트 (eBPF)")
    p.add_argument("--duration", type=float, default=5.0, help="추적 시간(초)")
    p.add_argument("--top", type=int, default=15, help="상위 N개")
    args = p.parse_args()

    bpf = BPF(text=BPF_TEXT)
    print(f"파일 I/O 측정 {args.duration}초...", file=sys.stderr)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    names = bpf["names"]
    rows = []
    for k, v in bpf["io"].items():
        comm = names[k].name.decode("utf-8", "replace").rstrip("\x00") if k in names else "?"
        rows.append((k.value, comm, v.rbytes, v.wbytes))
    rows.sort(key=lambda r: -(r[2] + r[3]))

    print(f"\n=== 프로세스별 파일 읽기/쓰기 (최근 {args.duration}초) ===")
    print(f"  {'PID':>7} {'프로세스':<16} {'읽기':>10} {'쓰기':>10}")
    print(f"  {'-' * 7} {'-' * 16} {'-' * 10} {'-' * 10}")
    for pid, comm, rb, wb in rows[: args.top]:
        print(f"  {pid:>7} {comm:<16} {human(rb):>10} {human(wb):>10}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
