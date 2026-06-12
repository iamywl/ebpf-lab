#!/usr/bin/env python3
"""page_faults.py — 프로세스별 페이지 폴트 집계기.

[배우는 OS 개념] 가상메모리, 페이지, 페이지 폴트(프로세스가 아직 메모리에 없는 영역에 접근해
   커널이 페이지를 채워주는 사건), 메모리 요구가 많은 프로세스(OSTEP 13~22장).
[eBPF로 무엇을] 페이지 폴트 이벤트를 프로세스별로 세어, 메모리를 적극적으로 만지는 프로세스를 찾는다.

부착 지점 : software:page-faults (perf 소프트웨어 이벤트)
관련 강의 : 14주차(성능), OS 모듈 V4(가상메모리)

실행:
    sudo python3 page_faults.py --duration 5
"""

from __future__ import annotations

import argparse
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

struct comm_t { char name[16]; };
BPF_HASH(faults, u32, u64);          // pid -> 페이지 폴트 횟수
BPF_HASH(names, u32, struct comm_t); // pid -> comm

int on_page_fault(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 init = 0, *cnt = faults.lookup_or_try_init(&pid, &init);
    if (cnt) {
        (*cnt)++;
    }
    struct comm_t c = {};
    bpf_get_current_comm(&c.name, sizeof(c.name));
    names.update(&pid, &c);
    return 0;
}
"""


def main() -> int:
    p = argparse.ArgumentParser(description="프로세스별 페이지 폴트 집계 (eBPF)")
    p.add_argument("--duration", type=float, default=5.0, help="추적 시간(초)")
    p.add_argument("--top", type=int, default=15, help="상위 N개")
    args = p.parse_args()

    bpf = BPF(text=BPF_TEXT)
    # 소프트웨어 페이지폴트 이벤트에 부착 (PERF_COUNT_SW_PAGE_FAULTS = 2)
    bpf.attach_perf_event(ev_type=1, ev_config=2, fn_name="on_page_fault",
                          sample_period=1, sample_freq=0)
    print(f"페이지 폴트 측정 {args.duration}초...", file=sys.stderr)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass

    names = bpf["names"]
    rows = []
    for k, v in bpf["faults"].items():
        comm = names[k].name.decode("utf-8", "replace").rstrip("\x00") if k in names else "?"
        rows.append((k.value, comm, v.value))
    rows.sort(key=lambda r: -r[2])

    print(f"\n=== 프로세스별 페이지 폴트 (최근 {args.duration}초) ===")
    print(f"  {'PID':>7} {'프로세스':<16} {'폴트수':>10}")
    print(f"  {'-' * 7} {'-' * 16} {'-' * 10}")
    for pid, comm, n in rows[: args.top]:
        print(f"  {pid:>7} {comm:<16} {n:>10,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
