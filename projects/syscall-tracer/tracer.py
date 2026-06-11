#!/usr/bin/env python3
"""프로세스(PID)별 시스템콜 추적기.

raw_syscalls:sys_enter 트레이스포인트에 eBPF 프로그램을 붙여
(PID, 시스템콜)별 호출 횟수를 커널에서 집계하고, 종료 시 요약을 출력한다.

사용 예::

    sudo python3 tracer.py --duration 5            # 5초간 전체 추적
    sudo python3 tracer.py --pid 1234              # 특정 PID 만 추적
    sudo python3 tracer.py --comm nginx --top 10   # 이름이 nginx 인 프로세스
"""

from __future__ import annotations

import argparse
import ctypes
import signal
import sys
import time
from collections import defaultdict

from bcc import BPF
from bcc.syscall import syscall_name

BPF_SOURCE = "bpf/syscall_count.c"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PID별 시스템콜 추적기 (eBPF)")
    p.add_argument("--pid", type=int, default=0, help="이 PID 만 추적 (기본: 전체)")
    p.add_argument("--comm", type=str, default=None, help="이 이름의 프로세스만 결과에 표시")
    p.add_argument("--duration", type=float, default=0.0,
                   help="추적 시간(초). 0 이면 Ctrl-C 까지 (기본: 0)")
    p.add_argument("--top", type=int, default=15, help="PID별 상위 N개 시스콜만 출력 (기본: 15)")
    return p.parse_args()


def load_bpf(target_pid: int) -> BPF:
    bpf = BPF(src_file=BPF_SOURCE)
    # 부착 직후 기본값은 0(=드롭). 여기서 즉시 실제 필터 값으로 덮어쓴다.
    #   target_pid == 0 → 0xFFFFFFFF(전체 추적),  그 외 → 해당 PID
    want = 0xFFFFFFFF if target_pid == 0 else target_pid
    bpf["target"][ctypes.c_int(0)] = ctypes.c_uint(want)
    return bpf


def render(bpf: BPF, comm_filter: str | None, top: int) -> None:
    counts = bpf["counts"]
    comms = bpf["comms"]

    # tgid -> 이름
    name_of: dict[int, str] = {}
    for k, v in comms.items():
        name_of[k.value] = v.name.decode("utf-8", "replace").rstrip("\x00")

    # tgid -> {syscall_name: count}
    per_pid: dict[int, dict[str, int]] = defaultdict(dict)
    for k, v in counts.items():
        name = syscall_name(k.syscall_id).decode("utf-8", "replace")
        per_pid[k.tgid][name] = v.value

    if not per_pid:
        print("\n[결과 없음] 추적된 시스템콜이 없습니다.")
        return

    # PID별 총 호출 수 기준 내림차순
    for tgid in sorted(per_pid, key=lambda p: -sum(per_pid[p].values())):
        comm = name_of.get(tgid, "?")
        if comm_filter and comm_filter not in comm:
            continue
        total = sum(per_pid[tgid].values())
        print(f"\n=== PID {tgid}  ({comm})  총 {total:,} 회 ===")
        print(f"  {'시스템콜':<20} {'횟수':>12}")
        print(f"  {'-' * 20} {'-' * 12}")
        rows = sorted(per_pid[tgid].items(), key=lambda kv: -kv[1])
        for name, cnt in rows[:top]:
            print(f"  {name:<20} {cnt:>12,}")
        if len(rows) > top:
            print(f"  ... 외 {len(rows) - top}개 시스템콜")


def main() -> int:
    args = parse_args()
    print("eBPF 시스템콜 추적기를 로드하는 중...", file=sys.stderr)
    bpf = load_bpf(args.pid)

    scope = f"PID={args.pid}" if args.pid else "전체 프로세스"
    dur = f"{args.duration}초" if args.duration else "Ctrl-C 까지"
    print(f"추적 시작: {scope}, 기간 {dur}\n", file=sys.stderr)

    stop = {"flag": False}

    def on_signal(_sig, _frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, on_signal)

    start = time.time()
    try:
        while not stop["flag"]:
            time.sleep(0.2)
            if args.duration and (time.time() - start) >= args.duration:
                break
    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start
    print(f"\n추적 종료 (경과 {elapsed:.1f}초). 결과를 집계합니다.", file=sys.stderr)
    render(bpf, args.comm, args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
