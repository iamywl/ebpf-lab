#!/usr/bin/env python3
"""proc_audit.py — 새 프로그램 실행(execve) 실시간 감사기.

[배우는 OS 개념] 프로세스 생성, exec(), 사용자/그룹 ID(UID), 프로그램 이미지 교체.
[eBPF로 무엇을] execve 시스템콜 진입을 가로채 (시각, PID, UID, 프로세스, 실행파일)을 한 줄씩 보여준다.
   "이 서버에서 방금 무엇이, 누구 권한으로 실행됐나" — 보안 감사의 기본기.

부착 지점 : tracepoint:syscalls:sys_enter_execve
관련 강의 : 9·13주차, OS 모듈 V1(프로세스), V2(시스템콜)

실행:
    sudo python3 proc_audit.py                 # Ctrl-C 까지
    sudo python3 proc_audit.py --duration 10   # 10초간
    sudo python3 proc_audit.py --comm bash     # 특정 부모 프로세스만
"""

from __future__ import annotations

import argparse
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];     // execve 를 호출한(부모) 프로세스 이름
    char fname[128];   // 실행하려는 파일 경로
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    // execve 의 filename 은 사용자 공간 문자열 → bpf_probe_read_user_str 로 안전 복사
    bpf_probe_read_user_str(&e.fname, sizeof(e.fname), args->filename);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="execve 실행 감사기 (eBPF)")
    p.add_argument("--duration", type=float, default=0.0, help="추적 시간(초), 0=Ctrl-C 까지")
    p.add_argument("--comm", type=str, default=None, help="이 이름의 부모 프로세스만 표시")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    bpf = BPF(text=BPF_TEXT)
    print(f"{'시각':<10} {'PID':>7} {'UID':>6} {'프로세스':<16} 실행파일", file=sys.stderr)
    print("-" * 72, file=sys.stderr)

    def handle(_cpu, data, _size):
        e = bpf["events"].event(data)
        comm = e.comm.decode("utf-8", "replace")
        if args.comm and args.comm != comm:
            return
        fname = e.fname.decode("utf-8", "replace")
        print(f"{time.strftime('%H:%M:%S'):<10} {e.pid:>7} {e.uid:>6} {comm:<16} {fname}")

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
