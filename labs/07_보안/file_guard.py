#!/usr/bin/env python3
"""file_guard.py — 민감 파일 접근 경보기 (런타임 보안 탐지 예제).

[배우는 OS 개념] 접근 제어, 민감 자원(예: /etc/shadow, SSH 키), 런타임 위협 탐지의 기본 발상.
   Falco/Tetragon 같은 eBPF 보안 도구가 하는 일의 축소판(OSTEP 보안 관점 + 13주차).
[eBPF로 무엇을] openat 으로 열리는 파일 경로를 커널에서 보고, 지정한 '민감 경로 패턴'에 걸리면
   (시각, PID, UID, 프로세스, 경로)를 경보로 출력한다.

부착 지점 : tracepoint:syscalls:sys_enter_openat
관련 강의 : 13주차(보안), OS 모듈 P2(파일)

실행:
    sudo python3 file_guard.py                       # 기본 민감 경로 감시
    sudo python3 file_guard.py --pattern .ssh        # 추가 패턴
    # 테스트:  다른 창에서  cat /etc/shadow   (권한 없어도 '시도'가 잡힘)
"""

from __future__ import annotations

import argparse
import sys
import time

from bcc import BPF

# 기본 감시 대상(부분 문자열). 사용자 공간에서 필터링한다(코드 단순화).
DEFAULT_WATCH = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", ".ssh/", "id_rsa", "/etc/gshadow"]

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char fname[160];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(&e.fname, sizeof(e.fname), args->filename);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""


def main() -> int:
    p = argparse.ArgumentParser(description="민감 파일 접근 경보기 (eBPF)")
    p.add_argument("--pattern", action="append", default=[], help="추가 감시 패턴(여러 번 가능)")
    p.add_argument("--duration", type=float, default=0.0, help="추적 시간(초), 0=Ctrl-C")
    args = p.parse_args()
    watch = DEFAULT_WATCH + args.pattern

    bpf = BPF(text=BPF_TEXT)
    print(f"민감 파일 접근 감시 시작. 대상 패턴: {', '.join(watch)}", file=sys.stderr)
    print(f"{'시각':<10} {'PID':>7} {'UID':>6} {'프로세스':<14} 경로", file=sys.stderr)
    print("-" * 72, file=sys.stderr)

    def handle(_cpu, data, _size):
        e = bpf["events"].event(data)
        fname = e.fname.decode("utf-8", "replace")
        if not any(w in fname for w in watch):
            return
        comm = e.comm.decode("utf-8", "replace")
        print(f"⚠️ {time.strftime('%H:%M:%S'):<8} {e.pid:>7} {e.uid:>6} {comm:<14} {fname}")

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
