#!/usr/bin/env python3
"""open_audit.py — 파일 열기(openat) 감사기: 누가·무엇을·결과까지.

[배우는 OS 개념] 파일 디스크립터(fd), open 플래그(읽기/쓰기/생성), 성공/실패(음수 fd),
   파일이 inode 로 연결되는 첫 단계(OSTEP 39장).
[eBPF로 무엇을] openat 진입에서 경로·플래그를 잡고, 반환에서 결과 fd 를 짝지어 한 줄로 보여준다.
   "이 프로그램이 무슨 파일을, 어떤 의도로 열었고, 성공했나"를 추적.

부착 지점 : tracepoint:syscalls:sys_enter_openat, sys_exit_openat
관련 강의 : 9주차, OS 모듈 P2(파일시스템)

실행:
    sudo python3 open_audit.py --duration 8
    sudo python3 open_audit.py --comm cat
"""

from __future__ import annotations

import argparse
import sys
import time

from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

struct val_t { char fname[128]; int flags; };
BPF_HASH(active, u64, struct val_t);   // pid_tgid -> 진행 중 open 정보

struct event_t {
    u32 pid;
    int flags;
    int ret;       // 결과 fd (음수면 실패)
    char comm[16];
    char fname[128];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct val_t v = {};
    v.flags = args->flags;
    bpf_probe_read_user_str(&v.fname, sizeof(v.fname), args->filename);
    u64 id = bpf_get_current_pid_tgid();
    active.update(&id, &v);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *vp = active.lookup(&id);
    if (!vp) {
        return 0;
    }
    struct event_t e = {};
    e.pid = id >> 32;
    e.flags = vp->flags;
    e.ret = args->ret;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    __builtin_memcpy(&e.fname, vp->fname, sizeof(e.fname));
    events.perf_submit(args, &e, sizeof(e));
    active.delete(&id);
    return 0;
}
"""

O_WRONLY, O_RDWR, O_CREAT = 0o1, 0o2, 0o100


def flag_str(flags: int) -> str:
    if flags & O_RDWR:
        mode = "RW"
    elif flags & O_WRONLY:
        mode = "W"
    else:
        mode = "R"
    return mode + ("+C" if flags & O_CREAT else "")


def main() -> int:
    p = argparse.ArgumentParser(description="파일 열기 감사기 (eBPF)")
    p.add_argument("--duration", type=float, default=0.0, help="추적 시간(초), 0=Ctrl-C")
    p.add_argument("--comm", type=str, default=None, help="이 프로세스만")
    args = p.parse_args()

    bpf = BPF(text=BPF_TEXT)
    print(f"{'PID':>7} {'프로세스':<14} {'모드':>4} {'fd':>5}  파일", file=sys.stderr)
    print("-" * 70, file=sys.stderr)

    def handle(_cpu, data, _size):
        e = bpf["events"].event(data)
        comm = e.comm.decode("utf-8", "replace")
        if args.comm and args.comm != comm:
            return
        fname = e.fname.decode("utf-8", "replace")
        fd = e.ret if e.ret >= 0 else f"{e.ret}(실패)"
        print(f"{e.pid:>7} {comm:<14} {flag_str(e.flags):>4} {str(fd):>5}  {fname}")

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
