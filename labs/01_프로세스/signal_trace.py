#!/usr/bin/env python3
"""signal_trace.py — 시그널 추적기: 누가 누구에게 무슨 시그널을 보내나.

[배우는 OS 개념] 시그널(SIGTERM/KILL/INT…)과 프로세스 간 통신(IPC), 비동기 통지, 프로세스 종료 경로.
[eBPF로 무엇을] 커널의 signal_generate 추적점에서 (보낸 프로세스, 받는 PID/이름, 시그널 번호)를 실시간으로.
   "누가 이 프로세스를 죽였나" 같은 추적에 쓰인다.

부착 지점 : tracepoint:signal:signal_generate
관련 강의 : 13주차(보안), OS 모듈 C/V (프로세스·시그널)

실행:
    sudo python3 signal_trace.py --duration 10
    # 테스트: 다른 창에서  sleep 100 &  후  kill %1
"""
from __future__ import annotations
import argparse, sys, time
from bcc import BPF

SIGNAMES = {1: "HUP", 2: "INT", 3: "QUIT", 9: "KILL", 11: "SEGV",
            13: "PIPE", 15: "TERM", 17: "CHLD", 18: "CONT", 19: "STOP"}

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
struct event_t {
    u32 spid;        // 보낸 프로세스 PID
    u32 tpid;        // 받는 프로세스 PID
    int sig;
    char scomm[16];  // 보낸 프로세스 이름
    char tcomm[16];  // 받는 프로세스 이름
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(signal, signal_generate) {
    struct event_t e = {};
    e.spid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.scomm, sizeof(e.scomm));
    e.tpid = args->pid;
    e.sig = args->sig;
    bpf_probe_read_kernel(&e.tcomm, sizeof(e.tcomm), args->comm);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""

def main() -> int:
    p = argparse.ArgumentParser(description="시그널 추적기 (eBPF)")
    p.add_argument("--duration", type=float, default=0.0, help="추적 시간(초), 0=Ctrl-C")
    args = p.parse_args()
    bpf = BPF(text=BPF_TEXT)
    print(f"{'시각':<10} {'보낸PID':>8} {'보낸이름':<14} -> {'받는PID':>8} {'받는이름':<14} 시그널",
          file=sys.stderr)
    print("-" * 78, file=sys.stderr)

    def handle(_cpu, data, _size):
        e = bpf["events"].event(data)
        s = SIGNAMES.get(e.sig, str(e.sig))
        print(f"{time.strftime('%H:%M:%S'):<10} {e.spid:>8} "
              f"{e.scomm.decode('utf-8','replace'):<14} -> {e.tpid:>8} "
              f"{e.tcomm.decode('utf-8','replace'):<14} SIG{s}")

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
