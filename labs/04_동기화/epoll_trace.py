#!/usr/bin/env python3
"""epoll_trace.py — 이벤트 기반 동시성(epoll) 관측기.

[배우는 OS 개념] 이벤트 기반 동시성(OSTEP 33장): 스레드/락 대신 한 스레드가 epoll 로
   여러 fd 를 한꺼번에 기다린다. 고성능 서버(nginx·node·redis)의 핵심 패턴.
[eBPF로 무엇을] epoll_ctl(관심 fd 등록)과 epoll 대기(do_epoll_wait)를 프로세스별로 세서,
   "이 프로세스가 이벤트 루프로 도는가"를 드러낸다.

부착 지점 : tracepoint:syscalls:sys_enter_epoll_ctl, kprobe:do_epoll_wait
   (epoll_pwait 트레이스포인트는 인자에 sigset_t 가 있어 BCC 컴파일이 막히므로,
    대기 쪽은 커널 함수 do_epoll_wait 에 kprobe 를 건다.)
관련 강의 : OS 모듈 C3(이벤트 기반 동시성)

실행:
    sudo python3 epoll_trace.py --duration 5
    # systemd·journald 등 데몬이 평소에도 epoll 을 쓰므로 트리거 없이도 잡힌다.
"""
from __future__ import annotations
import argparse, sys, time
from bcc import BPF

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
struct comm_t { char name[16]; };
struct ev_t { u64 ctl; u64 wait; };
BPF_HASH(stats, u32, struct ev_t);
BPF_HASH(names, u32, struct comm_t);

static inline void rec(int is_wait) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct ev_t init = {}, *e = stats.lookup_or_try_init(&pid, &init);
    if (e) { if (is_wait) e->wait += 1; else e->ctl += 1; }
    struct comm_t c = {}; bpf_get_current_comm(&c.name, sizeof(c.name));
    names.update(&pid, &c);
}
TRACEPOINT_PROBE(syscalls, sys_enter_epoll_ctl) { rec(0); return 0; }
int kprobe__do_epoll_wait(struct pt_regs *ctx)  { rec(1); return 0; }
"""

def main() -> int:
    p = argparse.ArgumentParser(description="epoll 이벤트 루프 관측 (eBPF)")
    p.add_argument("--duration", type=float, default=5.0, help="추적 시간(초)")
    p.add_argument("--top", type=int, default=15)
    args = p.parse_args()
    bpf = BPF(text=BPF_TEXT)
    print(f"epoll 관측 {args.duration}초...", file=sys.stderr)
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    names = bpf["names"]; rows = []
    for k, v in bpf["stats"].items():
        comm = names[k].name.decode("utf-8","replace").rstrip("\x00") if k in names else "?"
        rows.append((k.value, comm, v.ctl, v.wait))
    rows.sort(key=lambda r: -(r[2]+r[3]))
    print(f"\n=== 프로세스별 epoll 사용 (최근 {args.duration}초) ===")
    print(f"  {'PID':>7} {'프로세스':<16} {'epoll_ctl':>10} {'epoll_wait':>11}")
    print(f"  {'-'*7} {'-'*16} {'-'*10} {'-'*11}")
    for pid, comm, ctl, wait in rows[:args.top]:
        print(f"  {pid:>7} {comm:<16} {ctl:>10,} {wait:>11,}")
    if not rows:
        print("  (epoll 사용 프로세스 없음)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
