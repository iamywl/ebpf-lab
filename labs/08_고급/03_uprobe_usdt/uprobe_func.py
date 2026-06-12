#!/usr/bin/env python3
"""uprobe_func.py — 사용자 공간 함수(compute)의 호출과 인자를 추적.

[배우는 개념] uprobe = 커널이 아니라 '사용자 프로그램/라이브러리 함수'에 eBPF 를 붙이는 기법.
   애플리케이션 내부(예: SSL_write, malloc, 우리 compute)를 소스 수정 없이 들여다본다.
[부착] uprobe:<바이너리 경로>:<함수 이름>

실행:
    cc -O2 -o /tmp/target target.c      # 대상 빌드
    /tmp/target &                       # 대상 실행
    sudo python3 uprobe_func.py /tmp/target   # 추적 (Ctrl-C 종료)
"""
from __future__ import annotations
import sys, time
from bcc import BPF

text = r"""
#include <uapi/linux/ptrace.h>
struct data_t { int a; int b; u32 pid; };
BPF_PERF_OUTPUT(events);
int trace_compute(struct pt_regs *ctx) {
    struct data_t d = {};
    d.a = PT_REGS_PARM1(ctx);   // 첫 번째 인자 a
    d.b = PT_REGS_PARM2(ctx);   // 두 번째 인자 b
    d.pid = bpf_get_current_pid_tgid() >> 32;
    events.perf_submit(ctx, &d, sizeof(d));
    return 0;
}
"""

def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/target"
    b = BPF(text=text)
    b.attach_uprobe(name=path, sym="compute", fn_name="trace_compute")
    print(f"uprobe 부착: {path}:compute  (호출마다 인자 출력, Ctrl-C 종료)")
    print(f"{'PID':>7} {'compute(a, b)'}")

    def handle(_c, data, _s):
        e = b["events"].event(data)
        print(f"{e.pid:>7} compute({e.a}, {e.b})")

    b["events"].open_perf_buffer(handle)
    try:
        while True:
            b.perf_buffer_poll(timeout=200)
    except KeyboardInterrupt:
        pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
