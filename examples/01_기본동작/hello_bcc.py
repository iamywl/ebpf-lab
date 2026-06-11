#!/usr/bin/env python3
"""hello_bcc.py — 가장 단순한 eBPF 프로그램 (BCC / Python 버전).

[무엇을 하나]
    bpftrace 버전(hello.bt)과 똑같이 새 프로그램 실행을 감지하지만,
    이번엔 'C 로 쓴 eBPF 코드'를 'Python' 이 커널에 올리는 방식을 보여준다.
    eBPF 의 두 얼굴(커널에서 도는 C + 사용자공간에서 제어하는 Python)을 한 파일에서 본다.

[구조]
    1) bpf_text : 커널 안에서 돌 C 코드 (execve 진입점에 붙음)
    2) BPF(text=...) : Python 이 그 C 를 컴파일해 커널에 로드·부착
    3) trace_print() : 커널이 보낸 메시지를 Python 이 받아 출력

[실행]
    sudo python3 hello_bcc.py        (Ctrl-C 로 종료)
    다른 창에서 ls / date 등을 실행하면 줄이 찍힌다.
"""

from bcc import BPF

# ── 커널 안에서 실행될 eBPF 프로그램 (C) ─────────────────────────────
# 참고: bpf_trace_printk 의 형식 문자열은 ASCII 만 허용한다(한글 ✗).
# 그래서 커널 쪽은 ASCII 신호만 보내고, 한글 출력은 Python 쪽에서 한다.
bpf_text = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    // 이 블록은 누군가 execve 를 호출하는 "커널 안"에서 실행된다.
    bpf_trace_printk("exec\\n");
    return 0;
}
"""

# ── Python(사용자공간): C 를 컴파일해 커널에 로드·부착 ─────────────────
print("eBPF 로드 중... (다른 창에서 명령을 쳐보세요, Ctrl-C 로 종료)")
bpf = BPF(text=bpf_text)

# ── 커널이 신호를 보낼 때마다 Python 이 받아 한글로 출력 ────────────────
# trace_fields() 는 (프로세스이름, pid, cpu, flags, 타임스탬프, 메시지) 를 돌려준다.
try:
    while True:
        task, pid, cpu, flags, ts, msg = bpf.trace_fields()
        print(f"안녕! PID {pid} ({task.decode('utf-8', 'replace')}) 가 새 프로그램을 실행했어요")
except KeyboardInterrupt:
    print("\neBPF 종료. 안녕히 가세요!")
