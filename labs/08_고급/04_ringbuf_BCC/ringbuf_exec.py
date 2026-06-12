#!/usr/bin/env python3
"""ringbuf_exec.py — BCC 로 ring buffer 를 쓰는 예제 (perf buffer 와 대비).

[배우는 개념] **ring buffer**(BPF_MAP_TYPE_RINGBUF, 커널 5.8+)는 perf buffer 의 후속이다.
   - perf buffer: CPU마다 따로 → 이벤트 순서가 섞일 수 있고 메모리 더 씀
   - ring buffer: 모든 CPU가 공유하는 하나의 버퍼 → **순서 보존**, 메모리 효율적, reserve/submit
   labs 의 다른 도구는 perf buffer 를 쓴다. 이 예제로 ring buffer API 를 비교해 본다.

부착 지점 : tracepoint:syscalls:sys_enter_execve
관련 강의 : 8주차(BCC), 11주차(libbpf·ringbuf)

실행:
    sudo python3 ringbuf_exec.py     # 다른 창에서 ls/date 등 (Ctrl-C 종료)
"""
from __future__ import annotations
import sys
from bcc import BPF

text = r"""
struct event_t { u32 pid; char comm[16]; char fname[128]; };

// perf 가 아니라 ring buffer 출력 맵을 선언 (8 페이지)
BPF_RINGBUF_OUTPUT(rb, 8);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    // ring buffer 에서 공간 예약 → 채우기 → 제출
    struct event_t *e = rb.ringbuf_reserve(sizeof(struct event_t));
    if (!e) { return 0; }
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->fname, sizeof(e->fname), args->filename);
    rb.ringbuf_submit(e, 0);
    return 0;
}
"""

def main() -> int:
    b = BPF(text=text)
    print(f"{'PID':>7} {'COMM':<16} FILE   (BCC ring buffer, Ctrl-C 종료)")

    def handle(_cpu, data, _size):
        e = b["rb"].event(data)
        print(f"{e.pid:>7} {e.comm.decode('utf-8','replace'):<16} "
              f"{e.fname.decode('utf-8','replace')}")

    b["rb"].open_ring_buffer(handle)
    try:
        while True:
            b.ring_buffer_poll(timeout=200)
    except KeyboardInterrupt:
        pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
