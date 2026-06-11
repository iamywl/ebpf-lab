// tcpconnect.c — 커널 함수 tcp_v4_connect() 진입점에 kprobe 를 걸어
// "어떤 프로세스가 어디로 TCP 연결을 시도했는가" 를 포착한다.
//
// tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len) 의
// 두 번째 인자(목적지 주소)를 읽어 PID/프로세스 이름과 함께 사용자 공간으로 보낸다.
// 연결 "시도" 시점을 잡으므로 성공/실패와 무관하게 의도한 목적지를 알 수 있다.
//
// 참고: <net/sock.h> 는 최신 커널(6.17) 헤더와 BCC clang 사이에서 컴파일 충돌을
// 일으키고, 여기서는 struct sock 을 역참조하지 않으므로 첫 인자를 void* 로 받는다.
//
// 범위: 본 예제는 IPv4(tcp_v4_connect)만 추적한다. IPv6 아웃바운드(tcp_v6_connect,
// 예: ::1 로 해석되는 localhost)는 의도적으로 다루지 않는다 — 학습용으로 단순화한 것.

#include <uapi/linux/ptrace.h>
#include <linux/in.h>

#ifndef AF_INET
#define AF_INET 2
#endif

struct event_t {
    u32 pid;
    u32 daddr;   // 목적지 IPv4 (네트워크 바이트 오더)
    u16 dport;   // 목적지 포트 (네트워크 바이트 오더)
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, void *sk,
                           struct sockaddr *uaddr, int addr_len) {
    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sin->sin_family);
    if (family != AF_INET) {
        return 0;
    }

    struct event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel(&e.daddr, sizeof(e.daddr), &sin->sin_addr.s_addr);
    bpf_probe_read_kernel(&e.dport, sizeof(e.dport), &sin->sin_port);
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
