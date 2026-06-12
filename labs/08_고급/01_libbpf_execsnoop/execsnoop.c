// execsnoop.c — 사용자 공간 로더 (libbpf)
//
// 스켈레톤(execsnoop.skel.h)으로 BPF 오브젝트를 열고/로드하고/부착한 뒤,
// ring buffer 를 폴링하며 커널이 보낸 이벤트를 출력한다.

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "execsnoop.h"
#include "execsnoop.skel.h"

static volatile sig_atomic_t exiting = 0;
static void on_signal(int sig) { exiting = 1; }

// libbpf 내부 디버그 로그는 숨기고, 경고 이상만 출력
static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) {
        return 0;
    }
    return vfprintf(stderr, fmt, args);
}

// ring buffer 콜백: 이벤트 1건이 올 때마다 호출
static int handle_event(void *ctx, void *data, size_t size)
{
    const struct event *e = data;
    printf("%-8d %-8d %-16s %s\n", e->pid, e->uid, e->comm, e->filename);
    return 0;
}

int main(void)
{
    libbpf_set_print(libbpf_print);

    // 1) 스켈레톤으로 열고 + 로드(검증기·JIT 통과) + 부착
    struct execsnoop_bpf *skel = execsnoop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "BPF 오브젝트 로드 실패\n");
        return 1;
    }
    if (execsnoop_bpf__attach(skel)) {
        fprintf(stderr, "부착 실패\n");
        execsnoop_bpf__destroy(skel);
        return 1;
    }

    // 2) ring buffer 생성
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
                                              handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring buffer 생성 실패\n");
        execsnoop_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    printf("%-8s %-8s %-16s %s\n", "PID", "UID", "COMM", "FILENAME");
    printf("(libbpf + CO-RE + ring buffer. 다른 창에서 ls/date 등을 실행하세요. Ctrl-C 종료)\n");

    // 3) 폴링 루프
    while (!exiting) {
        int err = ring_buffer__poll(rb, 200 /*ms*/);
        if (err < 0 && err != -4 /*EINTR*/) {
            break;
        }
    }

    ring_buffer__free(rb);
    execsnoop_bpf__destroy(skel);
    printf("\n종료.\n");
    return 0;
}
