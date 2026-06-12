// execsnoop.bpf.c — 커널에서 도는 eBPF 프로그램 (libbpf / CO-RE 방식)
//
// [BCC 와의 차이] BCC 는 대상 머신에서 매번 clang 으로 런타임 컴파일하지만,
// libbpf + CO-RE 는 여기서 미리 컴파일한 오브젝트를 그대로 배포하고,
// 로드 시점에 커널 BTF 로 구조체 오프셋을 '재배치'해 여러 커널에서 동작한다.
//
// 이벤트는 ring buffer(BPF_MAP_TYPE_RINGBUF, 커널 5.8+)로 사용자 공간에 보낸다.

#include "vmlinux.h"               // bpftool 로 생성한 커널 타입 전체
#include <bpf/bpf_helpers.h>
#include "execsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ring buffer 맵 선언 (256KB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// execve 시스템콜 진입 트레이스포인트에 부착
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    // ring buffer 에서 이벤트 1건 공간을 예약
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;  // 버퍼가 가득 차면 조용히 드롭
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // sys_enter_execve 의 첫 인자(args[0]) = 사용자 공간 파일명 포인터
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);  // 사용자 공간으로 전송
    return 0;
}
