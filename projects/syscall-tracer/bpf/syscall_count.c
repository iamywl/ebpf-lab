// syscall_count.c — raw_syscalls:sys_enter 트레이스포인트에서
// (프로세스 TGID, 시스템콜 번호)별 호출 횟수를 커널 공간에서 집계한다.
//
// BCC 매크로(TRACEPOINT_PROBE / BPF_HASH / BPF_ARRAY)를 사용하므로
// 표준 libbpf C 가 아니라 BCC 가 런타임에 컴파일하는 소스다.

#include <uapi/linux/ptrace.h>

// 집계 키: 어떤 프로세스(tgid)가 어떤 시스템콜(syscall_id)을 호출했는가
struct key_t {
    u32 tgid;
    u32 syscall_id;
};

// comm(프로세스 이름)을 담는 고정 길이 래퍼 (TASK_COMM_LEN = 16)
struct comm_t {
    char name[16];
};

// (tgid, syscall_id) -> 호출 횟수
BPF_HASH(counts, struct key_t, u64);

// tgid -> 프로세스 이름. 프로세스가 종료된 뒤에도 이름을 보여주기 위해 커널에서 보관
BPF_HASH(comms, u32, struct comm_t);

// 사용자 공간에서 주입하는 필터.
//   target[0] == 0          : 아직 준비 안 됨 → 모두 드롭 (부착 직후 기본값)
//   target[0] == 0xFFFFFFFF  : 전체 추적
//   그 외                    : 해당 tgid 만 추적
// 0 을 "드롭"으로 둔 이유: BCC 는 BPF() 생성 시점에 트레이스포인트를 곧바로 부착하므로,
// 사용자 공간이 필터 값을 쓰기 직전의 짧은 순간에 엉뚱한 프로세스 이벤트가 섞이는 것을 막는다.
BPF_ARRAY(target, u32, 1);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;  // 상위 32비트가 TGID(= 사용자 관점의 PID)

    int zero = 0;
    u32 *want = target.lookup(&zero);
    if (!want || *want == 0) {
        return 0;  // 준비 전(0) 이거나 맵 조회 실패 → 드롭
    }
    if (*want != 0xFFFFFFFF && *want != tgid) {
        return 0;  // 특정 PID 필터에 걸리지 않은 프로세스는 무시 (0xFFFFFFFF = 전체)
    }

    struct key_t key = {};
    key.tgid = tgid;
    key.syscall_id = args->id;  // raw_syscalls:sys_enter 의 시스템콜 번호

    u64 init = 0;
    u64 *val = counts.lookup_or_try_init(&key, &init);
    if (val) {
        (*val)++;
    }

    struct comm_t c = {};
    bpf_get_current_comm(&c.name, sizeof(c.name));
    comms.update(&tgid, &c);

    return 0;
}
