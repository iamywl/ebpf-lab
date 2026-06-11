// workload.c — 정해진 횟수만큼 특정 시스템콜을 "직접" 호출하는 검증용 부하 생성기.
//
// 일반 libc 래퍼(open(3) 등)는 내부적으로 추가 시스템콜을 부를 수 있으므로,
// 검증의 기준값(ground truth)을 명확히 하기 위해 syscall(2) 로 커널을 직접 호출한다.
// 마지막에 "내가 의도적으로 호출한 시스템콜과 횟수"를 JSON 한 줄로 출력한다.
// 추적기(eBPF)가 관측한 값이 이 기준값 이상인지로 정확성을 검증한다.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
    long n = (argc > 1) ? atol(argv[1]) : 3000;
    if (n <= 0) {
        n = 3000;
    }

    char buf[1];

    // 1) 인자 없는 단순 시스템콜 — 노이즈가 거의 없어 관측값이 기준값과 거의 일치
    for (long i = 0; i < n; i++) {
        syscall(SYS_getpid);
    }
    for (long i = 0; i < n; i++) {
        syscall(SYS_getuid);
    }
    for (long i = 0; i < n; i++) {
        syscall(SYS_getppid);
    }

    // 2) 파일 입출력 워크플로: openat -> read -> close 를 n회 반복
    //    (arm64 에는 open(2) 가 없고 openat(2) 만 존재한다)
    for (long i = 0; i < n; i++) {
        long fd = syscall(SYS_openat, AT_FDCWD, "/dev/zero", O_RDONLY);
        if (fd >= 0) {
            syscall(SYS_read, fd, buf, (size_t)1);
            syscall(SYS_close, fd);
        }
    }

    // 3) write 워크로드: /dev/null 에 n회 기록
    long nullfd = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_WRONLY);
    for (long i = 0; i < n; i++) {
        syscall(SYS_write, nullfd, ".", (size_t)1);
    }
    syscall(SYS_close, nullfd);

    // 기준값(ground truth) 출력.
    //   - openat 은 위 두 루프(파일 입출력 n회 + /dev/null 1회)로 정확히 n+1 회.
    //   - close 는 파일 입출력 n회 + nullfd 1회로 정확히 n+1 회.
    //   - read/getpid/getuid/getppid/write 는 각각 정확히 n 회.
    // 추적기가 이 값 "이상"을 관측하면 정확히 동작하는 것으로 본다
    // (프로세스 시작 시 동적 링커/libc 가 부르는 소량의 시스템콜이 더해질 수 있음).
    long pid = (long)getpid();
    printf("{\"pid\": %ld, \"ground_truth\": {"
           "\"getpid\": %ld, \"getuid\": %ld, \"getppid\": %ld, "
           "\"openat\": %ld, \"read\": %ld, \"close\": %ld, \"write\": %ld}}\n",
           pid, n, n, n, n + 1, n, n + 1, n);
    fflush(stdout);
    return 0;
}
