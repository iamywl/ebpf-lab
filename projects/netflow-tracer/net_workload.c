// net_workload.c — 정해진 횟수만큼 지정한 목적지로 TCP 연결을 시도하는 검증용 부하 생성기.
// 사용법:  net_workload <port> [count]   (목적지는 127.0.0.1 고정)
// 마지막에 "내 PID / 목적지 포트 / 시도 횟수" 를 JSON 한 줄로 출력한다.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port> [count]\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);
    long n = (argc > 2) ? atol(argv[2]) : 50;
    if (n <= 0) {
        n = 50;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    long ok = 0;
    for (long i = 0; i < n; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            ok++;
        }
        close(fd);
    }

    printf("{\"pid\": %ld, \"dest\": \"127.0.0.1\", \"port\": %d, "
           "\"attempts\": %ld, \"connected\": %ld}\n",
           (long)getpid(), port, n, ok);
    fflush(stdout);
    return 0;
}
