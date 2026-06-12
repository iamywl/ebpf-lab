// target.c — uprobe 로 추적할 "사용자 공간 함수"를 가진 데모 프로그램.
#include <stdio.h>
#include <unistd.h>
// noinline: 최적화로 인라인되지 않게 해 uprobe 가 붙을 실제 함수로 남긴다.
__attribute__((noinline)) long compute(int a, int b) { return (long)a * b + 7; }
int main(void) {
    for (int i = 0; ; i++) { volatile long r = compute(i, i + 1); (void)r; usleep(300000); }
    return 0;
}
