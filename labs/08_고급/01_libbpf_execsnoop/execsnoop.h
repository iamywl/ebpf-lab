/* execsnoop.h — 커널(BPF)과 사용자 공간이 공유하는 이벤트 구조체. */
#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128

struct event {
    int pid;
    int uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif /* __EXECSNOOP_H */
