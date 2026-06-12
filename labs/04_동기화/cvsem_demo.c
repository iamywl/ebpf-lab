// cvsem_demo.c — 조건변수와 세마포어를 쓰는 생산자-소비자 데모.
//   둘 다 경합/대기 시 커널 futex 로 잠들었다 깨어난다 → futex_contention.py 로 관측된다.
// 빌드:  cc -O2 -o /tmp/cvsem_demo cvsem_demo.c -lpthread
// 관측:  (다른 창)  /tmp/cvsem_demo  실행 후  sudo python3 futex_contention.py --duration 5

#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;   // 조건변수 (OSTEP 30장)
static sem_t sem;                                       // 세마포어 (OSTEP 31장)
static int ready = 0;

void *consumer(void *a) {
    for (int i = 0; i < 20000; i++) {
        pthread_mutex_lock(&m);
        while (!ready) {
            pthread_cond_wait(&cv, &m);   // 조건 충족까지 대기 → 내부적으로 futex(FUTEX_WAIT)
        }
        ready = 0;
        pthread_mutex_unlock(&m);
        sem_wait(&sem);                   // 세마포어 대기 → futex
    }
    return 0;
}

void *producer(void *a) {
    for (int i = 0; i < 20000; i++) {
        pthread_mutex_lock(&m);
        ready = 1;
        pthread_cond_signal(&cv);         // 대기자 깨우기 → futex(FUTEX_WAKE)
        pthread_mutex_unlock(&m);
        sem_post(&sem);                   // 세마포어 올리기 → futex
        usleep(50);
    }
    return 0;
}

int main(void) {
    sem_init(&sem, 0, 0);
    pthread_t c, p;
    pthread_create(&c, NULL, consumer, NULL);
    pthread_create(&p, NULL, producer, NULL);
    pthread_join(p, NULL);
    pthread_join(c, NULL);
    return 0;
}
