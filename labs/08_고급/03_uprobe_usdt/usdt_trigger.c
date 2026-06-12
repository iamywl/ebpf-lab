// usdt_trigger.c — glibc 의 USDT 프로브(libc:cond_broadcast)를 발생시키는 데모.
#include <pthread.h>
#include <unistd.h>
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
int main(void){
    for(;;){ pthread_mutex_lock(&m); pthread_cond_broadcast(&cv); pthread_mutex_unlock(&m); usleep(300000); }
}
