/* N pthreads, each doing deterministic work; the sum is order-independent so
 * the output is deterministic regardless of scheduling. argv[1] = thread count. */
#include "oracle.h"
#include <pthread.h>
#include <unistd.h>

static long total = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *arg) {
    long id = (long)arg, acc = 0, i;
    for (i = 0; i < 20000; i++) acc += (id * 31 + i) % 97;
    pthread_mutex_lock(&lock);
    total += acc;
    pthread_mutex_unlock(&lock);
    return NULL;
}

int main(int argc, char **argv) {
    long n = (argc > 1) ? atol(argv[1]) : 4, i;
    pthread_t *t;
    int started = 0;
    orc_begin(getenv("FIXTURE_ID") ? getenv("FIXTURE_ID") : "linux-proc-threads");
    if (n < 1 || n > 4096) { orc_kv("BAD_ARG", "%ld", n); return 2; }
    t = calloc((size_t)n, sizeof *t);
    orc_kv("THREADS_REQUESTED", "%ld", n);
    for (i = 0; i < n; i++)
        if (pthread_create(&t[i], NULL, worker, (void *)i) == 0) started++;
        else break;
    for (i = 0; i < started; i++) pthread_join(t[i], NULL);
    orc_kv("THREADS_STARTED", "%d", started);
    orc_kv("TOTAL", "%ld", total);
    orc_check("ALL_THREADS_STARTED", started == n);
    free(t);
    return orc_end();
}
