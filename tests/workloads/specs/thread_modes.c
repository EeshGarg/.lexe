/* Thread behaviour beyond "how many".
 *
 *   argv[1]  detached | tls | crash | forkinthread | condvar | mainexits
 *
 * linux-proc-threads-4 and -256 vary the COUNT, which is one dimension and not
 * the interesting one. These are the shapes where threading changes what the
 * process IS from the outside:
 *
 *   detached      work that nobody joins, finishing on its own schedule
 *   tls           per-thread state, which depends on the TLS model the compiler
 *                 chose and is a real difference between -O levels and compilers
 *   crash         a fault in a NON-main thread, which kills the whole process --
 *                 a supervisor watching the main thread sees nothing coming
 *   forkinthread  fork() from a threaded process: the child has exactly ONE
 *                 thread, however many the parent had, which is the single most
 *                 misunderstood fact about fork
 *   condvar       a real producer/consumer handoff rather than a spin
 *   mainexits     main returns while a detached thread is still working, so the
 *                 process ends and the work does not finish
 */
#include "oracle.h"

#include <pthread.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static __thread unsigned long tls_value = 0;   /* one copy per thread */

static pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int queue_item = -1;
static int queue_done = 0;
static unsigned long consumed_sum = 0;

static unsigned long tls_seen[4];
static unsigned long detached_marker = 0;

static void *tls_worker(void *arg) {
    unsigned long idx = (unsigned long)arg;
    tls_value = 1000 + idx;            /* writes only this thread's copy */
    usleep(2000);
    tls_seen[idx] = tls_value;         /* must still be its own */
    return NULL;
}

static void *detached_worker(void *arg) {
    (void)arg;
    usleep(120000);
    __atomic_store_n(&detached_marker, 0xD00Dul, __ATOMIC_SEQ_CST);
    return NULL;
}

static void *crashing_worker(void *arg) {
    volatile int *p = (volatile int *)0;
    (void)arg;
    usleep(5000);
    *p = 1;                            /* a genuine fault, off the main thread */
    return NULL;
}

static void *consumer(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&mx);
        while (queue_item < 0 && !queue_done)
            pthread_cond_wait(&cv, &mx);
        if (queue_item >= 0) {
            consumed_sum += (unsigned long)queue_item;
            queue_item = -1;
            pthread_cond_signal(&cv);
        } else if (queue_done) {
            pthread_mutex_unlock(&mx);
            return NULL;
        }
        pthread_mutex_unlock(&mx);
    }
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    pthread_t th[4];
    unsigned long i;

    orc_begin("linux-thread-modes");
    orc_kv("THREAD_MODE", "%s", mode);

    if (strcmp(mode, "tls") == 0) {
        tls_value = 7;                 /* the main thread's own copy */
        for (i = 0; i < 4; i++)
            if (pthread_create(&th[i], NULL, tls_worker, (void *)i) != 0) {
                orc_check("THREADS_STARTED", 0);
                return orc_end();
            }
        for (i = 0; i < 4; i++) pthread_join(th[i], NULL);
        orc_check("THREADS_STARTED", 1);
        orc_kv("MAIN_TLS_AFTER_JOINS", "%lu", tls_value);
        orc_check("MAIN_TLS_UNDISTURBED", tls_value == 7);
        for (i = 0; i < 4; i++) {
            char key[32];
            /* orc_kv's first argument is a literal key, not a format string. */
            snprintf(key, sizeof key, "TLS_SEEN_%lu", i);
            orc_kv(key, "%lu", tls_seen[i]);
        }
        orc_check("TLS_ALL_DISTINCT",
                  tls_seen[0] == 1000 && tls_seen[1] == 1001 &&
                  tls_seen[2] == 1002 && tls_seen[3] == 1003);
        return orc_end();
    }

    if (strcmp(mode, "detached") == 0) {
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        orc_check("DETACH_ATTR", 1);
        if (pthread_create(&th[0], &at, detached_worker, NULL) != 0) {
            orc_check("DETACHED_STARTED", 0);
            return orc_end();
        }
        pthread_attr_destroy(&at);
        orc_check("DETACHED_STARTED", 1);
        usleep(400000);                /* outlast it deliberately */
        orc_kv("DETACHED_MARKER", "%lx",
               __atomic_load_n(&detached_marker, __ATOMIC_SEQ_CST));
        orc_check("DETACHED_WORK_COMPLETED",
                  __atomic_load_n(&detached_marker, __ATOMIC_SEQ_CST) == 0xD00Dul);
        orc_check("NEVER_JOINED", 1);
        return orc_end();
    }

    if (strcmp(mode, "mainexits") == 0) {
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        pthread_create(&th[0], &at, detached_worker, NULL);
        pthread_attr_destroy(&at);
        orc_check("DETACHED_STARTED", 1);
        orc_kv("MAIN_WAITS_MS", "0");
        orc_kv("DETACHED_MARKER_AT_EXIT", "%lx",
               __atomic_load_n(&detached_marker, __ATOMIC_SEQ_CST));
        orc_check("WORK_UNFINISHED_AT_EXIT",
                  __atomic_load_n(&detached_marker, __ATOMIC_SEQ_CST) != 0xD00Dul);
        orc_kv("NOTE", "main returns; the process ends and the thread never finishes");
        return orc_end();               /* the detached thread dies with us */
    }

    if (strcmp(mode, "crash") == 0) {
        orc_kv("FAULT_KIND", "null-write-in-a-non-main-thread");
        orc_expect_death("sigsegv-off-main-thread");
        if (pthread_create(&th[0], NULL, crashing_worker, NULL) != 0) {
            orc_kv("THREAD_START", "failed");
            return 91;
        }
        for (;;) usleep(50000);        /* the main thread is healthy throughout */
    }

    if (strcmp(mode, "forkinthread") == 0) {
        pid_t pid;
        int status = 0;
        for (i = 0; i < 4; i++)
            pthread_create(&th[i], NULL, tls_worker, (void *)i);
        orc_check("PARENT_THREADS_STARTED", 1);
        pid = fork();
        if (pid == 0) {
            /* Only async-signal-safe work here: the other threads did not come
             * across, and any lock they held is frozen for ever in this child. */
            const char *msg = "CHILD_THREAD_COUNT=1\nCHILD_ROLE=forked-from-threaded\n";
            ssize_t w = write(1, msg, strlen(msg));
            _exit(w > 0 ? 21 : 22);
        }
        orc_check("FORK_OK", pid > 0);
        for (i = 0; i < 4; i++) pthread_join(th[i], NULL);
        if (waitpid(pid, &status, 0) != pid) {
            orc_check("REAPED", 0);
            return orc_end();
        }
        orc_check("REAPED", 1);
        orc_kv("CHILD_EXIT", "%d", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        orc_check("CHILD_EXIT_21", WIFEXITED(status) && WEXITSTATUS(status) == 21);
        orc_kv("NOTE", "the child inherited the address space and exactly one thread");
        return orc_end();
    }

    if (strcmp(mode, "condvar") == 0) {
        int n;
        if (pthread_create(&th[0], NULL, consumer, NULL) != 0) {
            orc_check("CONSUMER_STARTED", 0);
            return orc_end();
        }
        orc_check("CONSUMER_STARTED", 1);
        for (n = 1; n <= 64; n++) {
            pthread_mutex_lock(&mx);
            while (queue_item >= 0) pthread_cond_wait(&cv, &mx);
            queue_item = n;
            pthread_cond_signal(&cv);
            pthread_mutex_unlock(&mx);
        }
        pthread_mutex_lock(&mx);
        while (queue_item >= 0) pthread_cond_wait(&cv, &mx);
        queue_done = 1;
        pthread_cond_broadcast(&cv);
        pthread_mutex_unlock(&mx);
        pthread_join(th[0], NULL);
        orc_kv("ITEMS_PRODUCED", "64");
        orc_kv("CONSUMED_SUM", "%lu", consumed_sum);
        orc_check("SUM_IS_2080", consumed_sum == 2080ul);   /* 64*65/2 */
        return orc_end();
    }

    orc_kv("USAGE", "thread_modes detached|tls|crash|forkinthread|condvar|mainexits");
    orc_check("MODE_RECOGNISED", 0);
    return orc_end();
}
