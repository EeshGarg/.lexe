/* A compound workload shaped like a small service: a named AF_UNIX listener, a
 * fixed pool of four worker threads, a forked client that issues twelve
 * requests, POSIX shared memory for the shared counter, a SIGTERM handler for
 * shutdown, and a persistent log file. It exercises threads, sockets, signals,
 * shared memory, fork and files in one process tree, and its final report is
 * still a deterministic set of counts. */
#include "oracle.h"
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKERS 4
#define REQUESTS 12

static int listen_fd = -1;
static volatile sig_atomic_t stop_requested = 0;
static unsigned long *counter;
static pthread_mutex_t logmu = PTHREAD_MUTEX_INITIALIZER;
static FILE *logf;

static void on_term(int s) { (void)s; stop_requested = 1; }

static void *worker(void *arg) {
    long id = (long)arg;
    for (;;) {
        int c = accept(listen_fd, NULL, NULL);
        char buf[64];
        ssize_t n;
        if (c < 0) return NULL;
        n = read(c, buf, sizeof buf - 1);
        if (n > 0) {
            buf[n] = 0;
            pthread_mutex_lock(&logmu);
            (*counter)++;
            if (logf) fprintf(logf, "served %s\n", buf);
            pthread_mutex_unlock(&logmu);
            { ssize_t ack = write(c, "ACK", 3); (void)ack; }
        }
        close(c);
        if (*counter >= REQUESTS) { (void)id; return NULL; }
    }
}

int main(void) {
    struct sockaddr_un a;
    pthread_t th[WORKERS];
    pid_t client;
    int st = 0, i, shm;
    struct sigaction sa;
    orc_begin("linux-compound-unix-service");

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    sigemptyset(&sa.sa_mask);
    orc_check("SIGTERM_HANDLER", sigaction(SIGTERM, &sa, NULL) == 0);

    shm = shm_open("/lexe-wl-service", O_CREAT | O_RDWR, 0600);
    orc_check("SHM_OPEN", shm >= 0);
    if (shm >= 0) {
        orc_check("SHM_SIZED", ftruncate(shm, sizeof(unsigned long)) == 0);
        counter = (unsigned long *)mmap(NULL, sizeof(unsigned long),
                                        PROT_READ | PROT_WRITE, MAP_SHARED, shm, 0);
    }
    if (!counter || counter == (unsigned long *)MAP_FAILED) {
        counter = (unsigned long *)calloc(1, sizeof(unsigned long));
        orc_kv("SHM_FALLBACK", "heap");
    } else {
        *counter = 0;
        orc_kv("SHM_FALLBACK", "none");
    }

    logf = fopen("service.log", "w");
    orc_check("LOG_OPEN", logf != NULL);

    unlink("service.sock");
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strcpy(a.sun_path, "service.sock");
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    orc_check("LISTEN_SOCKET", listen_fd >= 0);
    orc_check("BIND", bind(listen_fd, (struct sockaddr *)&a, sizeof a) == 0);
    orc_check("LISTEN", listen(listen_fd, 8) == 0);

    for (i = 0; i < WORKERS; i++)
        orc_check("WORKER_STARTED", pthread_create(&th[i], NULL, worker, (void *)(long)i) == 0);

    fflush(stdout);
    if (logf) fflush(logf);
    client = fork();
    if (client == 0) {
        int k, ok = 0;
        for (k = 0; k < REQUESTS; k++) {
            int c = socket(AF_UNIX, SOCK_STREAM, 0);
            char req[32], rep[16];
            ssize_t n;
            if (c < 0) break;
            if (connect(c, (struct sockaddr *)&a, sizeof a) != 0) { close(c); break; }
            snprintf(req, sizeof req, "req-%02d", k);
            if (write(c, req, strlen(req)) != (ssize_t)strlen(req)) { close(c); break; }
            n = read(c, rep, sizeof rep - 1);
            if (n == 3) ok++;
            close(c);
        }
        _exit(ok == REQUESTS ? 0 : 1);
    }

    waitpid(client, &st, 0);
    /* Unblock any worker still parked in accept(). */
    for (i = 0; i < WORKERS; i++) {
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        if (c >= 0) { (void)connect(c, (struct sockaddr *)&a, sizeof a); close(c); }
    }
    shutdown(listen_fd, SHUT_RDWR);
    close(listen_fd);
    for (i = 0; i < WORKERS; i++) pthread_join(th[i], NULL);

    raise(SIGTERM);

    orc_kv("CLIENT_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    orc_kv("REQUESTS_EXPECTED", "%d", REQUESTS);
    orc_kv("REQUESTS_SERVED_AT_LEAST", "%s", *counter >= REQUESTS ? "yes" : "no");
    orc_obs("REQUESTS_SERVED", "%lu", *counter);
    orc_kv("SHUTDOWN_SIGNAL_SEEN", "%s", stop_requested ? "yes" : "no");
    if (logf) fclose(logf);
    orc_check("LOG_PRESENT", access("service.log", F_OK) == 0);
    orc_check("CLIENT_ALL_ACKED", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    orc_check("SIGTERM_DELIVERED_TO_HANDLER", stop_requested == 1);
    unlink("service.sock");
    shm_unlink("/lexe-wl-service");
    return orc_end();
}
