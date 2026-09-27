/* A child killed by a signal; the parent reports WTERMSIG. */
#include "oracle.h"
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

int main(void) {
    pid_t p;
    int st = 0;
    orc_begin("linux-proc-wait-signal-status");
    p = fork();
    if (p == 0) { for (;;) pause(); }
    { struct timespec ts; ts.tv_sec = 0; ts.tv_nsec = 100 * 1000 * 1000; nanosleep(&ts, NULL); }
    kill(p, SIGKILL);
    waitpid(p, &st, 0);
    orc_check("SIGNALLED", WIFSIGNALED(st) != 0);
    orc_kv("TERM_SIGNAL", "%d", WIFSIGNALED(st) ? WTERMSIG(st) : -1);
    orc_kv("TERM_SIGNAL_IS_KILL", "%s", (WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL) ? "yes" : "no");
    return orc_end();
}
