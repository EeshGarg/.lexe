/* SIGCHLD handling: a handler counts child exits while the parent reaps in the
 * handler, which is the pattern that breaks naive wait loops. */
#include "oracle.h"
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

static volatile sig_atomic_t reaped = 0;

static void on_chld(int s) {
    int st;
    (void)s;
    while (waitpid(-1, &st, WNOHANG) > 0) reaped++;
}

int main(void) {
    struct sigaction sa;
    int i;
    orc_begin("linux-signal-sigchld-reaper");
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_chld;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);
    orc_check("SIGACTION_CHLD", sigaction(SIGCHLD, &sa, NULL) == 0);
    for (i = 0; i < 5; i++) {
        pid_t p = fork();
        if (p == 0) _exit(i);
    }
    {
        int waited = 0;
        while (reaped < 5 && waited < 5000) {
            struct timespec ts; ts.tv_sec = 0; ts.tv_nsec = 5 * 1000 * 1000;
            nanosleep(&ts, NULL);
            waited += 5;
        }
    }
    orc_kv("CHILDREN_FORKED", "5");
    orc_kv("CHILDREN_REAPED_IN_HANDLER", "%d", (int)reaped);
    orc_check("ALL_REAPED", reaped == 5);
    return orc_end();
}
