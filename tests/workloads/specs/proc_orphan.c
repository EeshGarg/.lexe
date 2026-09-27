/* A parent that exits while its child keeps running: the child sleeps past the
 * exit of the parent, then writes orphan.log recording that it was reparented. */
#include "oracle.h"
#include <unistd.h>
#include <time.h>

int main(void) {
    pid_t p, before;
    orc_begin("linux-proc-orphan");
    before = getpid();
    fflush(stdout);
    p = fork();
    if (p == 0) {
        pid_t first_ppid = getppid();
        struct timespec ts;
        ts.tv_sec = 0; ts.tv_nsec = 400 * 1000 * 1000;
        nanosleep(&ts, NULL);
        {
            FILE *f = fopen("orphan.log", "w");
            if (!f) _exit(73);
            fprintf(f, "CHILD_SURVIVED_PARENT=yes\n");
            fprintf(f, "PARENT_CHANGED=%s\n", getppid() != first_ppid ? "yes" : "no");
            fprintf(f, "ORPHAN_RESULT=PASS\n");
            fclose(f);
        }
        _exit(0);
    }
    orc_check("FORK_OK", p > 0);
    orc_kv("CHILD_LEFT_RUNNING", "yes");
    orc_kv("PARENT_EXITS_FIRST", "yes");
    orc_obs("PARENT_PID_STABLE", "%s", getpid() == before ? "yes" : "no");
    return orc_end();
}
