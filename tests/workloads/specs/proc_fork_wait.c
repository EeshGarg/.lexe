/* fork, child exits 17, parent reports the wait status. */
#include "oracle.h"
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t p, w;
    int st = 0;
    orc_begin("linux-proc-fork-wait");
    p = fork();
    if (p == 0) { _exit(17); }
    orc_check("FORK_OK", p > 0);
    if (p < 0) { orc_kv("FORK_ERRNO", "%s", orc_errno_name(errno)); return orc_end(); }
    w = waitpid(p, &st, 0);
    orc_check("REAPED", w == p);
    orc_check("EXITED_NORMALLY", WIFEXITED(st) != 0);
    orc_kv("CHILD_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    orc_obs("CHILD_PID_DIFFERS", "%s", p != getpid() ? "yes" : "no");
    return orc_end();
}
