/* Reports its own process-group and session relationships and whether it can
 * create a new session. Raw ids are observations; the relationships between
 * them are deterministic. */
#include "oracle.h"
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    pid_t pid, pgid, sid, c;
    int st = 0;
    orc_begin("linux-proc-session");
    pid = getpid(); pgid = getpgid(0); sid = getsid(0);
    orc_obs("PID", "%ld", (long)pid);
    orc_obs("PGID", "%ld", (long)pgid);
    orc_obs("SID", "%ld", (long)sid);
    orc_obs("IS_GROUP_LEADER", "%s", pid == pgid ? "yes" : "no");
    orc_obs("IS_SESSION_LEADER", "%s", pid == sid ? "yes" : "no");
    c = fork();
    if (c == 0) {
        int ok = (setsid() != (pid_t)-1);
        _exit(ok ? 0 : 1);
    }
    waitpid(c, &st, 0);
    orc_check("CHILD_SETSID_OK", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    return orc_end();
}
