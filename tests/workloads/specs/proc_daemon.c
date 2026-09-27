/* The classic double fork plus setsid. The first parent exits 0 immediately; the
 * daemon writes daemon.log and exits. The daemon reports into the file, not the
 * inherited stdout, because a real daemon has no stdout.
 *
 * The session facts are worth stating precisely, because the first version of
 * this specimen declared them wrongly and its own baseline caught it: after the
 * SECOND fork the daemon is NOT the session leader. The intermediate process was
 * the leader, and it exited. That is the entire reason for the second fork -- a
 * non-leader can never acquire a controlling terminal. What must be true is that
 * the session CHANGED from the one the launcher was in. */
#include "oracle.h"
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

int main(void) {
    pid_t p;
    pid_t launch_sid;
    orc_begin("linux-proc-daemon-double-fork");
    launch_sid = getsid(0);
    orc_obs("LAUNCH_SID", "%ld", (long)launch_sid);
    orc_kv("STAGE", "parent");
    fflush(stdout);
    p = fork();
    if (p < 0) {
        orc_kv("FORK_ERRNO", "%s", orc_errno_name(errno));
        orc_check("FORK_OK", 0);
        return orc_end();
    }
    if (p > 0) {
        orc_kv("PARENT_EXIT", "0");
        orc_check("FORK_OK", 1);
        return orc_end();
    }
    if (setsid() < 0) _exit(70);
    p = fork();
    if (p < 0) _exit(71);
    if (p > 0) _exit(0);
    {
        FILE *f;
        struct timespec ts;
        ts.tv_sec = 0; ts.tv_nsec = 150 * 1000 * 1000;
        nanosleep(&ts, NULL);
        f = fopen("daemon.log", "w");
        if (!f) _exit(72);
        fprintf(f, "DAEMON_STARTED=yes\n");
        fprintf(f, "DAEMON_SID_CHANGED=%s\n", getsid(0) != launch_sid ? "yes" : "no");
        fprintf(f, "DAEMON_IS_SESSION_LEADER=%s\n", getsid(0) == getpid() ? "yes" : "no");
        fprintf(f, "DAEMON_HAS_PARENT=%s\n", getppid() != 0 ? "yes" : "no");
        fprintf(f, "DAEMON_RESULT=PASS\n");
        fclose(f);
        _exit(0);
    }
}
