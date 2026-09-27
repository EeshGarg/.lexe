/* BSD advisory locking: the parent takes an exclusive flock and a forked child
 * attempts a non-blocking one, which must fail with EWOULDBLOCK. */
#include "oracle.h"
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int fd;
    pid_t p;
    int st = 0;
    orc_begin("linux-fs-flock-contention");
    fd = open("lockfile", O_RDWR | O_CREAT, 0600);
    orc_check("OPEN_LOCKFILE", fd >= 0);
    orc_check("FLOCK_EX", flock(fd, LOCK_EX) == 0);
    fflush(stdout);
    p = fork();
    if (p == 0) {
        int cfd = open("lockfile", O_RDWR);
        int rc;
        if (cfd < 0) _exit(90);
        rc = flock(cfd, LOCK_EX | LOCK_NB);
        if (rc == 0) _exit(1);
        _exit(errno == EWOULDBLOCK ? 0 : 91);
    }
    waitpid(p, &st, 0);
    orc_kv("CHILD_STATUS", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    orc_check("CHILD_BLOCKED_AS_EXPECTED", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    orc_check("UNLOCK", flock(fd, LOCK_UN) == 0);
    close(fd);
    return orc_end();
}
