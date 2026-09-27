/* POSIX record locking (fcntl F_SETLK): the parent locks bytes 0..127 and the
 * child probes both a conflicting range and a free one. Different semantics from
 * flock, and a different kernel path. */
#include "oracle.h"
#include <sys/wait.h>
#include <unistd.h>

static void region(struct flock *fl, short type, off_t start, off_t len) {
    memset(fl, 0, sizeof *fl);
    fl->l_type = type;
    fl->l_whence = SEEK_SET;
    fl->l_start = start;
    fl->l_len = len;
}

int main(void) {
    int fd;
    pid_t p;
    int st = 0;
    struct flock fl;
    orc_begin("linux-fs-fcntl-record-lock");
    fd = open("record.dat", O_RDWR | O_CREAT, 0600);
    orc_check("OPEN", fd >= 0);
    orc_check("EXTEND", ftruncate(fd, 4096) == 0);
    region(&fl, F_WRLCK, 0, 128);
    orc_check("LOCK_0_127", fcntl(fd, F_SETLK, &fl) == 0);
    fflush(stdout);
    p = fork();
    if (p == 0) {
        int cfd = open("record.dat", O_RDWR);
        struct flock c1, c2;
        int conflict_denied, free_granted;
        if (cfd < 0) _exit(92);
        region(&c1, F_WRLCK, 64, 8);
        conflict_denied = (fcntl(cfd, F_SETLK, &c1) != 0) && (errno == EAGAIN || errno == EACCES);
        region(&c2, F_WRLCK, 2048, 8);
        free_granted = (fcntl(cfd, F_SETLK, &c2) == 0);
        _exit((conflict_denied ? 0 : 1) + (free_granted ? 0 : 2));
    }
    waitpid(p, &st, 0);
    orc_kv("CHILD_STATUS", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    orc_check("CONFLICT_DENIED_AND_FREE_GRANTED", WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(fd);
    return orc_end();
}
