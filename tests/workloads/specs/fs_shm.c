/* POSIX shared memory: shm_open plus mmap shared with a forked child, which
 * writes a pattern the parent then verifies. Requires /dev/shm. */
#include "oracle.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHM_LEN 4096

int main(void) {
    char name[64];
    int fd;
    unsigned char *m;
    pid_t p;
    int st = 0;
    orc_begin("linux-fs-posix-shm");
    snprintf(name, sizeof name, "/lexe-wl-shm-%ld", (long)getpid());
    orc_obs("SHM_NAME", "%s", name);
    fd = shm_open(name, O_CREAT | O_RDWR | O_EXCL, 0600);
    if (fd < 0) {
        orc_kv("SHM_OPEN", "fail");
        orc_kv("SHM_ERRNO", "%s", orc_errno_name(errno));
        orc_check("SHM_AVAILABLE", 0);
        return orc_end();
    }
    orc_kv("SHM_OPEN", "ok");
    orc_check("SHM_SIZED", ftruncate(fd, SHM_LEN) == 0);
    m = (unsigned char *)mmap(NULL, SHM_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    orc_check("SHM_MAPPED", m != MAP_FAILED);
    if (m == MAP_FAILED) { shm_unlink(name); return orc_end(); }
    memset(m, 0, SHM_LEN);
    fflush(stdout);
    p = fork();
    if (p == 0) {
        unsigned i;
        for (i = 0; i < SHM_LEN; i++) m[i] = (unsigned char)((i * 11 + 2) & 0xff);
        _exit(0);
    }
    waitpid(p, &st, 0);
    orc_kv("CHILD_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    orc_kv("SHM_HASH", "%016lx", orc_fnv1a(m, SHM_LEN));
    orc_check("CHILD_WROTE_THROUGH_SHM", m[1] == 13);
    munmap(m, SHM_LEN);
    close(fd);
    orc_check("SHM_UNLINK", shm_unlink(name) == 0);
    orc_check("SHM_AVAILABLE", 1);
    return orc_end();
}
