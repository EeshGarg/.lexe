/* A named FIFO in the working directory: child writes, parent reads. Exercises
 * mkfifo and the blocking open semantics of a FIFO, not just an fd pair. */
#include "oracle.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    pid_t p;
    int st = 0;
    orc_begin("linux-io-fifo");
    unlink("wl.fifo");
    orc_check("MKFIFO", mkfifo("wl.fifo", 0600) == 0);
    fflush(stdout);
    p = fork();
    if (p == 0) {
        int fd = open("wl.fifo", O_WRONLY);
        const char *m = "FIFO-PAYLOAD-0123456789";
        if (fd < 0) _exit(81);
        if (write(fd, m, strlen(m)) != (ssize_t)strlen(m)) _exit(82);
        close(fd);
        _exit(0);
    }
    {
        char buf[64];
        ssize_t n;
        int fd = open("wl.fifo", O_RDONLY);
        orc_check("FIFO_OPEN_READ", fd >= 0);
        n = fd >= 0 ? read(fd, buf, sizeof buf - 1) : -1;
        if (n > 0) buf[n] = 0; else buf[0] = 0;
        orc_kv("FIFO_BYTES", "%ld", (long)n);
        orc_kv("FIFO_PAYLOAD", "%s", buf);
        orc_check("FIFO_PAYLOAD_OK", strcmp(buf, "FIFO-PAYLOAD-0123456789") == 0);
        if (fd >= 0) close(fd);
    }
    waitpid(p, &st, 0);
    orc_kv("WRITER_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    unlink("wl.fifo");
    return orc_end();
}
