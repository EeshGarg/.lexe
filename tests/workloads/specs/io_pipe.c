/* Two anonymous pipes for a request/response exchange with a forked child:
 * parent sends 1024 bytes, child returns their running checksum. */
#include "oracle.h"
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int down[2], up[2];
    pid_t p;
    int st = 0;
    unsigned char msg[1024];
    unsigned long i;
    orc_begin("linux-io-pipe-roundtrip");
    for (i = 0; i < sizeof msg; i++) msg[i] = (unsigned char)(i * 7 + 3);
    orc_check("PIPES_CREATED", pipe(down) == 0 && pipe(up) == 0);
    fflush(stdout);
    p = fork();
    if (p == 0) {
        unsigned char buf[1024];
        unsigned long h;
        size_t got = 0;
        ssize_t n;
        close(down[1]); close(up[0]);
        while (got < sizeof buf && (n = read(down[0], buf + got, sizeof buf - got)) > 0)
            got += (size_t)n;
        h = orc_fnv1a(buf, got);
        if (write(up[1], &h, sizeof h) != (ssize_t)sizeof h) _exit(80);
        _exit(0);
    }
    close(down[0]); close(up[1]);
    orc_check("WROTE_ALL", write(down[1], msg, sizeof msg) == (ssize_t)sizeof msg);
    close(down[1]);
    {
        unsigned long got_hash = 0;
        ssize_t n = read(up[0], &got_hash, sizeof got_hash);
        orc_check("READ_REPLY", n == (ssize_t)sizeof got_hash);
        orc_kv("EXPECTED_HASH", "%016lx", orc_fnv1a(msg, sizeof msg));
        orc_kv("CHILD_HASH", "%016lx", got_hash);
        orc_check("HASH_MATCHES", got_hash == orc_fnv1a(msg, sizeof msg));
    }
    waitpid(p, &st, 0);
    orc_kv("CHILD_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    return orc_end();
}
