/* socketpair(AF_UNIX): a bidirectional exchange with a forked child. Needs no
 * network stack and no filesystem name, so it is the baseline against which a
 * denied network can be told apart from a denied socket API. */
#include "oracle.h"
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int sv[2];
    pid_t p;
    int st = 0;
    char buf[32];
    ssize_t n;
    orc_begin("linux-socket-unix-pair");
    orc_check("SOCKETPAIR", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    fflush(stdout);
    p = fork();
    if (p == 0) {
        char in[32];
        ssize_t k;
        close(sv[0]);
        k = read(sv[1], in, sizeof in - 1);
        if (k <= 0) _exit(95);
        in[k] = 0;
        if (strcmp(in, "PING") != 0) _exit(96);
        if (write(sv[1], "PONG", 4) != 4) _exit(97);
        _exit(0);
    }
    close(sv[1]);
    orc_check("SENT_PING", write(sv[0], "PING", 4) == 4);
    n = read(sv[0], buf, sizeof buf - 1);
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    orc_kv("REPLY", "%s", buf);
    orc_check("GOT_PONG", strcmp(buf, "PONG") == 0);
    waitpid(p, &st, 0);
    orc_kv("PEER_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    return orc_end();
}
