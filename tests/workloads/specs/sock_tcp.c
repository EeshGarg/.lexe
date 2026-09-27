/* TCP over loopback: bind 127.0.0.1 on an ephemeral port, connect from a forked
 * child, exchange one message.
 *
 * This specimen does NOT require the network to work. Every failure mode is
 * reported with the syscall that failed and its errno, and the specimen still
 * reaches RESULT. Whether a denied loopback is correct is not its question --
 * its job is to say exactly what it observed. */
#include "oracle.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int srv, conn;
    struct sockaddr_in a;
    socklen_t alen = sizeof a;
    pid_t p;
    int st = 0;
    char buf[32];
    ssize_t n;
    unsigned short port;
    orc_begin("linux-socket-tcp-loopback");
    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        orc_kv("STAGE_FAILED", "socket");
        orc_kv("FAIL_ERRNO", "%s", orc_errno_name(errno));
        orc_kv("TCP_LOOPBACK", "unavailable");
        return orc_end();
    }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(srv, (struct sockaddr *)&a, sizeof a) != 0) {
        orc_kv("STAGE_FAILED", "bind");
        orc_kv("FAIL_ERRNO", "%s", orc_errno_name(errno));
        orc_kv("TCP_LOOPBACK", "unavailable");
        close(srv);
        return orc_end();
    }
    if (listen(srv, 1) != 0 || getsockname(srv, (struct sockaddr *)&a, &alen) != 0) {
        orc_kv("STAGE_FAILED", "listen");
        orc_kv("FAIL_ERRNO", "%s", orc_errno_name(errno));
        orc_kv("TCP_LOOPBACK", "unavailable");
        close(srv);
        return orc_end();
    }
    port = ntohs(a.sin_port);
    orc_obs("EPHEMERAL_PORT", "%u", (unsigned)port);
    fflush(stdout);
    p = fork();
    if (p == 0) {
        int cli = socket(AF_INET, SOCK_STREAM, 0);
        if (cli < 0) _exit(110);
        if (connect(cli, (struct sockaddr *)&a, sizeof a) != 0) _exit(111);
        if (write(cli, "HELLO-TCP", 9) != 9) _exit(112);
        close(cli);
        _exit(0);
    }
    conn = accept(srv, NULL, NULL);
    n = conn >= 0 ? read(conn, buf, sizeof buf - 1) : -1;
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    if (conn >= 0) close(conn);
    close(srv);
    waitpid(p, &st, 0);
    orc_kv("CLIENT_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    orc_kv("RECEIVED", "%s", buf);
    orc_kv("TCP_LOOPBACK", "%s", strcmp(buf, "HELLO-TCP") == 0 ? "ok" : "incomplete");
    orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
    return orc_end();
}
