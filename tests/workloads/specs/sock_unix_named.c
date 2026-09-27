/* A named AF_UNIX stream socket in the working directory: bind, listen, a forked
 * client connects, one exchange, then the socket file is removed. Exercises the
 * filesystem namespace as well as the socket API. */
#include "oracle.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int srv, cli, conn;
    struct sockaddr_un a;
    pid_t p;
    int st = 0;
    char buf[32];
    ssize_t n;
    orc_begin("linux-socket-unix-named");
    unlink("wl.sock");
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strcpy(a.sun_path, "wl.sock");
    srv = socket(AF_UNIX, SOCK_STREAM, 0);
    orc_check("SOCKET", srv >= 0);
    orc_check("BIND", bind(srv, (struct sockaddr *)&a, sizeof a) == 0);
    orc_check("LISTEN", listen(srv, 1) == 0);
    fflush(stdout);
    p = fork();
    if (p == 0) {
        cli = socket(AF_UNIX, SOCK_STREAM, 0);
        if (cli < 0) _exit(100);
        if (connect(cli, (struct sockaddr *)&a, sizeof a) != 0) _exit(101);
        if (write(cli, "HELLO-UNIX", 10) != 10) _exit(102);
        close(cli);
        _exit(0);
    }
    conn = accept(srv, NULL, NULL);
    orc_check("ACCEPT", conn >= 0);
    n = conn >= 0 ? read(conn, buf, sizeof buf - 1) : -1;
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    orc_kv("RECEIVED", "%s", buf);
    orc_check("PAYLOAD_OK", strcmp(buf, "HELLO-UNIX") == 0);
    if (conn >= 0) close(conn);
    close(srv);
    waitpid(p, &st, 0);
    orc_kv("CLIENT_EXIT", "%d", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    orc_check("SOCKFILE_REMOVED", unlink("wl.sock") == 0);
    return orc_end();
}
