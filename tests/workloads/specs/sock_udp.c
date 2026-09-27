/* UDP over loopback in a single process: two sockets, one datagram each way.
 * Like the TCP specimen, a denial is an observation and not a crash. */
#include "oracle.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int a_fd, b_fd;
    struct sockaddr_in a, b;
    socklen_t alen = sizeof a;
    char buf[32];
    ssize_t n;
    orc_begin("linux-socket-udp-loopback");
    a_fd = socket(AF_INET, SOCK_DGRAM, 0);
    b_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (a_fd < 0 || b_fd < 0) {
        orc_kv("STAGE_FAILED", "socket");
        orc_kv("FAIL_ERRNO", "%s", orc_errno_name(errno));
        orc_kv("UDP_LOOPBACK", "unavailable");
        return orc_end();
    }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(a_fd, (struct sockaddr *)&a, sizeof a) != 0
        || getsockname(a_fd, (struct sockaddr *)&a, &alen) != 0) {
        orc_kv("STAGE_FAILED", "bind");
        orc_kv("FAIL_ERRNO", "%s", orc_errno_name(errno));
        orc_kv("UDP_LOOPBACK", "unavailable");
        return orc_end();
    }
    orc_obs("BOUND_PORT", "%u", (unsigned)ntohs(a.sin_port));
    memset(&b, 0, sizeof b);
    b.sin_family = AF_INET;
    b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (sendto(b_fd, "DGRAM-1", 7, 0, (struct sockaddr *)&a, sizeof a) != 7) {
        orc_kv("STAGE_FAILED", "sendto");
        orc_kv("FAIL_ERRNO", "%s", orc_errno_name(errno));
        orc_kv("UDP_LOOPBACK", "unavailable");
        return orc_end();
    }
    n = recv(a_fd, buf, sizeof buf - 1, 0);
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    orc_kv("RECEIVED", "%s", buf);
    orc_kv("UDP_LOOPBACK", "%s", strcmp(buf, "DGRAM-1") == 0 ? "ok" : "incomplete");
    close(a_fd); close(b_fd);
    orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
    return orc_end();
}
