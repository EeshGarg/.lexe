/* One UDP datagram over loopback, two sockets in one process. Like the TCP
 * specimen, a denial is an observation and not a crash. */
/* winsock2.h must precede windows.h, which oracle_win.h includes. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include "oracle_win.h"

int main(void) {
    WSADATA wsa;
    SOCKET a_fd, b_fd;
    struct sockaddr_in a;
    int alen = sizeof a;
    char buf[32];
    int n;
    orc_begin("pe-socket-udp-loopback");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        orc_kv("STAGE_FAILED", "wsastartup");
        orc_kv("UDP_LOOPBACK", "unavailable");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    a_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    b_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (a_fd == INVALID_SOCKET || b_fd == INVALID_SOCKET) {
        orc_kv("STAGE_FAILED", "socket");
        orc_werr("FAIL_ERROR", (unsigned long)WSAGetLastError());
        orc_kv("UDP_LOOPBACK", "unavailable");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    ZeroMemory(&a, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(a_fd, (struct sockaddr *)&a, sizeof a) != 0
        || getsockname(a_fd, (struct sockaddr *)&a, &alen) != 0) {
        orc_kv("STAGE_FAILED", "bind");
        orc_werr("FAIL_ERROR", (unsigned long)WSAGetLastError());
        orc_kv("UDP_LOOPBACK", "unavailable");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    orc_obs("BOUND_PORT", "%u", (unsigned)ntohs(a.sin_port));
    if (sendto(b_fd, "DGRAM-1", 7, 0, (struct sockaddr *)&a, sizeof a) != 7) {
        orc_kv("STAGE_FAILED", "sendto");
        orc_werr("FAIL_ERROR", (unsigned long)WSAGetLastError());
        orc_kv("UDP_LOOPBACK", "unavailable");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    n = recv(a_fd, buf, sizeof buf - 1, 0);
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    orc_kv("RECEIVED", "%s", buf);
    orc_kv("UDP_LOOPBACK", "%s", strcmp(buf, "DGRAM-1") == 0 ? "ok" : "incomplete");
    closesocket(a_fd); closesocket(b_fd);
    WSACleanup();
    orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
    return orc_end();
}
