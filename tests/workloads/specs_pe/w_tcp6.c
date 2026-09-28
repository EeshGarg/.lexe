/* Winsock over IPv6 loopback: the same shape as w_tcp.c but AF_INET6 and ::1.
 *
 * Worth its own specimen because an IPv6 socket is a different family, a different
 * address structure and, in a translation layer, often a different amount of
 * implementation. A program that works on IPv4 loopback and not on IPv6 loopback
 * is a real and common failure, and the two must be recorded separately.
 *
 * Every failure names the stage and the Winsock error and the specimen still
 * reaches RESULT, as in the IPv4 case: whether a host offers IPv6 loopback is not
 * this program's question. */
/* winsock2.h must precede windows.h, which oracle_win.h includes. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include "oracle_win.h"

static void bail(const char *stage) {
    orc_kv("STAGE_FAILED", "%s", stage);
    orc_werr("FAIL_ERROR", (unsigned long)WSAGetLastError());
    orc_kv("TCP6_LOOPBACK", "unavailable");
}

int main(void) {
    WSADATA wsa;
    SOCKET srv = INVALID_SOCKET, cli = INVALID_SOCKET, acc = INVALID_SOCKET;
    struct sockaddr_in6 a;
    int alen = (int)sizeof a;
    char buf[32];
    int n;
    orc_begin("pe-socket-tcp6-loopback");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        bail("wsastartup");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    orc_kv("WSASTARTUP", "ok");
    srv = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) {
        bail("socket-af-inet6");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    orc_kv("AF_INET6_SOCKET", "ok");
    ZeroMemory(&a, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_addr = in6addr_loopback;
    a.sin6_port = 0;
    if (bind(srv, (struct sockaddr *)&a, sizeof a) != 0
        || listen(srv, 1) != 0
        || getsockname(srv, (struct sockaddr *)&a, &alen) != 0) {
        bail("bind-listen");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    orc_kv("BOUND_LOOPBACK_V6", "ok");
    orc_obs("EPHEMERAL_PORT", "%u", (unsigned)ntohs(a.sin6_port));
    cli = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (cli == INVALID_SOCKET || connect(cli, (struct sockaddr *)&a, sizeof a) != 0) {
        bail("connect");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    acc = accept(srv, NULL, NULL);
    orc_kv("ACCEPT", "%s", acc != INVALID_SOCKET ? "ok" : "fail");
    send(cli, "HELLO-TCP6", 10, 0);
    n = (acc != INVALID_SOCKET) ? recv(acc, buf, sizeof buf - 1, 0) : -1;
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    orc_kv("RECEIVED", "%s", buf);
    orc_kv("TCP6_LOOPBACK", "%s", strcmp(buf, "HELLO-TCP6") == 0 ? "ok" : "incomplete");
    /* The peer of a ::1 connection must itself be ::1, which is the one address
     * assertion here that is a property of the program rather than of the host. */
    {
        struct sockaddr_in6 peer;
        int plen = (int)sizeof peer;
        ZeroMemory(&peer, sizeof peer);
        if (acc != INVALID_SOCKET
            && getpeername(acc, (struct sockaddr *)&peer, &plen) == 0) {
            orc_kv("PEER_FAMILY_IS_INET6", "%s", peer.sin6_family == AF_INET6 ? "yes" : "no");
            orc_kv("PEER_IS_V6_LOOPBACK", "%s",
                   memcmp(&peer.sin6_addr, &in6addr_loopback, sizeof in6addr_loopback) == 0
                   ? "yes" : "no");
        }
    }
    if (acc != INVALID_SOCKET) closesocket(acc);
    closesocket(cli);
    closesocket(srv);
    WSACleanup();
    orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
    return orc_end();
}
