/* Non-blocking sockets and select(): the readiness model, rather than the
 * blocking one every other socket specimen here uses.
 *
 * Three distinct answers from select, each arranged so it is the only possible
 * one:
 *   an idle connected socket        -> select for READ returns 0 (timeout)
 *   a socket with data waiting      -> select for READ returns 1
 *   a freshly connecting socket     -> select for WRITE returns 1 once connected
 *
 * Whether a non-blocking connect over loopback returns WSAEWOULDBLOCK or
 * completes immediately is a PLATFORM choice, not a program one -- Windows always
 * reports WSAEWOULDBLOCK, a Unix kernel behind a translation layer may not -- so
 * that one key is declared as either of two legitimate outcomes and the rest
 * stays exact.
 */
/* winsock2.h must precede windows.h, which oracle_win.h includes. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include "oracle_win.h"

static int sel(SOCKET s, int want_write, long ms) {
    fd_set set;
    struct timeval tv;
    FD_ZERO(&set);
    FD_SET(s, &set);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return want_write ? select(0, NULL, &set, NULL, &tv)
                      : select(0, &set, NULL, NULL, &tv);
}

int main(void) {
    WSADATA wsa;
    SOCKET srv = INVALID_SOCKET, cli = INVALID_SOCKET, acc = INVALID_SOCKET;
    struct sockaddr_in a;
    int alen = (int)sizeof a;
    u_long nonblock = 1;
    char buf[32];
    int rc, n;
    orc_begin("pe-socket-select-nonblocking");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        orc_kv("STAGE_FAILED", "wsastartup");
        orc_kv("SELECT_MODEL", "unavailable");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(&a, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (srv == INVALID_SOCKET
        || bind(srv, (struct sockaddr *)&a, sizeof a) != 0
        || listen(srv, 1) != 0
        || getsockname(srv, (struct sockaddr *)&a, &alen) != 0) {
        orc_kv("STAGE_FAILED", "bind-listen");
        orc_werr("FAIL_ERROR", (unsigned long)WSAGetLastError());
        orc_kv("SELECT_MODEL", "unavailable");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    orc_obs("EPHEMERAL_PORT", "%u", (unsigned)ntohs(a.sin_port));

    cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    orc_check("CLIENT_SOCKET", cli != INVALID_SOCKET);
    orc_check("SET_NON_BLOCKING", ioctlsocket(cli, FIONBIO, &nonblock) == 0);

    WSASetLastError(0);
    rc = connect(cli, (struct sockaddr *)&a, sizeof a);
    if (rc == 0) {
        orc_kv("NONBLOCKING_CONNECT", "completed-immediately");
    } else {
        orc_kv("NONBLOCKING_CONNECT", "%s",
               WSAGetLastError() == WSAEWOULDBLOCK ? "would-block" : "failed");
        orc_werr("NONBLOCKING_CONNECT_ERROR", (unsigned long)WSAGetLastError());
    }
    orc_kv("SELECT_WRITABLE_AFTER_CONNECT", "%d", sel(cli, 1, 5000));
    orc_check("CONNECT_COMPLETED_VIA_SELECT", sel(cli, 1, 5000) == 1);

    acc = accept(srv, NULL, NULL);
    orc_check("ACCEPTED", acc != INVALID_SOCKET);
    if (acc == INVALID_SOCKET) { orc_werr("ACCEPT_ERROR", (unsigned long)WSAGetLastError());
                                 return orc_end(); }
    orc_check("SET_ACCEPTED_NON_BLOCKING", ioctlsocket(acc, FIONBIO, &nonblock) == 0);

    /* Nothing has been sent, so a read-select on the accepted socket must
     * time out. This is the assertion that a select which always claims
     * readiness would fail. */
    orc_kv("SELECT_READ_WHEN_IDLE", "%d", sel(acc, 0, 200));
    orc_check("IDLE_SOCKET_NOT_READABLE", sel(acc, 0, 200) == 0);

    /* A non-blocking recv on an idle socket has its own distinct answer. */
    WSASetLastError(0);
    n = recv(acc, buf, sizeof buf - 1, 0);
    orc_kv("NONBLOCKING_RECV_WHEN_IDLE", "%d", n);
    orc_werr("NONBLOCKING_RECV_ERROR", (unsigned long)WSAGetLastError());

    send(cli, "SELECT-PING", 11, 0);
    orc_kv("SELECT_READ_WITH_DATA", "%d", sel(acc, 0, 5000));
    n = recv(acc, buf, sizeof buf - 1, 0);
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    orc_kv("RECEIVED", "%s", buf);
    orc_check("READY_SOCKET_DELIVERED_THE_DATA", strcmp(buf, "SELECT-PING") == 0);
    orc_kv("SELECT_MODEL", "ok");

    closesocket(acc); closesocket(cli); closesocket(srv);
    WSACleanup();
    orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
    return orc_end();
}
