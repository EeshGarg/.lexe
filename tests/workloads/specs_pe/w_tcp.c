/* Winsock TCP over loopback: WSAStartup, bind 127.0.0.1 on an ephemeral port,
 * connect from a second socket in the same process, exchange one message.
 *
 * This specimen does not require the network to work. Every failure is reported
 * with the stage that failed and the Winsock error name, and it still reaches
 * RESULT. Whether a denied loopback is correct is not its question. */
/* winsock2.h must precede windows.h, which oracle_win.h includes. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include "oracle_win.h"

int main(void) {
    WSADATA wsa;
    SOCKET srv = INVALID_SOCKET, cli = INVALID_SOCKET, acc = INVALID_SOCKET;
    struct sockaddr_in a;
    int alen = sizeof a;
    char buf[32];
    int n;
    orc_begin("pe-socket-tcp-loopback");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        orc_kv("STAGE_FAILED", "wsastartup");
        orc_kv("TCP_LOOPBACK", "unavailable");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    orc_kv("WSASTARTUP", "ok");
    srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) {
        orc_kv("STAGE_FAILED", "socket");
        orc_werr("FAIL_ERROR", (unsigned long)WSAGetLastError());
        orc_kv("TCP_LOOPBACK", "unavailable");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    ZeroMemory(&a, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(srv, (struct sockaddr *)&a, sizeof a) != 0
        || listen(srv, 1) != 0
        || getsockname(srv, (struct sockaddr *)&a, &alen) != 0) {
        orc_kv("STAGE_FAILED", "bind-listen");
        orc_werr("FAIL_ERROR", (unsigned long)WSAGetLastError());
        orc_kv("TCP_LOOPBACK", "unavailable");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    orc_obs("EPHEMERAL_PORT", "%u", (unsigned)ntohs(a.sin_port));
    cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (cli == INVALID_SOCKET || connect(cli, (struct sockaddr *)&a, sizeof a) != 0) {
        orc_kv("STAGE_FAILED", "connect");
        orc_werr("FAIL_ERROR", (unsigned long)WSAGetLastError());
        orc_kv("TCP_LOOPBACK", "unavailable");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    acc = accept(srv, NULL, NULL);
    orc_kv("ACCEPT", "%s", acc != INVALID_SOCKET ? "ok" : "fail");
    send(cli, "HELLO-TCP", 9, 0);
    n = (acc != INVALID_SOCKET) ? recv(acc, buf, sizeof buf - 1, 0) : -1;
    if (n > 0) buf[n] = 0; else buf[0] = 0;
    orc_kv("RECEIVED", "%s", buf);
    orc_kv("TCP_LOOPBACK", "%s", strcmp(buf, "HELLO-TCP") == 0 ? "ok" : "incomplete");
    if (acc != INVALID_SOCKET) closesocket(acc);
    closesocket(cli);
    closesocket(srv);
    WSACleanup();
    orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
    return orc_end();
}
