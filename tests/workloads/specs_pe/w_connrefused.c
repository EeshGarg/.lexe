/* The socket error paths, which a corpus of only-happy-path socket specimens never
 * reaches. Each one has a DISTINCT Winsock error, and a layer that collapsed them
 * into one would be losing information a networked application branches on:
 *
 *   connect to a loopback port with nothing listening -> WSAECONNREFUSED
 *   send on a socket that was never connected         -> WSAENOTCONN
 *   bind the same address twice                       -> WSAEADDRINUSE
 *   an operation on a closed socket                   -> WSAENOTSOCK
 *
 * The dead port is obtained honestly: bind an ephemeral port, learn its number,
 * then close it, so the number is known to have been free and is now unused.
 */
/* winsock2.h must precede windows.h, which oracle_win.h includes. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include "oracle_win.h"

int main(void) {
    WSADATA wsa;
    SOCKET probe, s, second;
    struct sockaddr_in a;
    int alen = (int)sizeof a;
    orc_begin("pe-socket-error-paths");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        orc_kv("STAGE_FAILED", "wsastartup");
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }

    /* A port that was free a moment ago and has no listener now. */
    probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ZeroMemory(&a, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (probe == INVALID_SOCKET
        || bind(probe, (struct sockaddr *)&a, sizeof a) != 0
        || getsockname(probe, (struct sockaddr *)&a, &alen) != 0) {
        orc_kv("STAGE_FAILED", "probe-bind");
        orc_werr("FAIL_ERROR", (unsigned long)WSAGetLastError());
        orc_check("SURVIVED_NETWORK_ATTEMPT", 1);
        return orc_end();
    }
    orc_obs("DEAD_PORT", "%u", (unsigned)ntohs(a.sin_port));
    closesocket(probe);

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    orc_check("SOCKET", s != INVALID_SOCKET);
    WSASetLastError(0);
    orc_kv("CONNECT_TO_DEAD_PORT", "%s",
           connect(s, (struct sockaddr *)&a, sizeof a) == 0 ? "accepted" : "refused");
    orc_werr("CONNECT_TO_DEAD_PORT_ERROR", (unsigned long)WSAGetLastError());
    closesocket(s);

    /* Sending on a socket that was never connected. */
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    WSASetLastError(0);
    orc_kv("SEND_UNCONNECTED", "%d", send(s, "x", 1, 0));
    orc_werr("SEND_UNCONNECTED_ERROR", (unsigned long)WSAGetLastError());

    /* The same address bound twice. */
    {
        struct sockaddr_in b;
        int blen = (int)sizeof b;
        SOCKET held = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ZeroMemory(&b, sizeof b);
        b.sin_family = AF_INET;
        b.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        orc_check("FIRST_BIND", bind(held, (struct sockaddr *)&b, sizeof b) == 0);
        getsockname(held, (struct sockaddr *)&b, &blen);
        second = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        WSASetLastError(0);
        orc_kv("SECOND_BIND_SAME_ADDRESS", "%s",
               bind(second, (struct sockaddr *)&b, sizeof b) == 0 ? "accepted" : "refused");
        orc_werr("SECOND_BIND_ERROR", (unsigned long)WSAGetLastError());
        closesocket(second);
        closesocket(held);
    }

    /* An operation on a handle that is no longer a socket. */
    closesocket(s);
    WSASetLastError(0);
    orc_kv("SEND_ON_CLOSED_SOCKET", "%d", send(s, "x", 1, 0));
    orc_werr("SEND_ON_CLOSED_SOCKET_ERROR", (unsigned long)WSAGetLastError());

    WSACleanup();
    /* And after WSACleanup, Winsock must report that it is no longer initialised. */
    WSASetLastError(0);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    orc_kv("SOCKET_AFTER_WSACLEANUP", "%s", s == INVALID_SOCKET ? "refused" : "accepted");
    orc_werr("SOCKET_AFTER_WSACLEANUP_ERROR", (unsigned long)WSAGetLastError());
    if (s != INVALID_SOCKET) closesocket(s);

    orc_check("SURVIVED_EVERY_ERROR_PATH", 1);
    return orc_end();
}
