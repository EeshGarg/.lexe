/* Name resolution through Winsock: localhost, which should need no nameserver,
 * and a guaranteed-nonexistent name. Reports both verdicts symbolically. */
/* winsock2.h must precede windows.h, which oracle_win.h includes. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include "oracle_win.h"

static void resolve(const char *label, const char *host) {
    struct addrinfo hints, *res = NULL;
    int rc, n = 0;
    char k[128];
    ZeroMemory(&hints, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, "80", &hints, &res);
    snprintf(k, sizeof k, "%s_RC_IS_ZERO", label);
    orc_kv(k, "%s", rc == 0 ? "yes" : "no");
    if (rc != 0) {
        /* WHICH failure the resolver reports for a name that does not exist is
         * NOT deterministic: if the upstream DNS answers, it is
         * WSAHOST_NOT_FOUND, and if the query times out it is WSATRY_AGAIN --
         * observed here after a 15-second wait on one repeat out of three. So the
         * code is an observation. That the lookup FAILED is the deterministic
         * part, and that stays a checked key. */
        snprintf(k, sizeof k, "%s_ERROR", label);
        orc_obs(k, "%s", rc == WSAHOST_NOT_FOUND ? "WSAHOST_NOT_FOUND" :
                        rc == WSATRY_AGAIN ? "WSATRY_AGAIN" :
                        rc == WSANO_RECOVERY ? "WSANO_RECOVERY" : "OTHER");
        return;
    }
    { struct addrinfo *p; for (p = res; p; p = p->ai_next) n++; }
    snprintf(k, sizeof k, "%s_ADDRS_NONZERO", label);
    orc_kv(k, "%s", n > 0 ? "yes" : "no");
    freeaddrinfo(res);
}

int main(void) {
    WSADATA wsa;
    orc_begin("pe-socket-name-resolution");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        orc_kv("STAGE_FAILED", "wsastartup");
        orc_check("SURVIVED_RESOLUTION", 1);
        return orc_end();
    }
    resolve("LOCALHOST", "localhost");
    resolve("BOGUS", "no-such-host.invalid");
    WSACleanup();
    orc_check("SURVIVED_RESOLUTION", 1);
    return orc_end();
}
