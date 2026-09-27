/* Name resolution: getaddrinfo for localhost (should not need a nameserver) and
 * for a guaranteed-nonexistent name. Reports the resolver verdicts symbolically.
 * Needs /etc/hosts and /etc/nsswitch.conf to answer the first one the fast way,
 * which makes it a good probe of what a confined filesystem view kept. */
#include "oracle.h"
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

static void resolve(const char *label, const char *host) {
    struct addrinfo hints, *res = NULL;
    int rc, n = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, "80", &hints, &res);
    printf("%s_RC_IS_ZERO=%s\n", label, rc == 0 ? "yes" : "no");
    if (rc != 0) {
        printf("%s_GAI=%s\n", label,
               rc == EAI_NONAME ? "EAI_NONAME" :
               rc == EAI_AGAIN ? "EAI_AGAIN" :
               rc == EAI_FAIL ? "EAI_FAIL" :
               rc == EAI_SYSTEM ? "EAI_SYSTEM" : "EAI_OTHER");
        return;
    }
    { struct addrinfo *p; for (p = res; p; p = p->ai_next) n++; }
    printf("%s_ADDRS_NONZERO=%s\n", label, n > 0 ? "yes" : "no");
    freeaddrinfo(res);
}

int main(void) {
    orc_begin("linux-socket-name-resolution");
    resolve("LOCALHOST", "localhost");
    resolve("BOGUS", "no-such-host.invalid");
    orc_kv("ETC_HOSTS_READABLE", "%s", access("/etc/hosts", R_OK) == 0 ? "yes" : "no");
    orc_check("SURVIVED_RESOLUTION", 1);
    return orc_end();
}
