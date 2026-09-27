/* Opens many file descriptors at once, reports how many it reached and what
 * stopped it. The declared requirement is 256 usable descriptors. */
#include "oracle.h"
#include <sys/resource.h>
#include <unistd.h>

#define WANT 256

int main(void) {
    int fds[WANT];
    int i, opened = 0, last_errno = 0;
    struct rlimit rl;
    orc_begin("linux-io-many-fds");
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
        orc_obs("RLIMIT_NOFILE_SOFT", "%lu", (unsigned long)rl.rlim_cur);
    for (i = 0; i < WANT; i++) {
        char name[64];
        snprintf(name, sizeof name, "fd_%03d.tmp", i);
        fds[i] = open(name, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fds[i] < 0) { last_errno = errno; break; }
        opened++;
    }
    orc_kv("FDS_REQUESTED", "%d", WANT);
    orc_kv("FDS_OPENED", "%d", opened);
    orc_kv("STOP_ERRNO", "%s", orc_errno_name(last_errno));
    orc_check("REACHED_256", opened == WANT);
    for (i = 0; i < opened; i++) {
        char name[64];
        snprintf(name, sizeof name, "fd_%03d.tmp", i);
        close(fds[i]);
        unlink(name);
    }
    return orc_end();
}
