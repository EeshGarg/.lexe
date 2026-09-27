/* Ignores SIGTERM and SIGINT, sends both to itself, and keeps going. A specimen
 * that cannot be stopped by a polite request. */
#include "oracle.h"
#include <signal.h>
#include <unistd.h>

int main(void) {
    orc_begin("linux-signal-ignored");
    orc_check("IGNORE_SIGTERM", signal(SIGTERM, SIG_IGN) != SIG_ERR);
    orc_check("IGNORE_SIGINT", signal(SIGINT, SIG_IGN) != SIG_ERR);
    raise(SIGTERM);
    raise(SIGINT);
    kill(getpid(), SIGTERM);
    orc_kv("STILL_RUNNING_AFTER_SIGTERM", "yes");
    orc_kv("STILL_RUNNING_AFTER_SIGINT", "yes");
    return orc_end();
}
