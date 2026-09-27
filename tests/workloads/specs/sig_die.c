/* Dies from a signal with the default disposition. argv[1] selects term or quit.
 * There is no RESULT line by design: EXPECT_DEATH is the last thing on stdout. */
#include "oracle.h"
#include <signal.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *which = argc > 1 ? argv[1] : "term";
    orc_begin(getenv("FIXTURE_ID") ? getenv("FIXTURE_ID") : "linux-signal-death");
    orc_kv("SIGNAL_SELECTED", "%s", which);
    if (strcmp(which, "quit") == 0) {
        orc_expect_death("sigquit-default");
        raise(SIGQUIT);
    } else {
        orc_expect_death("sigterm-default");
        raise(SIGTERM);
    }
    orc_kv("UNREACHABLE", "yes");
    orc_check("DIED", 0);
    return orc_end();
}
