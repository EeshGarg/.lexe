/* Reports whether each standard descriptor is a terminal. Under the runner all
 * three are pipes, so the deterministic expectation is three noes; on a real
 * terminal it would differ, which is why TERM is only an observation. */
#include "oracle.h"
#include <unistd.h>

int main(void) {
    orc_begin("linux-io-tty-detect");
    orc_kv("STDIN_ISATTY", "%s", isatty(0) ? "yes" : "no");
    orc_kv("STDOUT_ISATTY", "%s", isatty(1) ? "yes" : "no");
    orc_kv("STDERR_ISATTY", "%s", isatty(2) ? "yes" : "no");
    orc_obs("TERM_ENV", "%s", getenv("TERM") ? getenv("TERM") : "(unset)");
    orc_check("ALL_FDS_OPEN", write(1, "", 0) == 0);
    return orc_end();
}
