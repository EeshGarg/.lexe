/* Writes into a pipe whose read end is closed. argv[1] = default (die from
 * SIGPIPE) or ignore (observe EPIPE and continue). */
#include "oracle.h"
#include <signal.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int fds[2];
    ssize_t n;
    int ignore = (argc > 1 && strcmp(argv[1], "ignore") == 0);
    orc_begin(getenv("FIXTURE_ID") ? getenv("FIXTURE_ID") : "linux-signal-sigpipe");
    orc_kv("MODE", "%s", ignore ? "ignore" : "default");
    orc_check("PIPE_CREATED", pipe(fds) == 0);
    close(fds[0]);
    if (ignore) {
        signal(SIGPIPE, SIG_IGN);
        errno = 0;
        n = write(fds[1], "x", 1);
        orc_kv("WRITE_RETURN", "%ld", (long)n);
        orc_kv("WRITE_ERRNO", "%s", orc_errno_name(errno));
        orc_check("EPIPE_OBSERVED", n < 0 && errno == EPIPE);
        return orc_end();
    }
    orc_expect_death("sigpipe");
    n = write(fds[1], "x", 1);
    orc_kv("UNREACHABLE_WRITE_RETURN", "%ld", (long)n);
    orc_check("DIED_OF_SIGPIPE", 0);
    return orc_end();
}
