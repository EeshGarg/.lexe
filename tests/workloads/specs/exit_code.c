/* Exits with the code given in argv[1], after producing a complete oracle
 * record. RESULT=PASS with a non-zero exit is the point: a non-zero exit is not
 * a malfunction, it is the declared outcome, and a consumer must not conflate
 * the two. */
#include "oracle.h"
#include <unistd.h>

int main(int argc, char **argv) {
    int code = argc > 1 ? atoi(argv[1]) : 0;
    orc_begin(getenv("FIXTURE_ID") ? getenv("FIXTURE_ID") : "linux-outcome-exit");
    orc_kv("EXIT_CODE_INTENDED", "%d", code);
    orc_kv("WORK_DONE", "yes");
    orc_end();
    return code;
}
