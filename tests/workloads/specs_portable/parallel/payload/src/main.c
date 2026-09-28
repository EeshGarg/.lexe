/* Combines four independently compiled objects in a fixed order.
 *
 * The COMBINED value is order-dependent by construction -- part0 then part1 then
 * part2 then part3 -- while the COMPILATION order is whatever make chooses. That
 * is the point: a parallel build that got the dependency graph wrong produces
 * either a link error or a stale object, and never a different number here.
 */
#include <stdio.h>
#include <stdlib.h>
#include "parts.h"

int main(int argc, char **argv) {
    const char *id = getenv("FIXTURE_ID");
    unsigned long x = 2166136261UL;
    x = part0(x); x = part1(x); x = part2(x); x = part3(x);
    printf("FIXTURE_ID=%s\n", id ? id : "portable-parallel");
    printf("PAYLOAD_KIND=portable-source\n");
    printf("TRANSLATION_UNITS=5\n");
    printf("PARTS_COMBINED=4\n");
    printf("COMBINED=%lu\n", x);
    printf("COMBINED_NONZERO=%s\n", x != 0 ? "yes" : "no");
    printf("ARGC=%d\n", argc);
    printf("OBS_BUILD_STAMP=%s %s\n", __DATE__, __TIME__);
    printf("RESULT=%s\n", (x != 0 && argc >= 1 && argv[0]) ? "PASS" : "FAIL");
    return 0;
}
